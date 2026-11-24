// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package tcloudpublickms

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	golangsdk "github.com/opentelekomcloud/gophertelekomcloud"
	kms "github.com/opentelekomcloud/gophertelekomcloud/openstack/kms/v1/keys"
)

const Type wrapping.WrapperType = "tcloudpublickms"

const (
	EnvTCloudPublicKmsKeyId         = "TCLOUDPUBLIC_KMS_KEY_ID"
	EnvTCloudPublicRegion           = "TCLOUDPUBLIC_REGION"
	EnvTCloudPublicProject          = "TCLOUDPUBLIC_PROJECT"
	EnvTCloudPublicAccessKey        = "TCLOUDPUBLIC_ACCESS_KEY"
	EnvTCloudPublicSecretKey        = "TCLOUDPUBLIC_SECRET_KEY"
	EnvTCloudPublicIdentityEndpoint = "TCLOUDPUBLIC_IDENTITY_ENDPOINT"
	EnvTCloudPublicAuthMethod       = "TCLOUDPUBLIC_AUTH_METHOD"
	EnvTCloudPublicIdpId            = "TCLOUDPUBLIC_IDP_ID"
	EnvTCloudPublicIdTokenFile      = "TCLOUDPUBLIC_ID_TOKEN_FILE"
)

// Supported values of the auth_method configuration parameter.
const (
	// AuthMethodAccessKey authenticates with an access key and secret key.
	AuthMethodAccessKey = "access_key"
	// AuthMethodWorkloadIdentity exchanges the OIDC token of a Kubernetes
	// service account (CCE workload identity) for an IAM token.
	AuthMethodWorkloadIdentity = "workload_identity"
	// AuthMethodECSAgency uses the temporary credentials of the agency
	// attached to the ECS or BMS instance.
	AuthMethodECSAgency = "ecs_agency"
)

// Ensure that we are implementing Wrapper
var _ wrapping.Wrapper = (*Wrapper)(nil)

// Wrapper is a Wrapper that uses T Cloud Public's KMS
type Wrapper struct {
	provider *clientProvider

	// keyId is the configured key ID or alias. It is used to request
	// encryption. We keep this separate from currentKeyId to support key
	// aliases/rotation.
	keyId string

	// currentKeyId is the resolved key ID from the last successful operation.
	currentKeyId *atomic.Value

	// Metadata fields stored for reporting
	region string
	// project is the ID of the T Cloud Public project/tenant scope.
	// Optional; when empty, the global KMS endpoint is used.
	project    string
	authMethod string

	// metadataEndpoint is the ECS metadata service. Tests override it.
	metadataEndpoint string
}

// NewWrapper creates a new TCloudPublic Wrapper
func NewWrapper() *Wrapper {
	k := &Wrapper{
		currentKeyId:     new(atomic.Value),
		metadataEndpoint: defaultMetadataEndpoint,
	}
	k.currentKeyId.Store("")
	return k
}

// SetConfig sets the fields on the TCloudPublic Wrapper object based on
// values from the config parameter.
//
// Order of precedence for T Cloud Public values (highest to lowest):
// * Environment variable (if not disabled via WithDisallowEnvVars)
// * Value from Vault configuration file
// Required: key_id, region
// Optional: project (defaults to global scope), identity_endpoint, auth_method
//
// project must be a project ID, such as 0123456789abcdef0123456789abcdef,
// not a project name such as eu-de or eu-de_myproject.
//
// auth_method selects how to authenticate:
// * access_key: requires access_key and secret_key
// * workload_identity: exchanges the OIDC token of a Kubernetes service
// account (CCE workload identity) for an IAM token scoped to project, or to
// the project named like the region if project is empty. Requires idp_id;
// id_token_file defaults to /var/run/secrets/tokens/oidc-token
// * ecs_agency: uses the temporary credentials of the agency attached to the
// ECS or BMS instance, served by the instance metadata service
// If auth_method is empty, access_key is used if an access key or secret key
// is set, otherwise workload_identity if idp_id is set. With
// WithDisallowEnvVars, only access_key is allowed.
func (k *Wrapper) SetConfig(
	ctx context.Context,
	opt ...wrapping.Option,
) (*wrapping.WrapperConfig, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	// Check and set KeyId
	switch {
	case os.Getenv(EnvTCloudPublicKmsKeyId) != "" && !opts.Options.WithDisallowEnvVars:
		k.keyId = os.Getenv(EnvTCloudPublicKmsKeyId)
	case opts.WithKeyId != "":
		k.keyId = opts.WithKeyId
	default:
		return nil, fmt.Errorf("'key_id' not found for T Cloud Public KMS wrapper configuration")
	}

	if err := k.setupClient(ctx, opts); err != nil {
		return nil, err
	}

	// Store non-sensitive configuration info
	wrapConfig := new(wrapping.WrapperConfig)
	wrapConfig.Metadata = make(map[string]string)
	wrapConfig.Metadata["region"] = k.region
	wrapConfig.Metadata["project"] = k.project
	wrapConfig.Metadata["key_id"] = k.keyId
	wrapConfig.Metadata["auth_method"] = k.authMethod

	return wrapConfig, nil
}

// Type returns the type for this particular wrapper implementation
func (k *Wrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return Type, nil
}

// KeyId returns the last known key id
func (k *Wrapper) KeyId(_ context.Context) (string, error) {
	return k.currentKeyId.Load().(string), nil
}

// Encrypt is used to encrypt the master key using the the T Cloud Public
// CMK. This returns the ciphertext, and/or any errors from this call. This
// should be called after the KMS client has been instantiated.
func (k *Wrapper) Encrypt(
	ctx context.Context,
	plaintext []byte,
	opt ...wrapping.Option,
) (*wrapping.BlobInfo, error) {
	if plaintext == nil {
		return nil, fmt.Errorf("given plaintext for encryption is nil")
	}

	env, err := wrapping.EnvelopeEncrypt(plaintext, opt...)
	if err != nil {
		return nil, fmt.Errorf("error wrapping data: %w", err)
	}

	// We use k.keyId (the config) here so that if it is an alias, KMS resolves
	// it to the latest version.
	resp, err := call(ctx, k.provider, func(client *golangsdk.ServiceClient) (*kms.EncryptResp, error) {
		return kms.EncryptData(
			client,
			kms.EncryptDataOpts{
				KeyID:     k.keyId,
				PlainText: base64.StdEncoding.EncodeToString(env.Key),
			},
		)
	})
	if err != nil {
		return nil, fmt.Errorf("error encrypting data: %w", err)
	}

	// Store the actual resolved key ID returned by KMS.
	k.currentKeyId.Store(resp.KeyID)

	return &wrapping.BlobInfo{
		Ciphertext: env.Ciphertext,
		Iv:         env.Iv,
		KeyInfo: &wrapping.KeyInfo{
			KeyId:      resp.KeyID,
			WrappedKey: []byte(resp.CipherText),
		},
	}, nil
}

// Decrypt is used to decrypt the ciphertext.
func (k *Wrapper) Decrypt(
	ctx context.Context,
	in *wrapping.BlobInfo,
	opt ...wrapping.Option,
) ([]byte, error) {
	// KeyId is not passed to this call because T Cloud Public handles this
	// internally based on the metadata stored with the encrypted data
	resp, err := call(ctx, k.provider, func(client *golangsdk.ServiceClient) (*kms.DecryptResp, error) {
		return kms.DecryptData(
			client,
			kms.DecryptDataOpts{CipherText: string(in.KeyInfo.WrappedKey)},
		)
	})
	if err != nil {
		return nil, fmt.Errorf("error decrypting data encryption key: %w", err)
	}

	keyBytes, err := base64.StdEncoding.DecodeString(resp.PlainText)
	if err != nil {
		return nil, err
	}

	envInfo := &wrapping.EnvelopeInfo{
		Key:        keyBytes,
		Iv:         in.Iv,
		Ciphertext: in.Ciphertext,
	}
	pt, err := wrapping.EnvelopeDecrypt(envInfo, opt...)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data: %w", err)
	}

	return pt, nil
}

func (k *Wrapper) setupClient(ctx context.Context, opts *options) error {
	switch {
	case os.Getenv(EnvTCloudPublicRegion) != "" && !opts.Options.WithDisallowEnvVars:
		k.region = os.Getenv(EnvTCloudPublicRegion)
	case opts.withRegion != "":
		k.region = opts.withRegion
	default:
		return fmt.Errorf("'region' not found for T Cloud Public KMS wrapper configuration")
	}

	// Project is optional: KMS can operate at the global or project scope.
	// When empty, the global KMS endpoint is used.
	switch {
	case os.Getenv(EnvTCloudPublicProject) != "" && !opts.Options.WithDisallowEnvVars:
		k.project = os.Getenv(EnvTCloudPublicProject)
	case opts.withProject != "":
		k.project = opts.withProject
	}

	endpoint := configValue(opts, EnvTCloudPublicIdentityEndpoint, opts.withIdentityEndpoint)
	accessKey := configValue(opts, EnvTCloudPublicAccessKey, opts.withAccessKey)
	secretKey := configValue(opts, EnvTCloudPublicSecretKey, opts.withSecretKey)
	idpId := configValue(opts, EnvTCloudPublicIdpId, opts.withIdpId)

	authMethod := strings.ToLower(configValue(opts, EnvTCloudPublicAuthMethod, opts.withAuthMethod))
	if authMethod == "" {
		switch {
		case accessKey != "" || secretKey != "":
			authMethod = AuthMethodAccessKey
		case idpId != "":
			authMethod = AuthMethodWorkloadIdentity
		default:
			return errors.New("no credentials found for T Cloud Public KMS wrapper configuration: set 'access_key' and 'secret_key', set 'idp_id' for workload identity, or set 'auth_method'")
		}
	}
	// As in other wrappers, identities provided by the environment, such as a
	// token file or the metadata service, require environment variables to be
	// allowed.
	if opts.Options.WithDisallowEnvVars && authMethod != AuthMethodAccessKey {
		return fmt.Errorf("auth method %q cannot be used when environment variables are disallowed", authMethod)
	}

	var source credentialSource
	switch authMethod {
	case AuthMethodAccessKey:
		if accessKey == "" {
			return fmt.Errorf("'access_key' not found for T Cloud Public KMS wrapper configuration")
		}
		if secretKey == "" {
			return fmt.Errorf("'secret_key' not found for T Cloud Public KMS wrapper configuration")
		}
		source = &staticCredentials{authOpts: golangsdk.AKSKAuthOptions{
			Region:           k.region,
			ProjectId:        k.project,
			AccessKey:        accessKey,
			SecretKey:        secretKey,
			IdentityEndpoint: endpoint,
		}}
	case AuthMethodWorkloadIdentity:
		if idpId == "" {
			return fmt.Errorf("'idp_id' not found for T Cloud Public KMS wrapper configuration")
		}
		tokenFile := configValue(opts, EnvTCloudPublicIdTokenFile, opts.withIdTokenFile)
		if tokenFile == "" {
			return fmt.Errorf("'id_token_file' not found for T Cloud Public KMS wrapper configuration")
		}
		source = &workloadIdentityCredentials{
			identityEndpoint: endpoint,
			idpId:            idpId,
			tokenFile:        tokenFile,
			projectId:        k.project,
			projectName:      k.region,
			httpClient:       newIAMHTTPClient(),
		}
	case AuthMethodECSAgency:
		source = &ecsAgencyCredentials{
			metadataEndpoint: k.metadataEndpoint,
			identityEndpoint: endpoint,
			region:           k.region,
			project:          k.project,
			httpClient:       newMetadataHTTPClient(),
		}
	default:
		return fmt.Errorf("unsupported auth method %q for T Cloud Public KMS wrapper configuration", authMethod)
	}

	provider := newClientProvider(source, k.region, opts.WithLogger)
	// Authenticate right away to surface configuration errors early.
	if _, err := provider.get(ctx); err != nil {
		return err
	}

	k.provider = provider
	k.authMethod = authMethod
	return nil
}

// configValue returns the value of the environment variable env unless it is
// empty or environment variables are disallowed, and value otherwise.
func configValue(opts *options, env, value string) string {
	if v := os.Getenv(env); v != "" && !opts.Options.WithDisallowEnvVars {
		return v
	}
	return value
}
