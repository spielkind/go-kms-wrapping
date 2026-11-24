// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package tcloudpublickms

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	golangsdk "github.com/opentelekomcloud/gophertelekomcloud"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack"
)

const (
	// refreshMargin is how long before their expiry renewable credentials are
	// refreshed. It is shorter than the 10 minute window in which the ECS
	// metadata service already serves rotated credentials.
	refreshMargin = 5 * time.Minute

	// minRefreshInterval throttles refresh attempts within the refresh margin
	// while the current credentials are still valid.
	minRefreshInterval = 30 * time.Second

	// maxResponseBytes limits how much of an IAM or metadata response is read.
	maxResponseBytes = 1 << 20

	defaultMetadataEndpoint = "http://169.254.169.254"
)

// credentialSource provides the authentication options for a KMS client.
type credentialSource interface {
	// retrieve returns authentication options and the time at which they
	// expire. A zero expiry means that the credentials never expire and are
	// never refreshed.
	retrieve(ctx context.Context) (golangsdk.AuthOptionsProvider, time.Time, error)
}

// staticCredentials is a long-lived access key and secret key.
type staticCredentials struct {
	authOpts golangsdk.AKSKAuthOptions
}

func (s *staticCredentials) retrieve(context.Context) (golangsdk.AuthOptionsProvider, time.Time, error) {
	return s.authOpts, time.Time{}, nil
}

// ecsAgencyCredentials are the temporary credentials of the agency attached
// to an ECS or BMS instance, served by the instance metadata service.
type ecsAgencyCredentials struct {
	metadataEndpoint string
	identityEndpoint string
	region           string
	project          string
	httpClient       *http.Client
}

func (s *ecsAgencyCredentials) retrieve(ctx context.Context) (golangsdk.AuthOptionsProvider, time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.metadataEndpoint+"/openstack/latest/securitykey", nil)
	if err != nil {
		return nil, time.Time{}, err
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to query ECS metadata service: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, time.Time{}, fmt.Errorf("failed to obtain temporary credentials from ECS metadata service (is an agency attached to the instance?): unexpected status %d", resp.StatusCode)
	}

	var body struct {
		Credential struct {
			Access        string    `json:"access"`
			Secret        string    `json:"secret"`
			SecurityToken string    `json:"securitytoken"`
			ExpiresAt     time.Time `json:"expires_at"`
		} `json:"credential"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&body); err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to decode ECS metadata response: %w", err)
	}
	cred := body.Credential
	if cred.Access == "" || cred.Secret == "" || cred.SecurityToken == "" || cred.ExpiresAt.IsZero() {
		return nil, time.Time{}, errors.New("incomplete temporary credentials in ECS metadata response")
	}

	return golangsdk.AKSKAuthOptions{
		IdentityEndpoint: s.identityEndpoint,
		Region:           s.region,
		ProjectId:        s.project,
		AccessKey:        cred.Access,
		SecretKey:        cred.Secret,
		SecurityToken:    cred.SecurityToken,
	}, cred.ExpiresAt, nil
}

// workloadIdentityCredentials exchange the OIDC token of a Kubernetes service
// account (CCE workload identity) for a project-scoped IAM token.
type workloadIdentityCredentials struct {
	identityEndpoint string
	idpId            string
	tokenFile        string
	// projectId scopes the IAM token. If empty, projectName is used.
	projectId   string
	projectName string
	httpClient  *http.Client
}

func (s *workloadIdentityCredentials) retrieve(ctx context.Context) (golangsdk.AuthOptionsProvider, time.Time, error) {
	// The file is read on every refresh because kubelet rotates the token.
	raw, err := os.ReadFile(s.tokenFile)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to read id token file: %w", err)
	}
	idToken := strings.TrimSpace(string(raw))
	if idToken == "" {
		return nil, time.Time{}, fmt.Errorf("id token file %q is empty", s.tokenFile)
	}

	project := map[string]string{"name": s.projectName}
	if s.projectId != "" {
		project = map[string]string{"id": s.projectId}
	}
	reqBody, err := json.Marshal(map[string]any{
		"auth": map[string]any{
			"id_token": map[string]string{"id": idToken},
			"scope":    map[string]any{"project": project},
		},
	})
	if err != nil {
		return nil, time.Time{}, err
	}

	url := identityBaseURL(s.identityEndpoint) + "/v3.0/OS-AUTH/id-token/tokens"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/json;charset=utf8")
	req.Header.Set("X-Idp-Id", s.idpId)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to exchange id token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// The response body is not part of the error as it may echo the request.
	if resp.StatusCode != http.StatusCreated {
		msg := fmt.Sprintf("failed to exchange id token: unexpected status %d", resp.StatusCode)
		if code := iamErrorCode(resp.Body); code != "" {
			msg += fmt.Sprintf(" (%s)", code)
			// IAM rejects a project name in place of the project ID as an
			// invalid request body.
			if code == iamCodeInvalidRequestBody && s.projectId != "" {
				msg += fmt.Sprintf(": check that 'project' is a project ID, not a project name (got %q)", s.projectId)
			}
		}
		return nil, time.Time{}, errors.New(msg)
	}

	var body struct {
		Token struct {
			ExpiresAt time.Time `json:"expires_at"`
		} `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&body); err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to decode id token exchange response: %w", err)
	}
	token := resp.Header.Get("X-Subject-Token")
	if token == "" || body.Token.ExpiresAt.IsZero() {
		return nil, time.Time{}, errors.New("incomplete id token exchange response")
	}

	return golangsdk.AuthOptions{
		IdentityEndpoint: s.identityEndpoint,
		TokenID:          token,
	}, body.Token.ExpiresAt, nil
}

// iamCodeInvalidRequestBody is the IAM error code for an invalid request body.
const iamCodeInvalidRequestBody = "IAM.0011"

// iamErrorCode returns the IAM error code of an error response, such as
// "IAM.0001", or an empty string.
func iamErrorCode(r io.Reader) string {
	var body struct {
		ErrorCode string `json:"error_code"`
	}
	if err := json.NewDecoder(io.LimitReader(r, maxResponseBytes)).Decode(&body); err != nil {
		return ""
	}
	return body.ErrorCode
}

// identityBaseURL strips the API version from an identity endpoint such as
// https://iam.eu-de.otc.t-systems.com:443/v3.
func identityBaseURL(endpoint string) string {
	u := strings.TrimRight(endpoint, "/")
	u = strings.TrimSuffix(u, "/v3")
	return strings.TrimSuffix(u, "/v3.0")
}

func newIAMHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		// A redirect would resend the id token to another location.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func newMetadataHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		// The link-local metadata service must not be reached through a proxy.
		Transport: &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// newKMSClient authenticates with authOpts and returns a KMS client.
func newKMSClient(authOpts golangsdk.AuthOptionsProvider, region string) (*golangsdk.ServiceClient, error) {
	client, err := openstack.NewClient(authOpts.GetIdentityEndpoint())
	if err != nil {
		return nil, fmt.Errorf("failed to create new client: %w", err)
	}

	if aksk, ok := authOpts.(golangsdk.AKSKAuthOptions); ok {
		// Configure the HTTP client to handle redirects with AK/SK resigning.
		client.HTTPClient = http.Client{
			Transport: client.HTTPClient.Transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				golangsdk.ReSign(req, golangsdk.SignOptions{
					AccessKey: aksk.AccessKey,
					SecretKey: aksk.SecretKey,
				})
				return nil
			},
		}
	}

	if err := openstack.Authenticate(client, authOpts); err != nil {
		return nil, fmt.Errorf("failed to authenticate: %w", err)
	}

	return openstack.NewKMSV1(
		client, golangsdk.EndpointOpts{
			Region:       region,
			Availability: golangsdk.AvailabilityPublic,
		},
	)
}

// clientProvider caches a KMS client and replaces it with a client using
// fresh credentials before they expire. Clients are never modified once in
// use, as the SDK does not synchronize access to their credentials.
type clientProvider struct {
	source    credentialSource
	newClient func(golangsdk.AuthOptionsProvider) (*golangsdk.ServiceClient, error)
	logger    hclog.Logger
	now       func() time.Time

	mu          sync.Mutex
	client      *golangsdk.ServiceClient
	expiresAt   time.Time
	lastAttempt time.Time
}

func newClientProvider(source credentialSource, region string, logger hclog.Logger) *clientProvider {
	return &clientProvider{
		source: source,
		newClient: func(authOpts golangsdk.AuthOptionsProvider) (*golangsdk.ServiceClient, error) {
			return newKMSClient(authOpts, region)
		},
		logger: logger,
		now:    time.Now,
	}
}

// get returns a client with valid credentials, refreshing them if needed.
func (p *clientProvider) get(ctx context.Context) (*golangsdk.ServiceClient, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := p.now()
	if p.client != nil {
		if p.expiresAt.IsZero() || now.Add(refreshMargin).Before(p.expiresAt) {
			return p.client, nil
		}
		if now.Before(p.expiresAt) && now.Sub(p.lastAttempt) < minRefreshInterval {
			return p.client, nil
		}
	}

	p.lastAttempt = now
	client, expiresAt, err := p.refresh(ctx)
	if err != nil {
		if p.client != nil && now.Before(p.expiresAt) {
			if p.logger != nil {
				p.logger.Warn("failed to refresh T Cloud Public credentials, using current credentials until they expire",
					"expires_at", p.expiresAt, "error", err)
			}
			return p.client, nil
		}
		return nil, err
	}

	p.client, p.expiresAt = client, expiresAt
	return client, nil
}

func (p *clientProvider) refresh(ctx context.Context) (*golangsdk.ServiceClient, time.Time, error) {
	authOpts, expiresAt, err := p.source.retrieve(ctx)
	if err != nil {
		return nil, time.Time{}, err
	}
	client, err := p.newClient(authOpts)
	if err != nil {
		return nil, time.Time{}, err
	}
	return client, expiresAt, nil
}

// invalidate forces the next get to refresh the credentials, unless client
// has already been replaced.
func (p *clientProvider) invalidate(client *golangsdk.ServiceClient) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.client == client {
		p.client = nil
	}
}

func (p *clientProvider) renewable() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.expiresAt.IsZero()
}

// call invokes fn with a client. If renewable credentials are rejected as
// unauthorized, they are refreshed and fn is retried once.
func call[T any](ctx context.Context, p *clientProvider, fn func(*golangsdk.ServiceClient) (T, error)) (T, error) {
	client, err := p.get(ctx)
	if err != nil {
		var zero T
		return zero, err
	}

	result, err := fn(client)
	var unauthorized golangsdk.ErrDefault401
	if err == nil || !errors.As(err, &unauthorized) || !p.renewable() {
		return result, err
	}

	p.invalidate(client)
	if client, err = p.get(ctx); err != nil {
		var zero T
		return zero, err
	}
	return fn(client)
}
