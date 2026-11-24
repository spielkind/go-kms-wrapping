// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package tcloudpublickms

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	golangsdk "github.com/opentelekomcloud/gophertelekomcloud"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testIdpId     = "cce-idp"
	testIdToken   = "jwt-1"
	testKeyId     = "key-1"
	testProjectId = "p1"
	testRegion    = "eu-de"
)

// fakeCloud emulates the IAM, KMS and ECS metadata APIs used by the wrapper.
type fakeCloud struct {
	*httptest.Server

	mu sync.Mutex
	// idTokens are the OIDC tokens exchanged for the IAM tokens iam-token-<n>.
	idTokens []string
	scopes   []map[string]string
	// accessKeys maps valid access keys to their security token, which is
	// empty for permanent access keys.
	accessKeys    map[string]string
	metadataCred  map[string]string
	metadataCalls int
	// kmsCallers are the IAM tokens or access keys used for KMS requests.
	kmsCallers []string
	rejectKMS  int
}

func newFakeCloud(t *testing.T) *fakeCloud {
	t.Helper()
	// Environment variables take precedence over the test configuration.
	for _, env := range []string{
		EnvTCloudPublicKmsKeyId, EnvTCloudPublicRegion, EnvTCloudPublicProject,
		EnvTCloudPublicAccessKey, EnvTCloudPublicSecretKey, EnvTCloudPublicIdentityEndpoint,
		EnvTCloudPublicAuthMethod, EnvTCloudPublicIdpId, EnvTCloudPublicIdTokenFile,
	} {
		t.Setenv(env, "")
	}

	f := &fakeCloud{accessKeys: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v3.0/OS-AUTH/id-token/tokens", f.exchangeIdToken)
	mux.HandleFunc("GET /v3/auth/tokens", f.getToken)
	mux.HandleFunc("GET /v3/auth/catalog", f.getCatalog)
	mux.HandleFunc("GET /openstack/latest/securitykey", f.getSecurityKey)
	mux.HandleFunc("POST /v1.0/"+testProjectId+"/kms/{action}", f.kms)
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

// config returns a wrapper configuration for this cloud, extended by the
// given key value pairs.
func (f *fakeCloud) config(kv ...string) wrapping.Option {
	config := map[string]string{
		"identity_endpoint": f.URL + "/v3",
		"region":            testRegion,
	}
	for i := 0; i < len(kv); i += 2 {
		config[kv[i]] = kv[i+1]
	}
	return wrapping.WithConfigMap(config)
}

func (f *fakeCloud) exchangeIdToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Auth struct {
			IdToken struct {
				Id string `json:"id"`
			} `json:"id_token"`
			Scope struct {
				Project map[string]string `json:"project"`
			} `json:"scope"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if r.Header.Get("X-Idp-Id") != testIdpId {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprintf(w, `{"error_code":"IAM.0001","error_msg":"rejected %s"}`, body.Auth.IdToken.Id)
		return
	}
	if id := body.Auth.Scope.Project["id"]; id != "" && id != testProjectId {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprint(w, `{"error_code":"IAM.0011","error_msg":"Request body is invalid."}`)
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	f.idTokens = append(f.idTokens, body.Auth.IdToken.Id)
	f.scopes = append(f.scopes, body.Auth.Scope.Project)
	w.Header().Set("X-Subject-Token", fmt.Sprintf("iam-token-%d", len(f.idTokens)))
	w.WriteHeader(http.StatusCreated)
	_, _ = fmt.Fprintf(w, `{"token":{"expires_at":%q,"methods":["mapped"]}}`, formatTime(time.Now().Add(time.Hour)))
}

func (f *fakeCloud) getToken(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-Subject-Token")
	if token == "" || token != r.Header.Get("X-Auth-Token") {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Header().Set("X-Subject-Token", token)
	_, _ = fmt.Fprintf(w, `{"token":{"expires_at":%q,"project":{"id":%q,"name":%q,"domain":{"id":"d1"}},"user":{"id":"u1","domain":{"id":"d1"}},%s}}`,
		formatTime(time.Now().Add(time.Hour)), testProjectId, testRegion, f.catalog())
}

func (f *fakeCloud) getCatalog(w http.ResponseWriter, r *http.Request) {
	if f.accessKey(r) == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	_, _ = fmt.Fprintf(w, "{%s}", f.catalog())
}

func (f *fakeCloud) catalog() string {
	return fmt.Sprintf(`"catalog":[{"type":"kmsv1","name":"kms","endpoints":[{"interface":"public","region":%q,"url":"%s/v1.0/%s"}]}]`,
		testRegion, f.URL, testProjectId)
}

// accessKey returns the access key that signed r if it is valid.
func (f *fakeCloud) accessKey(r *http.Request) string {
	_, credential, _ := strings.Cut(r.Header.Get("Authorization"), "Credential=")
	accessKey, _, _ := strings.Cut(credential, "/")

	f.mu.Lock()
	defer f.mu.Unlock()
	securityToken, ok := f.accessKeys[accessKey]
	if !ok || securityToken != r.Header.Get("X-Security-Token") {
		return ""
	}
	return accessKey
}

func (f *fakeCloud) getSecurityKey(w http.ResponseWriter, _ *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.metadataCalls++
	if f.metadataCred == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"credential": f.metadataCred})
}

// issueTemporaryKey makes the metadata service serve a new temporary access
// key. Previously issued keys stay valid.
func (f *fakeCloud) issueTemporaryKey(accessKey string, expiresAt time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.accessKeys[accessKey] = "st-" + accessKey
	f.metadataCred = map[string]string{
		"access":        accessKey,
		"secret":        "sk-" + accessKey,
		"securitytoken": "st-" + accessKey,
		"expires_at":    formatTime(expiresAt),
	}
}

func (f *fakeCloud) kms(w http.ResponseWriter, r *http.Request) {
	caller := r.Header.Get("X-Auth-Token")
	if caller == "" {
		caller = f.accessKey(r)
	}

	f.mu.Lock()
	f.kmsCallers = append(f.kmsCallers, caller)
	reject := caller == "" || f.rejectKMS > 0
	if f.rejectKMS > 0 {
		f.rejectKMS--
	}
	f.mu.Unlock()
	if reject {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var body map[string]string
	_ = json.NewDecoder(r.Body).Decode(&body)
	switch r.PathValue("action") {
	case "encrypt-data":
		_ = json.NewEncoder(w).Encode(map[string]string{"key_id": testKeyId, "cipher_text": "wrapped:" + body["plain_text"]})
	case "decrypt-data":
		_ = json.NewEncoder(w).Encode(map[string]string{"key_id": testKeyId, "plain_text": strings.TrimPrefix(body["cipher_text"], "wrapped:")})
	}
}

func (f *fakeCloud) rejectNextKMSCalls(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rejectKMS = n
}

func (f *fakeCloud) addAccessKey(accessKey, securityToken string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.accessKeys[accessKey] = securityToken
}

func (f *fakeCloud) exchangedIdTokens() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.idTokens...)
}

func (f *fakeCloud) exchangedScopes() []map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]string(nil), f.scopes...)
}

func (f *fakeCloud) kmsCallerList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.kmsCallers...)
}

func (f *fakeCloud) metadataRequests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.metadataCalls
}

// formatTime formats t like IAM and the ECS metadata service do.
func formatTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000000Z")
}

func writeIdToken(t *testing.T, token string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "oidc-token")
	require.NoError(t, os.WriteFile(path, []byte(token+"\n"), 0o600))
	return path
}

// advanceClock lets the wrapper act as if d has passed.
func advanceClock(w *Wrapper, d time.Duration) {
	w.provider.now = func() time.Time { return time.Now().Add(d) }
}

func roundtrip(t *testing.T, w *Wrapper) {
	t.Helper()
	blob, err := w.Encrypt(t.Context(), []byte("foo"))
	require.NoError(t, err)
	pt, err := w.Decrypt(t.Context(), blob)
	require.NoError(t, err)
	require.Equal(t, []byte("foo"), pt)
}

func TestWorkloadIdentity(t *testing.T) {
	tests := map[string]struct {
		project   string
		wantScope map[string]string
	}{
		"project id":           {project: testProjectId, wantScope: map[string]string{"id": testProjectId}},
		"region named project": {wantScope: map[string]string{"name": testRegion}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cloud := newFakeCloud(t)
			w := NewWrapper()
			cfg, err := w.SetConfig(t.Context(), wrapping.WithKeyId(testKeyId), cloud.config(
				"idp_id", testIdpId, "id_token_file", writeIdToken(t, testIdToken), "project", tc.project,
			))
			require.NoError(t, err)
			require.Equal(t, AuthMethodWorkloadIdentity, cfg.Metadata["auth_method"])

			roundtrip(t, w)
			require.Equal(t, []string{testIdToken}, cloud.exchangedIdTokens())
			require.Equal(t, []map[string]string{tc.wantScope}, cloud.exchangedScopes())
			require.Equal(t, []string{"iam-token-1", "iam-token-1"}, cloud.kmsCallerList())
		})
	}
}

func TestWorkloadIdentity_RefreshesBeforeExpiry(t *testing.T) {
	cloud := newFakeCloud(t)
	tokenFile := writeIdToken(t, testIdToken)
	w := NewWrapper()
	_, err := w.SetConfig(t.Context(), wrapping.WithKeyId(testKeyId), cloud.config(
		"auth_method", AuthMethodWorkloadIdentity, "idp_id", testIdpId, "id_token_file", tokenFile,
	))
	require.NoError(t, err)

	// kubelet rotates the token file.
	require.NoError(t, os.WriteFile(tokenFile, []byte("jwt-2"), 0o600))
	advanceClock(w, time.Hour-refreshMargin+time.Second)

	// Concurrent requests share a single refresh.
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := w.Encrypt(t.Context(), []byte("foo"))
			assert.NoError(t, err)
		}()
	}
	wg.Wait()

	require.Equal(t, []string{testIdToken, "jwt-2"}, cloud.exchangedIdTokens())
	require.Equal(t, []string{"iam-token-2", "iam-token-2", "iam-token-2", "iam-token-2", "iam-token-2"}, cloud.kmsCallerList())
}

func TestWorkloadIdentity_RetriesOnceWhenUnauthorized(t *testing.T) {
	cloud := newFakeCloud(t)
	w := NewWrapper()
	_, err := w.SetConfig(t.Context(), wrapping.WithKeyId(testKeyId), cloud.config(
		"idp_id", testIdpId, "id_token_file", writeIdToken(t, testIdToken),
	))
	require.NoError(t, err)

	cloud.rejectNextKMSCalls(1)
	_, err = w.Encrypt(t.Context(), []byte("foo"))
	require.NoError(t, err)
	require.Len(t, cloud.exchangedIdTokens(), 2)
	require.Equal(t, []string{"iam-token-1", "iam-token-2"}, cloud.kmsCallerList())

	cloud.rejectNextKMSCalls(2)
	_, err = w.Encrypt(t.Context(), []byte("foo"))
	var unauthorized golangsdk.ErrDefault401
	require.ErrorAs(t, err, &unauthorized)
	require.Len(t, cloud.exchangedIdTokens(), 3)
}

func TestECSAgency(t *testing.T) {
	cloud := newFakeCloud(t)
	cloud.issueTemporaryKey("ak-1", time.Now().Add(time.Hour))
	w := NewWrapper()
	w.metadataEndpoint = cloud.URL
	cfg, err := w.SetConfig(t.Context(), wrapping.WithKeyId(testKeyId), cloud.config(
		"auth_method", AuthMethodECSAgency, "project", testProjectId,
	))
	require.NoError(t, err)
	require.Equal(t, AuthMethodECSAgency, cfg.Metadata["auth_method"])
	roundtrip(t, w)

	// The metadata service rotates the credentials before they expire.
	cloud.issueTemporaryKey("ak-2", time.Now().Add(2*time.Hour))
	advanceClock(w, time.Hour-refreshMargin+time.Second)
	roundtrip(t, w)

	require.Equal(t, 2, cloud.metadataRequests())
	require.Equal(t, []string{"ak-1", "ak-1", "ak-2", "ak-2"}, cloud.kmsCallerList())
}

func TestSetConfig_AuthMethod(t *testing.T) {
	tests := map[string]struct {
		config          []string
		disallowEnvVars bool
		wantMethod      string
		wantErr         string
	}{
		"access key": {
			config:     []string{"access_key", "ak", "secret_key", "sk"},
			wantMethod: AuthMethodAccessKey,
		},
		"access key preferred over idp id": {
			config:     []string{"access_key", "ak", "secret_key", "sk", "idp_id", testIdpId},
			wantMethod: AuthMethodAccessKey,
		},
		"incomplete access key": {
			config:  []string{"access_key", "ak", "idp_id", testIdpId},
			wantErr: "'secret_key' not found",
		},
		"no credentials": {
			wantErr: "no credentials found",
		},
		"unsupported auth method": {
			config:  []string{"auth_method", "password"},
			wantErr: `unsupported auth method "password"`,
		},
		"workload identity without idp id": {
			config:  []string{"auth_method", AuthMethodWorkloadIdentity},
			wantErr: "'idp_id' not found",
		},
		"unknown identity provider": {
			config:  []string{"idp_id", "unknown"},
			wantErr: "unexpected status 401 (IAM.0001)",
		},
		"project name instead of project id": {
			config:  []string{"idp_id", testIdpId, "project", "eu-de_myproject"},
			wantErr: `unexpected status 400 (IAM.0011): check that 'project' is a project ID, not a project name (got "eu-de_myproject")`,
		},
		"missing id token file": {
			config:  []string{"idp_id", testIdpId, "id_token_file", "/nonexistent"},
			wantErr: "failed to read id token file",
		},
		"instance without agency": {
			config:  []string{"auth_method", AuthMethodECSAgency},
			wantErr: "is an agency attached to the instance?",
		},
		"access key with env vars disallowed": {
			config:          []string{"access_key", "ak", "secret_key", "sk"},
			disallowEnvVars: true,
			wantMethod:      AuthMethodAccessKey,
		},
		"workload identity with env vars disallowed": {
			config:          []string{"idp_id", testIdpId},
			disallowEnvVars: true,
			wantErr:         `auth method "workload_identity" cannot be used when environment variables are disallowed`,
		},
		"ecs agency with env vars disallowed": {
			config:          []string{"auth_method", AuthMethodECSAgency},
			disallowEnvVars: true,
			wantErr:         `auth method "ecs_agency" cannot be used when environment variables are disallowed`,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cloud := newFakeCloud(t)
			cloud.addAccessKey("ak", "")
			w := NewWrapper()
			w.metadataEndpoint = cloud.URL

			config := append([]string{"id_token_file", writeIdToken(t, testIdToken)}, tc.config...)
			cfg, err := w.SetConfig(t.Context(), wrapping.WithKeyId(testKeyId), cloud.config(config...),
				wrapping.WithDisallowEnvVars(tc.disallowEnvVars))
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				require.NotContains(t, err.Error(), testIdToken)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantMethod, cfg.Metadata["auth_method"])
		})
	}
}

type fakeSource struct {
	expiresAt time.Time
	err       error
	calls     int
}

func (s *fakeSource) retrieve(context.Context) (golangsdk.AuthOptionsProvider, time.Time, error) {
	s.calls++
	if s.err != nil {
		return nil, time.Time{}, s.err
	}
	return golangsdk.AuthOptions{}, s.expiresAt, nil
}

func TestClientProvider_RefreshFailure(t *testing.T) {
	start := time.Now()
	clock := start
	source := &fakeSource{expiresAt: start.Add(time.Hour)}
	p := &clientProvider{
		source: source,
		newClient: func(golangsdk.AuthOptionsProvider) (*golangsdk.ServiceClient, error) {
			return &golangsdk.ServiceClient{}, nil
		},
		now: func() time.Time { return clock },
	}
	client, err := p.get(t.Context())
	require.NoError(t, err)

	// Until they expire, the current credentials are used if a refresh fails,
	// and refreshes are throttled.
	source.err = errors.New("IAM unavailable")
	clock = start.Add(time.Hour - refreshMargin + time.Second)
	for _, d := range []time.Duration{0, minRefreshInterval - time.Second, time.Second} {
		clock = clock.Add(d)
		got, err := p.get(t.Context())
		require.NoError(t, err)
		require.Same(t, client, got)
	}
	require.Equal(t, 3, source.calls)

	clock = start.Add(time.Hour)
	_, err = p.get(t.Context())
	require.ErrorContains(t, err, "IAM unavailable")
}
