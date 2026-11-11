package plugin

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/mattermost/mattermost/server/public/plugin/plugintest"
	"github.com/mattermost/mattermost/server/public/pluginapi"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// countingStore wraps a KvStore and counts atomic writes so tests can assert
// that a still-valid token does not trigger a write-back.
type countingStore struct {
	KvStore
	atomicWrites int
}

func (c *countingStore) SetAtomicWithRetries(key string, fn func(oldValue []byte) (any, error)) error {
	c.atomicWrites++
	return c.KvStore.SetAtomicWithRetries(key, fn)
}

func newTokenTestPlugin(t *testing.T, store KvStore) *Plugin {
	t.Helper()
	p := NewPlugin()
	p.setConfiguration(&Configuration{
		ForgejoOAuthClientID:     "id",
		ForgejoOAuthClientSecret: "secret",
		EncryptionKey:            "mockKey123456789", // 16 bytes -> AES-128
	})

	api := &plugintest.API{}
	api.On("LogWarn", mock.Anything, mock.Anything, mock.Anything).Maybe()
	api.On("LogError", mock.Anything, mock.Anything, mock.Anything).Maybe()
	api.On("LogDebug", mock.Anything, mock.Anything, mock.Anything).Maybe()
	p.SetAPI(api)
	p.client = pluginapi.NewClient(api, p.Driver)
	p.store = store
	// The in-process gate in lockTokenRefresh is real; skip the cluster mutex.
	p.tokenRefreshClusterLocker = func(string) (func(), error) { return func() {}, nil }

	return p
}

// storeInitialUser persists a connected user with the given plaintext tokens.
func storeInitialUser(t *testing.T, p *Plugin, userID, access, refresh string) {
	t.Helper()
	err := p.storeGitHubUserInfo(&ForgejoUserInfo{
		UserID:          userID,
		ForgejoUsername: "alice",
		LastToDoPostAt:  42,
		Settings:        &UserSettings{SidebarButtons: settingButtonsTeam, Notifications: true},
		Token: &oauth2.Token{
			AccessToken:  access,
			RefreshToken: refresh,
			TokenType:    "Bearer",
		},
	})
	require.NoError(t, err)
}

// TestOAuthClientChokepoint verifies that both authenticated-client builders
// route through oauthClient, so the persisting token source is applied
// uniformly to the raw *http.Client and the *github.Client wrapper paths.
func TestOAuthClientChokepoint(t *testing.T) {
	p := newTokenTestPlugin(t, &pluginapi.MemoryStore{})
	info := &ForgejoUserInfo{
		UserID: "u1",
		Token:  &oauth2.Token{AccessToken: "a1", RefreshToken: "r1", TokenType: "Bearer"},
	}

	httpClient, err := p.oauthClient(info)
	require.NoError(t, err)
	require.NotNil(t, httpClient)
	require.IsType(t, &oauth2.Transport{}, httpClient.Transport, "oauthClient must return an OAuth-authenticated client")

	// Both builders must route through oauthClient and yield a usable client.
	require.NotNil(t, p.forgejoConnect(info), "forgejoConnect (http.Client path) must build a client")
	require.NotNil(t, p.githubConnectUser(context.Background(), info), "githubConnectUser (github.Client path) must build a client")
}

// TestPersistRefreshedToken verifies that a rotated token is written back,
// encrypted, while every other field of the stored record is preserved.
func TestPersistRefreshedToken(t *testing.T) {
	p := newTokenTestPlugin(t, &pluginapi.MemoryStore{})
	storeInitialUser(t, p, "u1", "old-access", "old-refresh")

	err := p.persistRefreshedToken("u1", &oauth2.Token{
		AccessToken:  "new-access",
		RefreshToken: "new-refresh",
		TokenType:    "Bearer",
	})
	require.NoError(t, err)

	info, apiErr := p.getGitHubUserInfo("u1")
	require.Nil(t, apiErr)
	require.Equal(t, "new-access", info.Token.AccessToken, "access token should be rotated")
	require.Equal(t, "new-refresh", info.Token.RefreshToken, "refresh token should be rotated")
	// Untouched fields must survive the write-back.
	require.Equal(t, "alice", info.ForgejoUsername)
	require.Equal(t, int64(42), info.LastToDoPostAt)
	require.NotNil(t, info.Settings)
	require.True(t, info.Settings.Notifications)
}

func TestPersistRefreshedToken_NoUser(t *testing.T) {
	p := newTokenTestPlugin(t, &pluginapi.MemoryStore{})

	err := p.persistRefreshedToken("missing", &oauth2.Token{AccessToken: "a", RefreshToken: "r"})
	require.Error(t, err, "persisting for an unknown user must fail rather than create a partial record")
}

// countingRefresher hands out a new token per refresh and records the refresh
// tokens it was called with, mimicking Forgejo's refresh-token rotation.
type countingRefresher struct {
	mu    sync.Mutex
	used  []string
	delay time.Duration
}

func (c *countingRefresher) refresh(refreshToken string) (*oauth2.Token, error) {
	time.Sleep(c.delay)
	c.mu.Lock()
	defer c.mu.Unlock()
	if slices.Contains(c.used, refreshToken) {
		return nil, errors.New("token was already used")
	}
	c.used = append(c.used, refreshToken)
	n := len(c.used) + 1
	return &oauth2.Token{
		AccessToken:  fmt.Sprintf("a%d", n),
		RefreshToken: fmt.Sprintf("r%d", n),
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour),
	}, nil
}

// newTestTokenSource mirrors oauthClient's token source wiring.
func newTestTokenSource(p *Plugin, userID string, tok *oauth2.Token, r *countingRefresher) oauth2.TokenSource {
	return oauth2.ReuseTokenSource(tok, &refreshingTokenSource{plugin: p, userID: userID, last: tok, refresh: r.refresh})
}

func expiredToken(access, refresh string) *oauth2.Token {
	return &oauth2.Token{AccessToken: access, RefreshToken: refresh, TokenType: "Bearer", Expiry: time.Now().Add(-time.Minute)}
}

// newCountingTokenTestPlugin returns a plugin with user u1 (a1/r1) stored and
// the write counter reset.
func newCountingTokenTestPlugin(t *testing.T) (*Plugin, *countingStore) {
	t.Helper()
	store := &countingStore{KvStore: &pluginapi.MemoryStore{}}
	p := newTokenTestPlugin(t, store)
	storeInitialUser(t, p, "u1", "a1", "r1")
	store.atomicWrites = 0
	return p, store
}

// TestTokenSource_RefreshPersistsOnce verifies that an expired token is
// refreshed once, persisted once, and readable via getGitHubUserInfo, while
// subsequent calls reuse the fresh token.
func TestTokenSource_RefreshPersistsOnce(t *testing.T) {
	p, store := newCountingTokenTestPlugin(t)
	r := &countingRefresher{}
	src := newTestTokenSource(p, "u1", expiredToken("a1", "r1"), r)

	for range 3 {
		tok, err := src.Token()
		require.NoError(t, err)
		require.Equal(t, "a2", tok.AccessToken)
	}
	require.Equal(t, []string{"r1"}, r.used)
	require.Equal(t, 1, store.atomicWrites, "the rotated token should be persisted only once")

	info, apiErr := p.getGitHubUserInfo("u1")
	require.Nil(t, apiErr)
	require.Equal(t, "a2", info.Token.AccessToken)
	require.Equal(t, "r2", info.Token.RefreshToken)
}

// TestTokenSource_ValidTokenNoWrite guards that a still-valid token neither
// refreshes nor writes.
func TestTokenSource_ValidTokenNoWrite(t *testing.T) {
	p, store := newCountingTokenTestPlugin(t)
	r := &countingRefresher{}
	src := newTestTokenSource(p, "u1", &oauth2.Token{AccessToken: "a1", RefreshToken: "r1", Expiry: time.Now().Add(time.Hour)}, r)

	for range 3 {
		tok, err := src.Token()
		require.NoError(t, err)
		require.Equal(t, "a1", tok.AccessToken)
	}
	require.Empty(t, r.used)
	require.Equal(t, 0, store.atomicWrites, "a still-valid token must not be written back")
}

// TestTokenSource_AdoptsStoredToken verifies that when another request already
// refreshed and stored the token, it is reused instead of refreshing again
// with the (now revoked) old refresh token.
func TestTokenSource_AdoptsStoredToken(t *testing.T) {
	p, _ := newCountingTokenTestPlugin(t)
	require.NoError(t, p.persistRefreshedToken("u1", &oauth2.Token{
		AccessToken: "a2", RefreshToken: "r2", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour),
	}))

	r := &countingRefresher{}
	src := newTestTokenSource(p, "u1", expiredToken("a1", "r1"), r)

	tok, err := src.Token()
	require.NoError(t, err)
	require.Equal(t, "a2", tok.AccessToken)
	require.Empty(t, r.used, "must not refresh when the stored token is already fresh")
}

// TestTokenSource_ConcurrentRefresh is the regression test for Forgejo
// revoking the grant when the same refresh token is used twice: concurrent
// clients of one user with an expired token must refresh only once.
func TestTokenSource_ConcurrentRefresh(t *testing.T) {
	p, _ := newCountingTokenTestPlugin(t)
	r := &countingRefresher{delay: 20 * time.Millisecond}

	const clients = 8
	var wg sync.WaitGroup
	errs := make([]error, clients)
	toks := make([]string, clients)
	for i := range clients {
		src := newTestTokenSource(p, "u1", expiredToken("a1", "r1"), r)
		wg.Go(func() {
			tok, err := src.Token()
			errs[i] = err
			if tok != nil {
				toks[i] = tok.AccessToken
			}
		})
	}
	wg.Wait()

	for i := range clients {
		require.NoError(t, errs[i])
		require.Equal(t, "a2", toks[i])
	}
	require.Equal(t, []string{"r1"}, r.used, "refresh token must be used exactly once")
}
