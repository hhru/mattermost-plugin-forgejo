package plugin

import (
	"context"
	"testing"

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

// fakeTokenSource returns the tokens in sequence, repeating the last one once
// the sequence is exhausted (mimicking ReuseTokenSource handing back a cached
// token on subsequent calls).
type fakeTokenSource struct {
	tokens []*oauth2.Token
	i      int
}

func (f *fakeTokenSource) Token() (*oauth2.Token, error) {
	tok := f.tokens[f.i]
	if f.i < len(f.tokens)-1 {
		f.i++
	}
	return tok, nil
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

// TestPersistingTokenSource_RotationPersists verifies that when the underlying
// source rotates the token, the new pair is persisted to the store and is
// readable back through getGitHubUserInfo.
func TestPersistingTokenSource_RotationPersists(t *testing.T) {
	store := &countingStore{KvStore: &pluginapi.MemoryStore{}}
	p := newTokenTestPlugin(t, store)
	storeInitialUser(t, p, "u1", "a1", "r1")

	src := &persistingTokenSource{
		base: &fakeTokenSource{tokens: []*oauth2.Token{
			{AccessToken: "a2", RefreshToken: "r2", TokenType: "Bearer"},
		}},
		plugin: p,
		userID: "u1",
		seen:   "a1",
	}

	tok, err := src.Token()
	require.NoError(t, err)
	require.Equal(t, "a2", tok.AccessToken)
	require.Equal(t, 1, store.atomicWrites, "rotation should trigger exactly one write")

	info, apiErr := p.getGitHubUserInfo("u1")
	require.Nil(t, apiErr)
	require.Equal(t, "a2", info.Token.AccessToken)
	require.Equal(t, "r2", info.Token.RefreshToken)
}

// TestPersistingTokenSource_ValidTokenNoWrite is the regression guard for the
// concern that the fix might disturb users whose access token has not expired:
// when base.Token() returns the same (still-valid) token, nothing is written.
func TestPersistingTokenSource_ValidTokenNoWrite(t *testing.T) {
	store := &countingStore{KvStore: &pluginapi.MemoryStore{}}
	p := newTokenTestPlugin(t, store)
	storeInitialUser(t, p, "u1", "a1", "r1")

	src := &persistingTokenSource{
		base: &fakeTokenSource{tokens: []*oauth2.Token{
			{AccessToken: "a1", RefreshToken: "r1", TokenType: "Bearer"},
		}},
		plugin: p,
		userID: "u1",
		seen:   "a1",
	}

	// Multiple calls with an unchanged token must never write.
	for range 3 {
		tok, err := src.Token()
		require.NoError(t, err)
		require.Equal(t, "a1", tok.AccessToken)
	}
	require.Equal(t, 0, store.atomicWrites, "a still-valid token must not be written back")
}

// TestPersistingTokenSource_RotatesOncePerNewToken ensures the write happens
// only on the transition to a new token, not on every subsequent request that
// reuses it.
func TestPersistingTokenSource_RotatesOncePerNewToken(t *testing.T) {
	store := &countingStore{KvStore: &pluginapi.MemoryStore{}}
	p := newTokenTestPlugin(t, store)
	storeInitialUser(t, p, "u1", "a1", "r1")

	src := &persistingTokenSource{
		base: &fakeTokenSource{tokens: []*oauth2.Token{
			{AccessToken: "a2", RefreshToken: "r2", TokenType: "Bearer"},
		}},
		plugin: p,
		userID: "u1",
		seen:   "a1",
	}

	for range 3 {
		_, err := src.Token()
		require.NoError(t, err)
	}
	require.Equal(t, 1, store.atomicWrites, "the rotated token should be persisted only once")
}
