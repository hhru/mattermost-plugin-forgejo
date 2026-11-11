package plugin

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-github/v54/github"
	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin/plugintest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestCheckIfConfiguredWebhookExists(t *testing.T) {
	const (
		siteURL = "https://example.com"
		owner   = "test-owner"
		repo    = "test-repo"
	)
	repoHooks := fmt.Sprintf("/repos/%s/%s/hooks", owner, repo)
	orgHooks := fmt.Sprintf("/orgs/%s/hooks", owner)
	matchingHook := fmt.Sprintf(`[{"config":{"url":"%s/plugins/forgejo/webhook"}}]`, siteURL)

	respond := func(status int, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}
	}

	unexpected := func(t *testing.T) http.HandlerFunc {
		return func(_ http.ResponseWriter, r *http.Request) { t.Errorf("unexpected request %s", r.URL.Path) }
	}

	run := func(t *testing.T, routes map[string]http.HandlerFunc, repo string) (bool, error) {
		t.Helper()
		mux := http.NewServeMux()
		for path, h := range routes {
			mux.HandleFunc(path, h)
		}
		server := httptest.NewServer(mux)
		t.Cleanup(server.Close)

		client := github.NewClient(nil)
		base, err := url.Parse(server.URL + "/")
		require.NoError(t, err)
		client.BaseURL = base

		api := &plugintest.API{}
		api.On("GetConfig").Return(&model.Config{ServiceSettings: model.ServiceSettings{SiteURL: model.NewPointer(siteURL)}})
		api.On("LogWarn", "Not able to get the list of webhooks", "Owner", owner, "Repo", repo, "error", mock.Anything).Maybe()
		p := getPluginTest(api, nil)

		return p.checkIfConfiguredWebhookExists(context.Background(), client, repo, owner)
	}

	t.Run("repo webhook matches site URL", func(t *testing.T) {
		found, err := run(t, map[string]http.HandlerFunc{
			repoHooks: respond(http.StatusOK, matchingHook),
			orgHooks:  unexpected(t),
		}, repo)
		require.NoError(t, err)
		assert.True(t, found)
	})

	t.Run("user-owned repo without a webhook", func(t *testing.T) {
		found, err := run(t, map[string]http.HandlerFunc{
			repoHooks: respond(http.StatusOK, "[]"),
			orgHooks:  respond(http.StatusNotFound, `{"message":"GetOrgByName"}`),
		}, repo)
		require.NoError(t, err)
		assert.False(t, found)
	})

	t.Run("org-owned repo falls back to an org webhook", func(t *testing.T) {
		found, err := run(t, map[string]http.HandlerFunc{
			repoHooks: respond(http.StatusOK, "[]"),
			orgHooks:  respond(http.StatusOK, matchingHook),
		}, repo)
		require.NoError(t, err)
		assert.True(t, found)
	})

	t.Run("org-owned repo without any webhook", func(t *testing.T) {
		found, err := run(t, map[string]http.HandlerFunc{
			repoHooks: respond(http.StatusOK, "[]"),
			orgHooks:  respond(http.StatusOK, `[{"config":{"url":"https://other.example.com/hook"}}]`),
		}, repo)
		require.NoError(t, err)
		assert.False(t, found)
	})

	t.Run("org webhooks hidden from non-admins are assumed configured", func(t *testing.T) {
		found, err := run(t, map[string]http.HandlerFunc{
			repoHooks: respond(http.StatusOK, "[]"),
			orgHooks:  respond(http.StatusForbidden, `{"message":"Forbidden"}`),
		}, repo)
		require.NoError(t, err)
		assert.True(t, found)
	})

	t.Run("repo webhooks access error is returned", func(t *testing.T) {
		_, err := run(t, map[string]http.HandlerFunc{
			repoHooks: respond(http.StatusForbidden, `{"message":"Forbidden"}`),
			orgHooks:  unexpected(t),
		}, repo)
		assert.True(t, isWebhookListAccessError(err))
	})

	t.Run("org subscription checks the org webhooks only", func(t *testing.T) {
		found, err := run(t, map[string]http.HandlerFunc{
			orgHooks: respond(http.StatusOK, matchingHook),
		}, "")
		require.NoError(t, err)
		assert.True(t, found)
	})
}
