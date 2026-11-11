package plugin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mattermost/mattermost/server/public/pluginapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetReviewComments(t *testing.T) {
	const (
		userID     = "author"
		reviewsURL = "/api/v1/repos/o/r/pulls/42/reviews"
	)

	event := func(reviewType string) *FPullRequestReviewEvent {
		return &FPullRequestReviewEvent{
			Repo:        &FRepository{Owner: &FUser{Login: sToP("o")}, Name: sToP("r")},
			PullRequest: &FPullRequest{Number: iToP(42)},
			Sender:      &FUser{Login: sToP("panda")},
			Review:      &FPullRequestReview{Type: sToP(reviewType)},
		}
	}

	review := func(id int, login, state string) map[string]any {
		return map[string]any{
			"id": id, "state": state, "user": map[string]any{"login": login},
			"html_url": fmt.Sprintf("https://forgejo.example.com/o/r/pulls/42#issuecomment-%d", id),
		}
	}

	comments := func(n int) []map[string]any {
		out := make([]map[string]any, n)
		for i := range out {
			out[i] = map[string]any{"path": "a.go", "html_url": fmt.Sprintf("https://forgejo.example.com/c/%d", i)}
		}
		return out
	}

	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}

	reviews := []map[string]any{
		review(3, "panda", "REQUEST_CHANGES"),
		review(5, "bob", "REQUEST_CHANGES"),
		review(6, "panda", "COMMENT"),
		review(7, "panda", "REQUEST_CHANGES"),
	}

	// setup serves the PR reviews and the given handler for any review's comments.
	setup := func(t *testing.T, commentsHandler http.HandlerFunc) *Plugin {
		t.Helper()
		mux := http.NewServeMux()
		mux.HandleFunc(reviewsURL, func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, reviews) })
		mux.HandleFunc(reviewsURL+"/", commentsHandler)
		server := httptest.NewServer(mux)
		t.Cleanup(server.Close)

		p := newTokenTestPlugin(t, &pluginapi.MemoryStore{})
		config := p.getConfiguration().Clone()
		config.BaseURL = server.URL
		config.UploadURL = server.URL
		p.setConfiguration(config)
		storeInitialUser(t, p, userID, "access", "refresh")
		return p
	}

	commentsOfReview7 := func(n int) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, reviewsURL+"/7/comments", r.URL.Path)
			writeJSON(w, comments(n))
		}
	}

	t.Run("links comments of the latest matching review", func(t *testing.T) {
		p := setup(t, commentsOfReview7(2))

		got, moreURL := p.getReviewComments(userID, event("pull_request_review_rejected"))
		require.Len(t, got, 2)
		assert.Equal(t, "a.go", got[0].GetPath())
		assert.Equal(t, "https://forgejo.example.com/c/1", got[1].GetHTMLURL())
		assert.Empty(t, moreURL)
	})

	t.Run("caps links and points to the review for the rest", func(t *testing.T) {
		p := setup(t, commentsOfReview7(maxReviewCommentLinks+1))

		got, moreURL := p.getReviewComments(userID, event("pull_request_review_rejected"))
		assert.Len(t, got, maxReviewCommentLinks)
		assert.Equal(t, "https://forgejo.example.com/o/r/pulls/42#issuecomment-7", moreURL)
	})

	t.Run("no matching review skips the comments request", func(t *testing.T) {
		p := setup(t, func(_ http.ResponseWriter, r *http.Request) { t.Errorf("unexpected request %s", r.URL.Path) })

		got, moreURL := p.getReviewComments(userID, event("pull_request_review_approved"))
		assert.Nil(t, got)
		assert.Empty(t, moreURL)
	})

	t.Run("Forgejo error sends the DM without links", func(t *testing.T) {
		p := setup(t, func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"message":"boom"}`, http.StatusInternalServerError)
		})

		got, moreURL := p.getReviewComments(userID, event("pull_request_review_rejected"))
		assert.Nil(t, got)
		assert.Empty(t, moreURL)
	})

	t.Run("not connected", func(t *testing.T) {
		p := newTokenTestPlugin(t, &pluginapi.MemoryStore{})

		got, moreURL := p.getReviewComments(userID, event("pull_request_review_rejected"))
		assert.Nil(t, got)
		assert.Empty(t, moreURL)
	})
}
