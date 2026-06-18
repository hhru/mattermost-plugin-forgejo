package plugin

import (
	"encoding/json"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/go-github/v54/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/mattermost/mattermost/server/public/plugin/plugintest"

	"github.com/mattermost/mattermost-plugin-github/server/mocks"
)

func TestIgnoreRequestedReview(t *testing.T) {
	tests := map[string]struct {
		event           *FPullRequestEvent
		requestedUserID string
		userInfo        *ForgejoUserInfo
		expected        bool
	}{
		"empty user ID": {
			event: &FPullRequestEvent{
				PullRequest: &FPullRequest{
					RequestedReviewersTeams: []*FTeam{},
				},
			},
			requestedUserID: "",
			expected:        false,
		},
		"no team reviewers": {
			event: &FPullRequestEvent{
				PullRequest: &FPullRequest{
					RequestedReviewersTeams: []*FTeam{},
				},
			},
			requestedUserID: "test-userID",
			expected:        false,
		},
		"user is individual reviewer": {
			event: &FPullRequestEvent{
				PullRequest: &FPullRequest{
					RequestedReviewersTeams: []*FTeam{{Name: stringPtr("team1")}},
					RequestedReviewers: []*FUser{
						{Login: stringPtr("test-user")},
					},
				},
				RequestedReviewer: &FUser{Login: stringPtr("test-user")},
			},
			requestedUserID: "test-userID",
			userInfo: &ForgejoUserInfo{
				Token: &oauth2.Token{
					AccessToken:  testToken,
					RefreshToken: testToken,
				},
				Settings: &UserSettings{
					DisableTeamNotifications: true,
				},
			},
			expected: false,
		},
		"team notifications disabled": {
			event: &FPullRequestEvent{
				PullRequest: &FPullRequest{
					RequestedReviewersTeams: []*FTeam{{Name: stringPtr("team1")}},
				},
			},
			requestedUserID: "test-userID",
			userInfo: &ForgejoUserInfo{
				Token: &oauth2.Token{
					AccessToken:  testToken,
					RefreshToken: testToken,
				},
				Settings: &UserSettings{
					DisableTeamNotifications: true,
				},
			},
			expected: true,
		},
		"repository excluded": {
			event: &FPullRequestEvent{
				PullRequest: &FPullRequest{
					RequestedReviewersTeams: []*FTeam{{Name: stringPtr("team1")}},
				},
				Repo: &FRepository{
					FullName: stringPtr("org/repo1"),
				},
			},
			requestedUserID: "test-userID",
			userInfo: &ForgejoUserInfo{
				Token: &oauth2.Token{
					AccessToken:  testToken,
					RefreshToken: testToken,
				},
				Settings: &UserSettings{
					DisableTeamNotifications:       false,
					ExcludeTeamReviewNotifications: []string{"org/repo1"},
				},
			},
			expected: true,
		},
		"repository not excluded": {
			event: &FPullRequestEvent{
				PullRequest: &FPullRequest{
					RequestedReviewersTeams: []*FTeam{{Name: stringPtr("team1")}},
				},
				Repo: &FRepository{
					FullName: stringPtr("org/repo1"),
				},
			},
			requestedUserID: "test-userID",
			userInfo: &ForgejoUserInfo{
				Token: &oauth2.Token{
					AccessToken:  testToken,
					RefreshToken: testToken,
				},
				Settings: &UserSettings{
					DisableTeamNotifications:       false,
					ExcludeTeamReviewNotifications: []string{"org/other-repo"},
				},
			},
			expected: false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mockKvStore := mocks.NewMockKvStore(mockCtrl)
			currentTestAPI := &plugintest.API{}
			p := getPluginTest(currentTestAPI, mockKvStore)

			// Mock getGitHubUserInfo if userInfo is provided
			if tt.userInfo != nil {
				mockKvStore.EXPECT().
					Get("test-userID"+forgejoTokenKey, gomock.Any()).
					DoAndReturn(func(key string, value any) error {
						*(value.(**ForgejoUserInfo)) = tt.userInfo
						return nil
					}).
					AnyTimes()
			}

			result := p.ignoreRequestedReview(tt.event, tt.requestedUserID)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Helper function to create string pointers
func stringPtr(s string) *string {
	return &s
}

// forgejoIssuesPayload mirrors the shape Forgejo (v10..v14) sends for the
// "issues" webhook event. The nested issue.repository.owner is a string
// (Forgejo's RepositoryMeta), which is why go-github's ParseWebHook cannot
// unmarshal it and the plugin parses it into FIssuesEvent instead.
const forgejoIssuesPayload = `{
	"action": "opened",
	"number": 7,
	"issue": {
		"number": 7,
		"title": "Sample issue",
		"body": "issue body @devuser",
		"html_url": "http://forgejo.example/devuser/testrepo/issues/7",
		"user": {"login": "devuser", "html_url": "http://forgejo.example/devuser"},
		"labels": [{"name": "bug", "color": "ff0000"}],
		"created_at": "2026-06-17T09:40:00Z",
		"updated_at": "2026-06-17T09:40:00Z",
		"repository": {"id": 1, "name": "testrepo", "owner": "devuser", "full_name": "devuser/testrepo"}
	},
	"repository": {"full_name": "devuser/testrepo", "private": false, "html_url": "http://forgejo.example/devuser/testrepo", "owner": {"login": "devuser"}},
	"sender": {"login": "devuser", "html_url": "http://forgejo.example/devuser"}
}`

func TestForgejoIssuesEventParsing(t *testing.T) {
	body := []byte(forgejoIssuesPayload)

	// go-github cannot parse the Forgejo payload: issue.repository.owner is a
	// string, but go-github expects an object. This documents why FIssuesEvent exists.
	_, ghErr := github.ParseWebHook("issues", body)
	assert.Error(t, ghErr)

	// The Forgejo-native type parses cleanly via the same path the webhook uses.
	var event FIssuesEvent
	require.NoError(t, json.Unmarshal(body, &event))

	gh := event.toGitHubIssuesEvent()
	require.NotNil(t, gh)
	assert.Equal(t, "opened", gh.GetAction())
	assert.Equal(t, "devuser/testrepo", gh.GetRepo().GetFullName())
	assert.False(t, gh.GetRepo().GetPrivate())
	assert.Equal(t, 7, gh.GetIssue().GetNumber())
	assert.Equal(t, "Sample issue", gh.GetIssue().GetTitle())
	assert.Equal(t, "issue body @devuser", gh.GetIssue().GetBody())
	assert.Equal(t, "devuser", gh.GetIssue().GetUser().GetLogin())
	assert.Equal(t, "devuser", gh.GetSender().GetLogin())
	require.Len(t, gh.GetIssue().Labels, 1)
	assert.Equal(t, "bug", gh.GetIssue().Labels[0].GetName())
}
