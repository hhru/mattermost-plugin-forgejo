// Copyright (c) 2018-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package plugin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/go-github/v54/github"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/oauth2"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin/plugintest"
	"github.com/mattermost/mattermost/server/public/pluginapi"

	"github.com/mattermost/mattermost-plugin-github/server/mocks"
)

const (
	webhookSecret = "whsecret"
)

func TestHandleWebhookBodySizeLimit(t *testing.T) {
	t.Run("rejects oversized request body", func(t *testing.T) {
		_, mockAPI, _, _, _ := GetTestSetup(t)
		p := NewPlugin()
		p.initializeAPI()
		p.SetAPI(mockAPI)
		p.client = pluginapi.NewClient(mockAPI, p.Driver)
		p.setConfiguration(&Configuration{
			WebhookSecret: webhookSecret,
		})

		mockAPI.On("LogInfo", "Webhook event received")

		oversizedBody := strings.NewReader(strings.Repeat("x", 26*1024*1024))
		req := httptest.NewRequest(http.MethodPost, "/webhook", oversizedBody)
		req.Header.Set("X-Hub-Signature", "sha1=invalid")
		w := httptest.NewRecorder()

		p.handleWebhook(w, req)

		assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
	})

	t.Run("accepts normal sized request body", func(t *testing.T) {
		_, mockAPI, _, _, _ := GetTestSetup(t)
		p := NewPlugin()
		p.initializeAPI()
		p.SetAPI(mockAPI)
		p.client = pluginapi.NewClient(mockAPI, p.Driver)
		p.setConfiguration(&Configuration{
			WebhookSecret: webhookSecret,
		})

		mockAPI.On("LogInfo", "Webhook event received")

		body := `{"zen": "test"}`
		req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(body))
		req.Header.Set("X-Hub-Signature", "sha1=invalid")
		w := httptest.NewRecorder()

		p.handleWebhook(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestPostCreateEvent(t *testing.T) {
	tests := []struct {
		name        string
		createEvent *github.CreateEvent
		setup       func(*plugintest.API, *mocks.MockKvStore)
	}{
		{
			name:        "No subscription found",
			createEvent: GetMockCreateEvent(),
			setup: func(_ *plugintest.API, mockKVStore *mocks.MockKvStore) {
				mockKVStore.EXPECT().Get(SubscriptionsKey, mock.MatchedBy(func(val any) bool {
					_, ok := val.(**Subscriptions)
					return ok
				})).Return(nil).Times(1)
			},
		},
		{
			name:        "Unsupported ref type",
			createEvent: GetMockCreateEventWithUnsupportedRefType(),
			setup: func(_ *plugintest.API, mockKVStore *mocks.MockKvStore) {
				mockSubscription(mockKVStore)
			},
		},
		{
			name:        "Error creating post",
			createEvent: GetMockCreateEvent(),
			setup: func(mockAPI *plugintest.API, mockKVStore *mocks.MockKvStore) {
				mockSubscription(mockKVStore)
				mockAPI.On("CreatePost", mock.Anything).Return(nil, &model.AppError{Message: "error creating post"}).Times(1)
				mockAPI.On("LogWarn", "Error webhook post", "channel_id", mock.Anything, "error", "error creating post")
			},
		},
		{
			name:        "Successfully handle post create event",
			createEvent: GetMockCreateEvent(),
			setup: func(mockAPI *plugintest.API, mockKVStore *mocks.MockKvStore) {
				mockSubscription(mockKVStore)
				mockAPI.On("CreatePost", mock.Anything).Return(&model.Post{}, nil).Times(1)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockKVStore, mockAPI, _, _, _ := GetTestSetup(t)
			p := getPluginTest(mockAPI, mockKVStore)

			mockAPI.ExpectedCalls = nil
			tc.setup(mockAPI, mockKVStore)

			p.postCreateEvent(tc.createEvent)

			mockAPI.AssertExpectations(t)
		})
	}
}

func TestPostDeleteEvent(t *testing.T) {
	tests := []struct {
		name        string
		deleteEvent *github.DeleteEvent
		setup       func(*plugintest.API, *mocks.MockKvStore)
	}{
		{
			name:        "No subscription found",
			deleteEvent: GetMockDeleteEvent(),
			setup: func(_ *plugintest.API, mockKVStore *mocks.MockKvStore) {
				mockKVStore.EXPECT().Get(SubscriptionsKey, mock.MatchedBy(func(val any) bool {
					_, ok := val.(**Subscriptions)
					return ok
				})).Return(nil).Times(1)
			},
		},
		{
			name:        "Non-tag and non-branch event",
			deleteEvent: GetMockDeleteEventWithInvalidType(),
			setup: func(_ *plugintest.API, mockKVStore *mocks.MockKvStore) {
				mockSubscription(mockKVStore)
			},
		},
		{
			name:        "Error creating post",
			deleteEvent: GetMockDeleteEvent(),
			setup: func(mockAPI *plugintest.API, mockKVStore *mocks.MockKvStore) {
				mockSubscription(mockKVStore)
				mockAPI.On("CreatePost", mock.Anything).Return(nil, &model.AppError{Message: "error creating post"}).Times(1)
				mockAPI.On("LogWarn", "Error webhook post", "channel_id", mock.Anything, "error", "error creating post")
			},
		},
		{
			name:        "Successful handle post delete event",
			deleteEvent: GetMockDeleteEvent(),
			setup: func(mockAPI *plugintest.API, mockKVStore *mocks.MockKvStore) {
				mockSubscription(mockKVStore)
				mockAPI.On("CreatePost", mock.Anything).Return(&model.Post{}, nil).Times(1)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockKVStore, mockAPI, _, _, _ := GetTestSetup(t)
			p := getPluginTest(mockAPI, mockKVStore)

			mockAPI.ExpectedCalls = nil
			tc.setup(mockAPI, mockKVStore)

			p.postDeleteEvent(tc.deleteEvent)

			mockAPI.AssertExpectations(t)
		})
	}
}

func TestSenderMutedByReceiver(t *testing.T) {
	tests := []struct {
		name   string
		userID string
		sender string
		setup  func(*mocks.MockKvStore, *plugintest.API)
		assert func(t *testing.T, muted bool)
	}{
		{
			name:   "Sender is muted",
			userID: "user1",
			sender: "sender1",
			setup: func(mockKVStore *mocks.MockKvStore, _ *plugintest.API) {
				mockKVStore.EXPECT().Get("user1-muted-users", mock.MatchedBy(func(val any) bool {
					_, ok := val.(*[]uint8)
					return ok
				})).Return(nil).Do(func(key string, value any) {
					*value.(*[]byte) = []byte("sender1,sender2")
				}).Times(1)
			},
			assert: func(t *testing.T, muted bool) {
				assert.True(t, muted, "Expected sender to be muted")
			},
		},
		{
			name:   "Sender is not muted",
			userID: "user1",
			sender: "sender3",
			setup: func(mockKVStore *mocks.MockKvStore, _ *plugintest.API) {
				mockKVStore.EXPECT().Get("user1-muted-users", mock.MatchedBy(func(val any) bool {
					_, ok := val.(*[]uint8)
					return ok
				})).Return(nil).Do(func(key string, value any) {
					*value.(*[]byte) = []byte("sender1,sender2")
				}).Times(1)
			},
			assert: func(t *testing.T, muted bool) {
				assert.False(t, muted, "Expected sender to not be muted")
			},
		},
		{
			name:   "Sender is muted with different casing",
			userID: "user1",
			sender: "Sender1",
			setup: func(mockKVStore *mocks.MockKvStore, _ *plugintest.API) {
				mockKVStore.EXPECT().Get("user1-muted-users", mock.MatchedBy(func(val any) bool {
					_, ok := val.(*[]uint8)
					return ok
				})).Return(nil).Do(func(key string, value any) {
					*value.(*[]byte) = []byte("sender1,sender2")
				}).Times(1)
			},
			assert: func(t *testing.T, muted bool) {
				assert.True(t, muted, "Expected sender to be muted regardless of casing")
			},
		},
		{
			name:   "Empty muted users list",
			userID: "user1",
			sender: "sender1",
			setup: func(mockKVStore *mocks.MockKvStore, _ *plugintest.API) {
				mockKVStore.EXPECT().Get("user1-muted-users", mock.MatchedBy(func(val any) bool {
					_, ok := val.(*[]uint8)
					return ok
				})).Return(nil).Do(func(key string, value any) {
					*value.(*[]byte) = []byte("")
				}).Times(1)
			},
			assert: func(t *testing.T, muted bool) {
				assert.False(t, muted, "Expected sender to not be muted when mute list is empty")
			},
		},
		{
			name:   "Error fetching muted users",
			userID: "user1",
			sender: "sender1",
			setup: func(mockKVStore *mocks.MockKvStore, mockAPI *plugintest.API) {
				mockKVStore.EXPECT().Get("user1-muted-users", mock.MatchedBy(func(val any) bool {
					_, ok := val.(*[]uint8)
					return ok
				})).Return(errors.New("store error")).Times(1)
				mockAPI.On("LogWarn", "Failed to get muted users", "userID", "user1").Times(1)
			},
			assert: func(t *testing.T, muted bool) {
				assert.False(t, muted, "Expected sender to not be muted due to store error")
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockKVStore, mockAPI, _, _, _ := GetTestSetup(t)
			p := getPluginTest(mockAPI, mockKVStore)

			mockAPI.ExpectedCalls = nil
			tc.setup(mockKVStore, mockAPI)

			muted := p.senderMutedByReceiver(tc.userID, tc.sender)

			tc.assert(t, muted)
			mockAPI.AssertExpectations(t)
		})
	}
}

func TestHandleIssueNotification(t *testing.T) {
	mockKvStore, mockAPI, _, _, _ := GetTestSetup(t)
	p := getPluginTest(mockAPI, mockKvStore)

	tests := []struct {
		name      string
		event     *github.IssuesEvent
		setup     func()
		assertDMs func(*testing.T)
	}{
		{
			name:  "issue closed by author",
			event: GetMockIssuesEvent(actionClosed, MockRepo, false, "authorUser", "authorUser", ""),
			setup: func() {},
		},
		{
			name:  "issue closed successfully",
			event: GetMockIssuesEvent(actionClosed, MockRepo, true, "authorUser", "senderUser", ""),
			setup: func() {
				mockKvStore.EXPECT().Get("authorUser_forgejousername", mock.MatchedBy(func(val any) bool {
					_, ok := val.(*[]uint8)
					return ok
				})).DoAndReturn(setByteValue("authorUserID")).Times(1)
				mockKvStore.EXPECT().Get("authorUserID_forgejotoken", mock.MatchedBy(func(val any) bool {
					_, ok := val.(**ForgejoUserInfo)
					return ok
				})).Return(nil).Times(1)
			},
		},
		{
			name:  "issue reopened with no repo permission",
			event: GetMockIssuesEvent(actionReopened, MockRepo, true, "authorUser", "senderUser", ""),
			setup: func() {
				mockKvStore.EXPECT().Get("authorUser_forgejousername", mock.MatchedBy(func(val any) bool {
					_, ok := val.(*[]uint8)
					return ok
				})).Return(nil).Times(1)
			},
		},
		{
			name:  "issue assigned to self",
			event: GetMockIssuesEvent(actionAssigned, MockRepo, false, "assigneeUser", "assigneeUser", "assigneeUser"),
			setup: func() {},
		},
		{
			name:  "issue assigned successfully",
			event: GetMockIssuesEvent(actionAssigned, MockRepo, false, "senderUser", "assigneeUser", "assigneeUser"),
			setup: func() {
				mockKvStore.EXPECT().Get("assigneeUser_forgejousername", mock.MatchedBy(func(val any) bool {
					_, ok := val.(*[]uint8)
					return ok
				})).DoAndReturn(setByteValue("assigneeUserID")).Times(1)
			},
		},
		{
			name:  "issue assigned with no repo permission for assignee",
			event: GetMockIssuesEvent(actionAssigned, MockRepo, true, "senderUser", "demoassigneeUser", "assigneeUser"),
			setup: func() {
				mockKvStore.EXPECT().Get("assigneeUser_forgejousername", mock.MatchedBy(func(val any) bool {
					_, ok := val.(*[]uint8)
					return ok
				})).DoAndReturn(setByteValue("assigneeUserID")).Times(1)
			},
		},
		{
			name:  "muted sender suppresses issue closed notification to author",
			event: GetMockIssuesEvent(actionClosed, MockRepo, false, "authorUser", "senderUser", ""),
			setup: func() {
				mockKvStore.EXPECT().Get("authorUser_forgejousername", mock.MatchedBy(func(val any) bool {
					_, ok := val.(*[]uint8)
					return ok
				})).DoAndReturn(setByteValue("authorUserID")).Times(1)
				mockKvStore.EXPECT().Get("authorUserID-muted-users", mock.MatchedBy(func(val any) bool {
					_, ok := val.(*[]uint8)
					return ok
				})).DoAndReturn(func(key string, value any) error {
					*value.(*[]byte) = []byte("senderUser,otherBot")
					return nil
				}).Times(1)
			},
			assertDMs: func(t *testing.T) {
				t.Helper()
				mockAPI.AssertNotCalled(t, "GetDirectChannel", mock.Anything, mock.Anything)
				mockAPI.AssertNotCalled(t, "CreatePost", mock.Anything)
			},
		},
		{
			name:  "muted sender suppresses issue assigned notification to assignee",
			event: GetMockIssuesEvent(actionAssigned, MockRepo, false, "authorUser", "senderUser", "assigneeUser"),
			setup: func() {
				mockKvStore.EXPECT().Get("assigneeUser_forgejousername", mock.MatchedBy(func(val any) bool {
					_, ok := val.(*[]uint8)
					return ok
				})).DoAndReturn(setByteValue("assigneeUserID")).Times(1)
				mockKvStore.EXPECT().Get("assigneeUserID-muted-users", mock.MatchedBy(func(val any) bool {
					_, ok := val.(*[]uint8)
					return ok
				})).DoAndReturn(func(key string, value any) error {
					*value.(*[]byte) = []byte("senderUser")
					return nil
				}).Times(1)
			},
			assertDMs: func(t *testing.T) {
				t.Helper()
				mockAPI.AssertNotCalled(t, "GetDirectChannel", mock.Anything, mock.Anything)
				mockAPI.AssertNotCalled(t, "CreatePost", mock.Anything)
			},
		},
		{
			name:  "unhandled event action",
			event: GetMockIssuesEvent("unsupported_action", MockRepo, false, "senderUser", "", ""),
			setup: func() {
				mockAPI.On("LogDebug", "Unhandled event action", "action", "unsupported_action").Return(nil).Times(1)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockAPI.ExpectedCalls = nil
			mockAPI.Calls = nil
			tc.setup()

			p.handleIssueNotification(tc.event)

			if tc.assertDMs != nil {
				tc.assertDMs(t)
			}
			mockAPI.AssertExpectations(t)
		})
	}
}

func TestPostStarEvent(t *testing.T) {
	mockKvStore, mockAPI, _, _, _ := GetTestSetup(t)
	p := getPluginTest(mockAPI, mockKvStore)

	tests := []struct {
		name  string
		event *github.StarEvent
		setup func()
	}{
		{
			name:  "no subscribed channels for repository",
			event: GetMockStarEvent(MockRepo, MockOrg, false, MockSender),
			setup: func() {
				mockKvStore.EXPECT().Get("subscriptions", mock.MatchedBy(func(val any) bool {
					_, ok := val.(**Subscriptions)
					return ok
				})).Return(nil).Times(1)
			},
		},
		{
			name:  "error creating post",
			event: GetMockStarEvent(MockRepo, MockOrg, false, MockSender),
			setup: func() {
				mockKvStore.EXPECT().Get("subscriptions", mock.MatchedBy(func(val any) bool {
					_, ok := val.(**Subscriptions)
					return ok
				})).DoAndReturn(setupMockSubscriptions(map[string][]*Subscription{
					"mockrepo/mockorg": {
						{ChannelID: MockChannelID, CreatorID: MockCreatorID, Features: featureStars, Repository: MockRepo},
						{ChannelID: MockChannelID, CreatorID: MockCreatorID, Features: featureDeletes, Repository: MockRepo},
					},
				})).Times(1)
				mockAPI.On("CreatePost", mock.Anything).Return(nil, &model.AppError{Message: "error creating post"}).Times(1)
				mockAPI.On("LogWarn", "Error webhook post", "channel_id", mock.Anything, "error", "error creating post")
			},
		},
		{
			name:  "successful star event notification",
			event: GetMockStarEvent(MockRepo, MockOrg, false, MockSender),
			setup: func() {
				mockKvStore.EXPECT().Get("subscriptions", mock.MatchedBy(func(val any) bool {
					_, ok := val.(**Subscriptions)
					return ok
				})).DoAndReturn(setupMockSubscriptions(map[string][]*Subscription{
					"mockrepo/mockorg": {
						{ChannelID: MockChannelID, CreatorID: MockCreatorID, Features: featureStars, Repository: MockRepo},
						{ChannelID: MockChannelID, CreatorID: MockCreatorID, Features: featureDeletes, Repository: MockRepo},
					},
				})).Times(1)
				mockAPI.On("CreatePost", mock.Anything).Return(&model.Post{}, nil).Times(1)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockAPI.ExpectedCalls = nil
			tc.setup()

			p.postStarEvent(tc.event)

			mockAPI.AssertExpectations(t)
		})
	}
}

func TestPostReleaseEvent(t *testing.T) {
	mockKvStore, mockAPI, _, _, _ := GetTestSetup(t)
	p := getPluginTest(mockAPI, mockKvStore)

	tests := []struct {
		name  string
		event *github.ReleaseEvent
		setup func()
	}{
		{
			name:  "no subscribed channels for repository",
			event: GetMockReleaseEvent(MockRepo, MockOrg, "created", MockSender),
			setup: func() {
				mockKvStore.EXPECT().Get("subscriptions", mock.MatchedBy(func(val any) bool {
					_, ok := val.(**Subscriptions)
					return ok
				})).Return(nil).Times(1)
			},
		},
		{
			name:  "unsupported action",
			event: GetMockReleaseEvent(MockRepo, MockOrg, "edited", MockSender),
			setup: func() {},
		},
		{
			name:  "error creating post",
			event: GetMockReleaseEvent(MockRepo, MockOrg, "created", MockSender),
			setup: func() {
				mockKvStore.EXPECT().Get("subscriptions", mock.MatchedBy(func(val any) bool {
					_, ok := val.(**Subscriptions)
					return ok
				})).DoAndReturn(setupMockSubscriptions(map[string][]*Subscription{
					"mockrepo/mockorg": {
						{ChannelID: MockChannelID, CreatorID: MockCreatorID, Features: featureReleases, Repository: MockRepo},
						{ChannelID: MockChannelID, CreatorID: MockCreatorID, Features: featureDeletes, Repository: MockRepo},
					},
				})).Times(1)
				mockAPI.On("CreatePost", mock.Anything).Return(nil, &model.AppError{Message: "error creating post"}).Times(1)
				mockAPI.On("LogWarn", "Error webhook post", "channel_id", mock.Anything, "error", "error creating post")
			},
		},
		{
			name:  "successful release event notification",
			event: GetMockReleaseEvent(MockRepo, MockOrg, "created", MockSender),
			setup: func() {
				mockKvStore.EXPECT().Get("subscriptions", mock.MatchedBy(func(val any) bool {
					_, ok := val.(**Subscriptions)
					return ok
				})).DoAndReturn(setupMockSubscriptions(map[string][]*Subscription{
					"mockrepo/mockorg": {
						{ChannelID: MockChannelID, CreatorID: MockCreatorID, Features: featureReleases, Repository: MockRepo},
						{ChannelID: MockChannelID, CreatorID: MockCreatorID, Features: featureDeletes, Repository: MockRepo},
					},
				})).Times(1)
				mockAPI.On("CreatePost", mock.Anything).Return(&model.Post{}, nil).Times(1)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockAPI.ExpectedCalls = nil
			tc.setup()

			p.postReleaseEvent(tc.event)

			mockAPI.AssertExpectations(t)
		})
	}
}

func TestPostDiscussionEvent(t *testing.T) {
	mockKvStore, mockAPI, _, _, _ := GetTestSetup(t)
	p := getPluginTest(mockAPI, mockKvStore)

	tests := []struct {
		name  string
		event *github.DiscussionEvent
		setup func()
	}{
		{
			name:  "no subscribed channels for repository",
			event: GetMockDiscussionEvent(MockRepo, MockOrg, MockSender),
			setup: func() {
				mockKvStore.EXPECT().Get("subscriptions", mock.MatchedBy(func(val any) bool {
					_, ok := val.(**Subscriptions)
					return ok
				})).Return(nil).Times(1)
			},
		},
		{
			name:  "error creating discussion post",
			event: GetMockDiscussionEvent(MockRepo, MockOrg, MockSender),
			setup: func() {
				mockKvStore.EXPECT().Get("subscriptions", mock.MatchedBy(func(val any) bool {
					_, ok := val.(**Subscriptions)
					return ok
				})).DoAndReturn(setupMockSubscriptions(map[string][]*Subscription{
					"mockrepo/mockorg": {
						{ChannelID: MockChannelID, CreatorID: MockCreatorID, Features: featureDiscussions, Repository: MockRepo},
						{ChannelID: MockChannelID, CreatorID: MockCreatorID, Features: featureDeletes, Repository: MockRepo},
					},
				})).Times(1)
				mockAPI.On("CreatePost", mock.Anything).Return(nil, &model.AppError{Message: "error creating post"}).Times(1)
				mockAPI.On("LogWarn", "Error creating discussion notification post", "channel_id", mock.Anything, "error", "error creating post")
			},
		},
		{
			name:  "successful discussion notification",
			event: GetMockDiscussionEvent(MockRepo, MockOrg, MockSender),
			setup: func() {
				mockKvStore.EXPECT().Get("subscriptions", mock.MatchedBy(func(val any) bool {
					_, ok := val.(**Subscriptions)
					return ok
				})).DoAndReturn(setupMockSubscriptions(map[string][]*Subscription{
					"mockrepo/mockorg": {
						{ChannelID: MockChannelID, CreatorID: MockCreatorID, Features: featureDiscussions, Repository: MockRepo},
					},
				})).Times(1)
				mockAPI.On("CreatePost", mock.Anything).Return(&model.Post{}, nil).Times(1)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockAPI.ExpectedCalls = nil
			tc.setup()

			p.postDiscussionEvent(tc.event)

			mockAPI.AssertExpectations(t)
		})
	}
}

func TestPostDiscussionCommentEvent(t *testing.T) {
	mockKvStore, mockAPI, _, _, _ := GetTestSetup(t)
	p := getPluginTest(mockAPI, mockKvStore)

	tests := []struct {
		name  string
		event *github.DiscussionCommentEvent
		setup func()
	}{
		{
			name:  "no subscribed channels for repository",
			event: GetMockDiscussionCommentEvent(MockRepo, MockOrg, "created", MockSender),
			setup: func() {
				mockKvStore.EXPECT().Get("subscriptions", mock.MatchedBy(func(val any) bool {
					_, ok := val.(**Subscriptions)
					return ok
				})).Return(nil).Times(1)
			},
		},
		{
			name:  "error creating discussion comment post",
			event: GetMockDiscussionCommentEvent(MockRepo, MockOrg, "created", MockSender),
			setup: func() {
				mockKvStore.EXPECT().Get("subscriptions", mock.MatchedBy(func(val any) bool {
					_, ok := val.(**Subscriptions)
					return ok
				})).DoAndReturn(setupMockSubscriptions(map[string][]*Subscription{
					"mockrepo/mockorg": {
						{ChannelID: MockChannelID, CreatorID: MockCreatorID, Features: featureDiscussionComments, Repository: MockRepo},
						{ChannelID: MockChannelID, CreatorID: MockCreatorID, Features: featureDeletes, Repository: MockRepo},
					},
				})).Times(1)
				mockAPI.On("CreatePost", mock.Anything).Return(nil, &model.AppError{Message: "error creating post"}).Times(1)
				mockAPI.On("LogWarn", "Error creating discussion comment post", "channel_id", mock.Anything, "error", "error creating post")
			},
		},
		{
			name:  "successful discussion comment notification",
			event: GetMockDiscussionCommentEvent(MockRepo, MockOrg, "created", MockSender),
			setup: func() {
				mockKvStore.EXPECT().Get("subscriptions", mock.MatchedBy(func(val any) bool {
					_, ok := val.(**Subscriptions)
					return ok
				})).DoAndReturn(setupMockSubscriptions(map[string][]*Subscription{
					"mockrepo/mockorg": {
						{ChannelID: MockChannelID, CreatorID: MockCreatorID, Features: featureDiscussionComments, Repository: MockRepo},
					},
				})).Times(1)
				mockAPI.On("CreatePost", mock.Anything).Return(&model.Post{}, nil).Times(1)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockAPI.ExpectedCalls = nil
			tc.setup()

			p.postDiscussionCommentEvent(tc.event)

			mockAPI.AssertExpectations(t)
		})
	}
}

func mockSubscription(mockKVStore *mocks.MockKvStore) {
	mockKVStore.EXPECT().Get(SubscriptionsKey, mock.MatchedBy(func(val any) bool {
		_, ok := val.(**Subscriptions)
		return ok
	})).DoAndReturn(func(key string, value any) error {
		if v, ok := value.(**Subscriptions); ok {
			*v = GetMockSubscriptions()
		}
		return nil
	}).Times(1)
}

func setupMockSubscriptions(subs map[string][]*Subscription) func(string, any) error {
	return func(_ string, value any) error {
		if v, ok := value.(**Subscriptions); ok {
			*v = &Subscriptions{
				Repositories: subs,
			}
		}
		return nil
	}
}

func setByteValue(data string) func(key string, value any) error {
	return func(key string, value any) error {
		if v, ok := value.(*[]byte); ok {
			*v = []byte(data)
		}
		return nil
	}
}

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

			// Mock getGitHubUserInfo if userInfo is provided. getGitHubUserInfo
			// decrypts the stored tokens, so encrypt them with the plugin's
			// configured key first.
			if tt.userInfo != nil {
				encKey := []byte(p.getConfiguration().EncryptionKey)
				encAccess, err := encrypt(encKey, tt.userInfo.Token.AccessToken)
				assert.NoError(t, err)
				encRefresh, err := encrypt(encKey, tt.userInfo.Token.RefreshToken)
				assert.NoError(t, err)
				tt.userInfo.Token.AccessToken = encAccess
				tt.userInfo.Token.RefreshToken = encRefresh
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
