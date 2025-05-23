package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/go-github/v54/github"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
	"github.com/mattermost/mattermost/server/public/pluginapi"
	"github.com/mattermost/mattermost/server/public/pluginapi/experimental/bot/logger"
	"github.com/mattermost/mattermost/server/public/pluginapi/experimental/flow"
)

const (
	apiErrorIDNotConnected = "not_connected"
	// TokenTTL is the OAuth token expiry duration in seconds
	TokenTTL = 10 * 60

	requestTimeout       = 30 * time.Second
	oauthCompleteTimeout = 2 * time.Minute
)

type OAuthState struct {
	UserID         string `json:"user_id"`
	Token          string `json:"token"`
	PrivateAllowed bool   `json:"private_allowed"`
}

type APIErrorResponse struct {
	ID         string `json:"id"`
	Message    string `json:"message"`
	StatusCode int    `json:"status_code"`
}

func (e *APIErrorResponse) Error() string {
	return e.Message
}

type PRDetails struct {
	URL                string    `json:"url"`
	Number             int       `json:"number"`
	Status             string    `json:"status"`
	Mergeable          bool      `json:"mergeable"`
	RequestedReviewers []*string `json:"requestedReviewers"`
	Reviews            []string  `json:"reviews"`
}

type FilteredNotification struct {
	FNotification
	HTMLURL string `json:"html_url"`
}

type SidebarContent struct {
	// TODO: get additions/deletitions data about pr content from api/v1/repos/{owner}/{repo}/pulls/{id}
	PRs         []*github.Issue         `json:"prs"`
	Reviews     []*github.Issue         `json:"reviews"`
	Assignments []*github.Issue         `json:"assignments"`
	Unreads     []*FilteredNotification `json:"unreads"`
}

type Context struct {
	Ctx    context.Context
	UserID string
	Log    logger.Logger
}

// HTTPHandlerFuncWithContext is http.HandleFunc but with a Context attached
type HTTPHandlerFuncWithContext func(c *Context, w http.ResponseWriter, r *http.Request)

type UserContext struct {
	Context
	GHInfo *ForgejoUserInfo
}

// HTTPHandlerFuncWithUserContext is http.HandleFunc but with a UserContext attached
type HTTPHandlerFuncWithUserContext func(c *UserContext, w http.ResponseWriter, r *http.Request)

// ResponseType indicates type of response returned by api
type ResponseType string

const (
	// ResponseTypeJSON indicates that response type is json
	ResponseTypeJSON ResponseType = "JSON_RESPONSE"
	// ResponseTypePlain indicates that response type is text plain
	ResponseTypePlain ResponseType = "TEXT_RESPONSE"
)

type FRepositoryMeta struct {
	FullName *string `json:"full_name,omitempty"`
}

type FRepository struct {
	FullName *string `json:"full_name,omitempty"`
	Owner    *FUser  `json:"owner,omitempty"`
	HTMLURL  *string `json:"html_url,omitempty"`
	Name     *string `json:"name,omitempty"`
	Private  *bool   `json:"private,omitempty"`
}

type FNotification struct {
	ID         *int                  `json:"id,omitempty"`
	Repository *FRepository          `json:"repository,omitempty"`
	Subject    *FNotificationSubject `json:"subject,omitempty"`
	Unread     *bool                 `json:"unread,omitempty"`
	UpdatedAt  *FTimestamp           `json:"updated_at,omitempty"`
	URL        *string               `json:"url,omitempty"`
}

type FNotificationSubject struct {
	Title            *string `json:"title,omitempty"`
	URL              *string `json:"url,omitempty"`
	LatestCommentURL *string `json:"latest_comment_url,omitempty"`
	Type             *string `json:"type,omitempty"`
}

type FIssue struct {
	Number     *int             `json:"number,omitempty"`
	Repository *FRepositoryMeta `json:"repository,omitempty"`
	Title      *string          `json:"title,omitempty"`
	CreatedAt  *FTimestamp      `json:"created_at,omitempty"`
	UpdatedAt  *FTimestamp      `json:"updated_at,omitempty"`
	User       *FUser           `json:"user,omitempty"`
	Assignees  []*FUser         `json:"assignees,omitempty"`
	Milestone  *FMilestone      `json:"milestone,omitempty"`
	HTMLURL    *string          `json:"html_url,omitempty"`
	Labels     []*FLabel        `json:"labels,omitempty"`
}

type FIssueCommentEvent struct {
	Action  *string        `json:"action,omitempty"`
	Repo    *FRepository   `json:"repository,omitempty"`
	Issue   *FIssue        `json:"issue,omitempty"`
	Comment *FIssueComment `json:"comment,omitempty"`
	Sender  *FUser         `json:"sender,omitempty"`
}

type FIssueComment struct {
	ID      *int    `json:"id,omitempty"`
	Body    *string `json:"body,omitempty"`
	HTMLURL *string `json:"html_url,omitempty"`
}

type FPullRequestReviewCommentEvent struct {
	Action      *string             `json:"action,omitempty"`
	PullRequest *FPullRequest       `json:"pull_request,omitempty"`
	Repo        *FRepository        `json:"repository,omitempty"`
	Sender      *FUser              `json:"sender,omitempty"`
	Review      *FPullRequestReview `json:"review,omitempty"`
}

type FPullRequestReviewEvent struct {
	Action      *string             `json:"action,omitempty"`
	Review      *FPullRequestReview `json:"review,omitempty"`
	PullRequest *FPullRequest       `json:"pull_request,omitempty"`
	Repo        *FRepository        `json:"repository,omitempty"`
	Sender      *FUser              `json:"sender,omitempty"`
}

type FPullRequestReview struct {
	Type    *string `json:"type,omitempty"`
	Content *string `json:"content,omitempty"`
}

type FPushEvent struct {
	Repo    *FRepository   `json:"repository,omitempty"`
	Sender  *FUser         `json:"sender,omitempty"`
	Forced  *bool          `json:"forced,omitempty"`
	Commits []*FHeadCommit `json:"commits,omitempty"`
	Compare *string        `json:"compare_url,omitempty"`
	Ref     *string        `json:"ref,omitempty"`
}

type FHeadCommit struct {
	ID        *string        `json:"id,omitempty"`
	URL       *string        `json:"url,omitempty"`
	Message   *string        `json:"message,omitempty"`
	Author    *FCommitAuthor `json:"author,omitempty"`
	Committer *FCommitAuthor `json:"committer,omitempty"`
}

type FCommitAuthor struct {
	Date  *FTimestamp `json:"date,omitempty"`
	Name  *string     `json:"name,omitempty"`
	Email *string     `json:"email,omitempty"`
	Login *string     `json:"username,omitempty"`
}

func (p *FPullRequestReviewEvent) GetReview() *FPullRequestReview {
	if p == nil {
		return nil
	}
	return p.Review
}

func (p *FPullRequestReview) GetType() string {
	if p == nil || p.Type == nil {
		return ""
	}
	return *p.Type
}

func (p *FPullRequestReview) GetContent() string {
	if p == nil || p.Content == nil {
		return ""
	}
	return *p.Content
}

type FPullRequest struct {
	ID                      *int      `json:"id,omitempty"`
	Labels                  []*FLabel `json:"labels,omitempty"`
	User                    *FUser    `json:"user,omitempty"`
	Number                  *int      `json:"number,omitempty"`
	Draft                   *bool     `json:"draft,omitempty"`
	Merged                  *bool     `json:"merged,omitempty"`
	Title                   *string   `json:"title,omitempty"`
	HTMLURL                 *string   `json:"html_url,omitempty"`
	Assignee                *FUser    `json:"assignee,omitempty"`
	Assignees               []*FUser  `json:"assignees,omitempty"`
	Body                    *string   `json:"body,omitempty"`
	RequestedReviewers      []*FUser  `json:"requested_reviewers,omitempty"`
	RequestedReviewersTeams []*FTeam  `json:"requested_reviewers_teams,omitempty"`
}

func (p *FPullRequestEvent) GetPullRequest() *FPullRequest {
	if p == nil {
		return nil
	}
	return p.PullRequest
}

func (p *FPullRequest) GetMerged() bool {
	if p == nil || p.Merged == nil {
		return false
	}
	return *p.Merged
}

type FPullRequestEvent struct {
	Action            *string       `json:"action,omitempty"`
	Assignee          *FUser        `json:"assignee,omitempty"`
	Number            *int          `json:"number,omitempty"`
	PullRequest       *FPullRequest `json:"pull_request,omitempty"`
	RequestedReviewer *FUser        `json:"requested_reviewer,omitempty"`
	Repo              *FRepository  `json:"repository,omitempty"`
	Sender            *FUser        `json:"sender,omitempty"`
	Label             *FLabel       `json:"label,omitempty"`
}

func (p *FPullRequestEvent) GetAction() string {
	if p == nil || p.Action == nil {
		return ""
	}
	return *p.Action
}

type FTimestamp struct {
	time.Time
}

type FUser struct {
	Login   *string `json:"login,omitempty"`
	HTMLURL *string `json:"html_url,omitempty"`
}

type FMilestone struct {
	Title *string `json:"title,omitempty"`
}

type FLabel struct {
	Name  *string `json:"name,omitempty"`
	Color *string `json:"color,omitempty"`
}

type FTaskStep = github.TaskStep

type FTeam struct {
	ID   *int64  `json:"id,omitempty"`
	Name *string `json:"name,omitempty"`
}

func (p *Plugin) writeJSON(w http.ResponseWriter, v interface{}) {
	b, err := json.Marshal(v)
	if err != nil {
		p.client.Log.Warn("Failed to marshal JSON response", "error", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	_, err = w.Write(b)
	if err != nil {
		p.client.Log.Warn("Failed to write JSON response", "error", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (p *Plugin) writeAPIError(w http.ResponseWriter, apiErr *APIErrorResponse) {
	b, err := json.Marshal(apiErr)
	if err != nil {
		p.client.Log.Warn("Failed to marshal API error", "error", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(apiErr.StatusCode)

	_, err = w.Write(b)
	if err != nil {
		p.client.Log.Warn("Failed to write JSON response", "error", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (p *Plugin) initializeAPI() {
	p.router = mux.NewRouter()
	p.router.Use(p.withRecovery)

	oauthRouter := p.router.PathPrefix("/oauth").Subrouter()
	apiRouter := p.router.PathPrefix("/api/v1").Subrouter()
	apiRouter.Use(p.checkConfigured)

	p.router.HandleFunc("/webhook", p.handleWebhook).Methods(http.MethodPost)

	oauthRouter.HandleFunc("/connect", p.checkAuth(p.attachContext(p.connectUserToForgejo), ResponseTypePlain)).Methods(http.MethodGet)
	oauthRouter.HandleFunc("/complete", p.checkAuth(p.attachContext(p.completeConnectUserToForgejo), ResponseTypePlain)).Methods(http.MethodGet)

	apiRouter.HandleFunc("/connected", p.attachContext(p.getConnected)).Methods(http.MethodGet)

	apiRouter.HandleFunc("/user", p.checkAuth(p.attachContext(p.getForgejoUser), ResponseTypeJSON)).Methods(http.MethodPost)
	apiRouter.HandleFunc("/todo", p.checkAuth(p.attachUserContext(p.postToDo), ResponseTypeJSON)).Methods(http.MethodPost)
	apiRouter.HandleFunc("/prsdetails", p.checkAuth(p.attachUserContext(p.getPrsDetails), ResponseTypePlain)).Methods(http.MethodPost)
	apiRouter.HandleFunc("/searchissues", p.checkAuth(p.attachUserContext(p.searchIssues), ResponseTypePlain)).Methods(http.MethodGet)
	apiRouter.HandleFunc("/createissue", p.checkAuth(p.attachUserContext(p.createIssue), ResponseTypePlain)).Methods(http.MethodPost)
	apiRouter.HandleFunc("/createissuecomment", p.checkAuth(p.attachUserContext(p.createIssueComment), ResponseTypePlain)).Methods(http.MethodPost)
	apiRouter.HandleFunc("/mentions", p.checkAuth(p.attachUserContext(p.getMentions), ResponseTypePlain)).Methods(http.MethodGet)
	apiRouter.HandleFunc("/labels", p.checkAuth(p.attachUserContext(p.getLabels), ResponseTypePlain)).Methods(http.MethodGet)
	apiRouter.HandleFunc("/milestones", p.checkAuth(p.attachUserContext(p.getMilestones), ResponseTypePlain)).Methods(http.MethodGet)
	apiRouter.HandleFunc("/assignees", p.checkAuth(p.attachUserContext(p.getAssignees), ResponseTypePlain)).Methods(http.MethodGet)
	apiRouter.HandleFunc("/repositories", p.checkAuth(p.attachUserContext(p.getRepositories), ResponseTypePlain)).Methods(http.MethodGet)
	apiRouter.HandleFunc("/settings", p.checkAuth(p.attachUserContext(p.updateSettings), ResponseTypePlain)).Methods(http.MethodPost)
	apiRouter.HandleFunc("/issue", p.checkAuth(p.attachUserContext(p.getIssueByNumber), ResponseTypePlain)).Methods(http.MethodGet)
	apiRouter.HandleFunc("/pr", p.checkAuth(p.attachUserContext(p.getPrByNumber), ResponseTypePlain)).Methods(http.MethodGet)
	apiRouter.HandleFunc("/lhs-content", p.checkAuth(p.attachUserContext(p.getSidebarContent), ResponseTypePlain)).Methods(http.MethodGet)

	apiRouter.HandleFunc("/config", checkPluginRequest(p.getConfig)).Methods(http.MethodGet)
	apiRouter.HandleFunc("/token", checkPluginRequest(p.getToken)).Methods(http.MethodGet)
}

func (p *Plugin) withRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if x := recover(); x != nil {
				p.client.Log.Warn("Recovered from a panic",
					"url", r.URL.String(),
					"error", x,
					"stack", string(debug.Stack()))
			}
		}()

		next.ServeHTTP(w, r)
	})
}

func (p *Plugin) checkConfigured(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		config := p.getConfiguration()

		if err := config.IsValid(); err != nil {
			p.client.Log.Error("This plugin is not configured.", "error", err)
			p.writeAPIError(w, &APIErrorResponse{Message: "this plugin is not configured", StatusCode: http.StatusNotImplemented})
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (p *Plugin) checkAuth(handler http.HandlerFunc, responseType ResponseType) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.Header.Get("Mattermost-User-ID")
		if userID == "" {
			switch responseType {
			case ResponseTypeJSON:
				p.writeAPIError(w, &APIErrorResponse{ID: "", Message: "Not authorized.", StatusCode: http.StatusUnauthorized})
			case ResponseTypePlain:
				http.Error(w, "Not authorized", http.StatusUnauthorized)
			default:
				p.client.Log.Debug("Unknown ResponseType detected")
			}
			return
		}

		handler(w, r)
	}
}

func (p *Plugin) createContext(_ http.ResponseWriter, r *http.Request) (*Context, context.CancelFunc) {
	userID := r.Header.Get("Mattermost-User-ID")

	log := logger.New(p.API).With(logger.LogContext{
		"userid": userID,
	})

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)

	context := &Context{
		Ctx:    ctx,
		UserID: userID,
		Log:    log,
	}

	return context, cancel
}

func (p *Plugin) attachContext(handler HTTPHandlerFuncWithContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		context, cancel := p.createContext(w, r)
		defer cancel()

		handler(context, w, r)
	}
}

func (p *Plugin) attachUserContext(handler HTTPHandlerFuncWithUserContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		context, cancel := p.createContext(w, r)
		defer cancel()

		info, apiErr := p.getGitHubUserInfo(context.UserID)
		if apiErr != nil {
			p.writeAPIError(w, apiErr)
			return
		}

		context.Log = context.Log.With(logger.LogContext{
			"forgejo username": info.ForgejoUsername,
		})

		userContext := &UserContext{
			Context: *context,
			GHInfo:  info,
		}

		handler(userContext, w, r)
	}
}

func checkPluginRequest(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// All other plugins are allowed
		pluginID := r.Header.Get("Mattermost-Plugin-ID")
		if pluginID == "" {
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

func (p *Plugin) ServeHTTP(c *plugin.Context, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	p.router.ServeHTTP(w, r)
}

func (p *Plugin) connectUserToForgejo(c *Context, w http.ResponseWriter, r *http.Request) {
	privateAllowed := false
	pValBool, _ := strconv.ParseBool(r.URL.Query().Get("private"))
	if pValBool {
		privateAllowed = true
	}

	conf, err := p.getOAuthConfig()
	if err != nil {
		c.Log.WithError(err).Warnf("Failed to generate OAuthConfig")
		http.Error(w, "error generating OAuthConfig", http.StatusBadRequest)
		return
	}

	state := OAuthState{
		UserID:         c.UserID,
		Token:          model.NewId()[:15],
		PrivateAllowed: privateAllowed,
	}

	_, err = p.store.Set(forgejoOauthKey+state.Token, state, pluginapi.SetExpiry(TokenTTL))
	if err != nil {
		c.Log.WithError(err).Warnf("error occurred while trying to store oauth state into KV store")
		p.writeAPIError(w, &APIErrorResponse{Message: "error saving the oauth state", StatusCode: http.StatusInternalServerError})
		return
	}

	codeURL := conf.AuthCodeURL(state.Token, oauth2.AccessTypeOnline)

	ch := p.oauthBroker.SubscribeOAuthComplete(c.UserID)

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()

		var errorMsg string
		select {
		case err := <-ch:
			if err != nil {
				errorMsg = err.Error()
			}
		case <-ctx.Done():
			errorMsg = "Timed out waiting for OAuth connection. Please check if the SiteURL is correct."
		}

		if errorMsg != "" {
			_, err := p.poster.DMWithAttachments(c.UserID, &model.SlackAttachment{
				Text:  fmt.Sprintf("There was an error connecting to your Forgejo: `%s` Please double check your configuration.", errorMsg),
				Color: string(flow.ColorDanger),
			})
			if err != nil {
				c.Log.WithError(err).Warnf("Failed to DM with cancel information")
			}
		}

		p.oauthBroker.UnsubscribeOAuthComplete(c.UserID, ch)
	}()

	http.Redirect(w, r, codeURL, http.StatusFound)
}

func (p *Plugin) completeConnectUserToForgejo(c *Context, w http.ResponseWriter, r *http.Request) {
	var rErr error
	defer func() {
		p.oauthBroker.publishOAuthComplete(c.UserID, rErr, false)
	}()

	code := r.URL.Query().Get("code")
	if len(code) == 0 {
		p.client.Log.Error("Missing authorization code.")
		p.writeAPIError(w, &APIErrorResponse{Message: "missing authorization code", StatusCode: http.StatusBadRequest})
		return
	}

	stateToken := r.URL.Query().Get("state")

	var state OAuthState
	err := p.store.Get(forgejoOauthKey+stateToken, &state)
	if err != nil {
		c.Log.WithError(err).Warnf("error occurred while trying to get oauth state from KV store")
		p.writeAPIError(w, &APIErrorResponse{Message: "missing stored state", StatusCode: http.StatusBadRequest})
		return
	}

	err = p.store.Delete(forgejoOauthKey + stateToken)
	if err != nil {
		c.Log.WithError(err).Warnf("error occurred while trying to delete oauth state from KV store")
		p.writeAPIError(w, &APIErrorResponse{Message: "error deleting stored state", StatusCode: http.StatusInternalServerError})
		return
	}

	if state.Token != stateToken {
		p.writeAPIError(w, &APIErrorResponse{Message: "invalid state token", StatusCode: http.StatusBadRequest})
		return
	}

	if state.UserID != c.UserID {
		c.Log.Warnf("not authorized, incorrect user")
		p.writeAPIError(w, &APIErrorResponse{Message: "unauthorized user", StatusCode: http.StatusUnauthorized})
		return
	}

	conf, err := p.getOAuthConfig()
	if err != nil {
		c.Log.WithError(err).Warnf("Failed to generate OAuthConfig")
		http.Error(w, "error generating OAuthConfig", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), oauthCompleteTimeout)
	defer cancel()

	tok, err := conf.Exchange(ctx, code)
	if err != nil {
		c.Log.WithError(err).Warnf("Failed to exchange oauth code into token")
		p.writeAPIError(w, &APIErrorResponse{Message: "failed to exchange oauth code into token", StatusCode: http.StatusInternalServerError})
		return
	}

	githubClient := p.githubConnectToken(*tok)
	gitUser, _, err := githubClient.Users.Get(ctx, "")
	if err != nil {
		c.Log.WithError(err).Warnf("Failed to get authenticated Forgejo user")
		p.writeAPIError(w, &APIErrorResponse{Message: "failed to get authenticated Forgejo user", StatusCode: http.StatusInternalServerError})
		return
	}

	// track the successful connection
	p.TrackUserEvent("account_connected", c.UserID, nil)

	userInfo := &ForgejoUserInfo{
		UserID:          state.UserID,
		Token:           tok,
		ForgejoUsername: gitUser.GetLogin(),
		LastToDoPostAt:  model.GetMillis(),
		Settings: &UserSettings{
			SidebarButtons: settingButtonsTeam,
			DailyReminder:  true,
			Notifications:  true,
		},
		AllowedPrivateRepos: state.PrivateAllowed,
	}

	if err = p.storeGitHubUserInfo(userInfo); err != nil {
		c.Log.WithError(err).Warnf("Failed to store Forgejo user info")
		p.writeAPIError(w, &APIErrorResponse{Message: "unable to connect user to Forgejo", StatusCode: http.StatusInternalServerError})
		return
	}

	if err = p.storeGitHubToUserIDMapping(gitUser.GetLogin(), state.UserID); err != nil {
		c.Log.WithError(err).Warnf("Failed to store Forgejo user info mapping")
	}

	flowClone := p.flowManager.setupFlow.ForUser(c.UserID)

	stepName, err := flowClone.GetCurrentStep()
	if err != nil {
		c.Log.WithError(err).Warnf("Failed to get current step")
	}

	if stepName == stepOAuthConnect {
		err = flowClone.Go(stepWebhookQuestion)
		if err != nil {
			c.Log.WithError(err).Warnf("Failed go to next step")
		}
	} else {
		// Only post introduction message if no setup wizard is running

		var commandHelp string
		commandHelp, err = renderTemplate("helpText", p.getConfiguration())
		if err != nil {
			c.Log.WithError(err).Warnf("Failed to render help template")
		}

		message := fmt.Sprintf("#### Welcome to the Mattermost Forgejo Plugin!\n"+
			"You've connected your Mattermost account to [%s](%s) on Forgejo. Read about the features of this plugin below:\n\n"+
			"##### Daily Reminders\n"+
			"The first time you log in each day, you'll get a post right here letting you know what messages you need to read and what pull requests are awaiting your review.\n"+
			"Turn off reminders with `/forgejo settings reminders off`.\n\n"+
			"##### Notifications\n"+
			"When someone mentions you, requests your review, comments on or modifies one of your pull requests/issues, or assigns you, you'll get a post here about it.\n"+
			"Turn off notifications with `/forgejo settings notifications off`.\n\n"+
			"##### Sidebar Buttons\n"+
			"Check out the buttons in the left-hand sidebar of Mattermost.\n"+
			"It shows your Open PRs, PRs that are awaiting your review, issues assigned to you, and all your unread messages you have in Forgejo. \n"+
			"* The first button tells you how many pull requests you have submitted.\n"+
			"* The second shows the number of PR that are awaiting your review.\n"+
			"* The third shows the number of PR and issues your are assiged to.\n"+
			"* The fourth tracks the number of unread messages you have.\n"+
			"* The fifth will refresh the numbers.\n\n"+
			"Click on them!\n\n"+
			"##### Slash Commands\n"+
			commandHelp, gitUser.GetLogin(), gitUser.GetHTMLURL())

		p.CreateBotDMPost(state.UserID, message, "custom_git_welcome")
	}

	config := p.getConfiguration()
	orgList := p.configuration.getOrganizations()
	p.client.Frontend.PublishWebSocketEvent(
		wsEventConnect,
		map[string]interface{}{
			"connected":         true,
			"forgejo_username":  userInfo.ForgejoUsername,
			"forgejo_client_id": config.ForgejoOAuthClientID,
			"base_url":          config.BaseURL,
			"organizations":     orgList,
			"configuration":     config.ClientConfiguration(),
		},
		&model.WebsocketBroadcast{UserId: state.UserID},
	)

	html := `
			<!DOCTYPE html>
			<html>
			<head>
			<script>
			window.close();
			</script>
			</head>
			<body>
			<p>Completed connecting to Forgejo. Please close this window.</p>
			</body>
			</html>
			`

	w.Header().Set("Content-Type", "text/html")
	_, err = w.Write([]byte(html))
	if err != nil {
		c.Log.WithError(err).Warnf("Failed to write HTML response")
		p.writeAPIError(w, &APIErrorResponse{Message: "failed to write HTML response", StatusCode: http.StatusInternalServerError})
		return
	}
}

func (p *Plugin) getForgejoUser(c *Context, w http.ResponseWriter, r *http.Request) {
	type GitHubUserRequest struct {
		UserID string `json:"user_id"`
	}

	req := &GitHubUserRequest{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.Log.WithError(err).Warnf("Error decoding ForgejoUserRequest from JSON body")
		p.writeAPIError(w, &APIErrorResponse{ID: "", Message: "Please provide a JSON object.", StatusCode: http.StatusBadRequest})
		return
	}

	if req.UserID == "" {
		p.writeAPIError(w, &APIErrorResponse{ID: "", Message: "Please provide a JSON object with a non-blank user_id field.", StatusCode: http.StatusBadRequest})
		return
	}

	userInfo, apiErr := p.getGitHubUserInfo(req.UserID)
	if apiErr != nil {
		if apiErr.ID == apiErrorIDNotConnected {
			p.writeAPIError(w, &APIErrorResponse{ID: "", Message: "User is not connected to a Forgejo account.", StatusCode: http.StatusNotFound})
		} else {
			p.writeAPIError(w, apiErr)
		}
		return
	}

	if userInfo == nil {
		p.writeAPIError(w, &APIErrorResponse{ID: "", Message: "User is not connected to a Forgejo account.", StatusCode: http.StatusNotFound})
		return
	}

	type GitHubUserResponse struct {
		Username string `json:"username"`
	}

	resp := &GitHubUserResponse{Username: userInfo.ForgejoUsername}
	p.writeJSON(w, resp)
}

func (p *Plugin) getConnected(c *Context, w http.ResponseWriter, r *http.Request) {
	config := p.getConfiguration()

	type ConnectedResponse struct {
		Connected           bool                   `json:"connected"`
		ForgejoUsername     string                 `json:"forgejo_username"`
		ForgejoClientID     string                 `json:"forgejo_client_id"`
		BaseURL             string                 `json:"base_url,omitempty"`
		Organizations       []string               `json:"organizations"`
		UserSettings        *UserSettings          `json:"user_settings"`
		ClientConfiguration map[string]interface{} `json:"configuration"`
	}

	orgList := p.configuration.getOrganizations()
	resp := &ConnectedResponse{
		Connected:           false,
		BaseURL:             config.BaseURL,
		Organizations:       orgList,
		ClientConfiguration: p.getConfiguration().ClientConfiguration(),
	}

	if c.UserID == "" {
		p.writeJSON(w, resp)
		return
	}

	info, err := p.getGitHubUserInfo(c.UserID)
	if err != nil {
		c.Log.WithError(err).Warnf("failed to get Forgejo user info")
		p.writeAPIError(w, &APIErrorResponse{Message: "failed to get Forgejo user info", StatusCode: http.StatusInternalServerError})
		return
	}

	if info == nil || info.Token == nil {
		p.writeJSON(w, resp)
		return
	}

	resp.Connected = true
	resp.ForgejoUsername = info.ForgejoUsername
	resp.ForgejoClientID = config.ForgejoOAuthClientID
	resp.UserSettings = info.Settings

	if info.Settings.DailyReminder && r.URL.Query().Get("reminder") == "true" {
		lastPostAt := info.LastToDoPostAt

		offset, err := strconv.Atoi(r.Header.Get("X-Timezone-Offset"))
		if err != nil {
			c.Log.WithError(err).Warnf("Invalid timezone offset")
			p.writeAPIError(w, &APIErrorResponse{Message: "invalid timezone offset", StatusCode: http.StatusBadRequest})
			return
		}

		timezone := time.FixedZone("local", -60*offset)
		// Post to do message if it's the next day and been more than an hour since the last post
		now := model.GetMillis()
		nt := time.Unix(now/1000, 0).In(timezone)
		lt := time.Unix(lastPostAt/1000, 0).In(timezone)
		if nt.Sub(lt).Hours() >= 1 && (nt.Day() != lt.Day() || nt.Month() != lt.Month() || nt.Year() != lt.Year()) {
			if p.HasUnreads(info) {
				if err := p.PostToDo(info, c.UserID); err != nil {
					c.Log.WithError(err).Warnf("Failed to create Forgejo todo message")
				}
				info.LastToDoPostAt = now
				if err := p.storeGitHubUserInfo(info); err != nil {
					c.Log.WithError(err).Warnf("Failed to store Forgejo info for new user")
				}
			}
		}
	}

	privateRepoStoreKey := info.UserID + forgejoPrivateRepoKey
	if config.EnablePrivateRepo && !info.AllowedPrivateRepos {
		var val []byte
		err := p.store.Get(privateRepoStoreKey, &val)
		if err != nil {
			p.writeAPIError(w, &APIErrorResponse{Message: "Unable to get private repo key value", StatusCode: http.StatusInternalServerError})
			c.Log.WithError(err).Warnf("Unable to get private repo key value")
			return
		}

		// Inform the user once that private repositories enabled
		if val == nil {
			message := "Private repositories have been enabled for this plugin. To be able to use them you must disconnect and reconnect your Forgejo account. To reconnect your account, use the following slash commands: `/forgejo disconnect` followed by %s"
			if config.ConnectToPrivateByDefault {
				p.CreateBotDMPost(info.UserID, fmt.Sprintf(message, "`/forgejo connect`."), "")
			} else {
				p.CreateBotDMPost(info.UserID, fmt.Sprintf(message, "`/forgejo connect private`."), "")
			}
			if _, err := p.store.Set(privateRepoStoreKey, []byte("1")); err != nil {
				p.writeAPIError(w, &APIErrorResponse{Message: "unable to set private repo key value", StatusCode: http.StatusInternalServerError})
				c.Log.WithError(err).Warnf("Unable to set private repo key value")
			}
		}
	}

	p.writeJSON(w, resp)
}

func (p *Plugin) getMentions(c *UserContext, w http.ResponseWriter, r *http.Request) {
	config := p.getConfiguration()
	orgList := config.getOrganizations()
	baseURL := config.getBaseURL()

	forgejoClient := p.forgejoConnect(c.GHInfo)

	var result []*github.Issue
	for _, org := range orgList {
		resultData := getRequestResponse(c, forgejoClient, p.createRequestUrl(baseURL, org, "mentioned"))
		result = fillGhIssue(resultData, baseURL, result)
	}
	p.writeJSON(w, result)
}

func (p *Plugin) getUnreadsData(c *UserContext) []*FilteredNotification {
	config := p.getConfiguration()
	baseURL := config.getBaseURL()

	forgejoClient := p.forgejoConnect(c.GHInfo)
	notifications := makeForgejoRequest[[]FNotification](p, forgejoClient, fmt.Sprintf("%sapi/v1/notifications", baseURL))
	var filteredNotifications []*FilteredNotification

	for _, n := range notifications {
		if p.checkOrg(*n.Repository.Owner.Login) != nil {
			continue
		}

		issueURL := *n.Subject.URL
		issueNumIndex := strings.LastIndex(issueURL, "/")
		issueNum := issueURL[issueNumIndex+1:]
		subjectURL := *n.Subject.URL
		if *n.Subject.LatestCommentURL != "" {
			subjectURL = *n.Subject.LatestCommentURL
		}

		filteredNotifications = append(filteredNotifications, &FilteredNotification{
			FNotification: n,
			HTMLURL:       fixGithubNotificationSubjectURL(subjectURL, issueNum),
		})
	}

	return filteredNotifications
}

func (p *Plugin) getPrsDetails(c *UserContext, w http.ResponseWriter, r *http.Request) {
	githubClient := p.githubConnectUser(c.Context.Ctx, c.GHInfo)

	var prList []*PRDetails
	if err := json.NewDecoder(r.Body).Decode(&prList); err != nil {
		c.Log.WithError(err).Warnf("Error decoding PRDetails JSON body")
		p.writeAPIError(w, &APIErrorResponse{ID: "", Message: "Please provide a JSON object.", StatusCode: http.StatusBadRequest})
		return
	}

	prDetails := make([]*PRDetails, len(prList))
	var wg sync.WaitGroup
	for i, pr := range prList {
		i := i
		pr := pr
		wg.Add(1)
		go func() {
			defer wg.Done()
			prDetail := p.fetchPRDetails(c, githubClient, pr.URL, pr.Number)
			prDetails[i] = prDetail
		}()
	}

	wg.Wait()

	p.writeJSON(w, prDetails)
}

func (p *Plugin) fetchPRDetails(c *UserContext, client *github.Client, prURL string, prNumber int) *PRDetails {
	var status string
	var mergeable bool
	// Initialize to a non-nil slice to simplify JSON handling semantics
	requestedReviewers := []*string{}
	//reviewsList := []*github.PullRequestReview{}

	repoOwner, repoName := getRepoOwnerAndNameFromURL(prURL)

	var wg sync.WaitGroup

	// Fetch reviews
	//TODO: commented cause of bug in request that always return empty data
	//wg.Add(1)
	//go func() {
	//	defer wg.Done()
	//	fetchedReviews, err := fetchReviews(c, client, repoOwner, repoName, prNumber)
	//	if err != nil {
	//		c.Log.WithError(err).Warnf("Failed to fetch reviews for PR details")
	//		return
	//	}
	//	reviewsList = fetchedReviews
	//}()

	// Fetch reviewers and status
	wg.Add(1)
	go func() {
		defer wg.Done()
		prInfo, _, err := client.PullRequests.Get(c.Ctx, repoOwner, repoName, prNumber)
		if err != nil {
			c.Log.WithError(err).Warnf("Failed to fetch PR for PR details")
			return
		}

		mergeable = prInfo.GetMergeable()

		for _, v := range prInfo.RequestedReviewers {
			requestedReviewers = append(requestedReviewers, v.Login)
		}
		statuses, _, err := client.Repositories.GetCombinedStatus(c.Ctx, repoOwner, repoName, prInfo.GetHead().GetSHA(), nil)
		if err != nil {
			c.Log.WithError(err).Warnf("Failed to fetch combined status")
			return
		}
		if *statuses.State == "" {
			status = "pending"
		} else {
			status = *statuses.State
		}
	}()

	wg.Wait()
	return &PRDetails{
		URL:                prURL,
		Number:             prNumber,
		Status:             status,
		Mergeable:          mergeable,
		RequestedReviewers: requestedReviewers,
		Reviews:            []string{},
	}
}

func fetchReviews(c *UserContext, client *github.Client, repoOwner string, repoName string, number int) ([]*github.PullRequestReview, error) {
	reviewsList, _, err := client.PullRequests.ListReviews(c.Ctx, repoOwner, repoName, number, nil)

	if err != nil {
		return []*github.PullRequestReview{}, errors.Wrap(err, "could not list reviews")
	}

	return reviewsList, nil
}

func getRepoOwnerAndNameFromURL(url string) (string, string) {
	splitted := strings.Split(url, "/")
	return splitted[len(splitted)-2], splitted[len(splitted)-1]
}

func (p *Plugin) searchIssues(c *UserContext, w http.ResponseWriter, r *http.Request) {
	config := p.getConfiguration()
	orgList := config.getOrganizations()
	baseURL := config.getBaseURL()

	forgejoClient := p.forgejoConnect(c.GHInfo)

	searchTerm := r.FormValue("term")
	result := []*github.Issue{}
	for _, org := range orgList {
		query := fmt.Sprintf("%sapi/v1/repos/issues/search?owner=%s&q=%s&type=pulls&limit=100", baseURL, org, searchTerm)
		resultData := getRequestResponse(c, forgejoClient, query)
		result = fillGhIssue(resultData, baseURL, result)
	}

	p.writeJSON(w, result)
}

func (p *Plugin) getPermaLink(postID string) (string, error) {
	siteURL, err := getSiteURL(p.client)
	if err != nil {
		return "", err
	}

	redirectURL, err := url.JoinPath(siteURL, "_redirect", "pl", postID)
	if err != nil {
		return "", errors.Wrap(err, "failed to build pluginURL")
	}

	return redirectURL, nil
}

func getFailReason(code int, repo string, username string) string {
	cause := ""
	switch code {
	case http.StatusInternalServerError:
		cause = "Internal server error"
	case http.StatusBadRequest:
		cause = "Bad request"
	case http.StatusNotFound:
		cause = fmt.Sprintf("Sorry, either you don't have access to the repo %s with the user %s or it is no longer available", repo, username)
	case http.StatusUnauthorized:
		cause = fmt.Sprintf("Sorry, your user %s is unauthorized to do this action", username)
	case http.StatusForbidden:
		cause = fmt.Sprintf("Sorry, you don't have enough permissions to comment in the repo %s with the user %s", repo, username)
	default:
		cause = fmt.Sprintf("Unknown status code %d", code)
	}
	return cause
}

func (p *Plugin) createIssueComment(c *UserContext, w http.ResponseWriter, r *http.Request) {
	type CreateIssueCommentRequest struct {
		PostID  string `json:"post_id"`
		Owner   string `json:"owner"`
		Repo    string `json:"repo"`
		Number  int    `json:"number"`
		Comment string `json:"comment"`
	}

	req := &CreateIssueCommentRequest{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.Log.WithError(err).Warnf("Error decoding CreateIssueCommentRequest JSON body")
		p.writeAPIError(w, &APIErrorResponse{ID: "", Message: "Please provide a JSON object.", StatusCode: http.StatusBadRequest})
		return
	}

	if req.PostID == "" {
		p.writeAPIError(w, &APIErrorResponse{ID: "", Message: "Please provide a valid post id", StatusCode: http.StatusBadRequest})
		return
	}

	if req.Owner == "" {
		p.writeAPIError(w, &APIErrorResponse{ID: "", Message: "Please provide a valid repo owner.", StatusCode: http.StatusBadRequest})
		return
	}

	if req.Repo == "" {
		p.writeAPIError(w, &APIErrorResponse{ID: "", Message: "Please provide a valid repo.", StatusCode: http.StatusBadRequest})
		return
	}

	if req.Number == 0 {
		p.writeAPIError(w, &APIErrorResponse{ID: "", Message: "Please provide a valid issue number.", StatusCode: http.StatusBadRequest})
		return
	}

	if req.Comment == "" {
		p.writeAPIError(w, &APIErrorResponse{ID: "", Message: "Please provide a valid non empty comment.", StatusCode: http.StatusBadRequest})
		return
	}

	githubClient := p.githubConnectUser(c.Context.Ctx, c.GHInfo)

	post, err := p.client.Post.GetPost(req.PostID)
	if err != nil {
		p.writeAPIError(w, &APIErrorResponse{ID: "", Message: "failed to load post " + req.PostID, StatusCode: http.StatusInternalServerError})
		return
	}
	if post == nil {
		p.writeAPIError(w, &APIErrorResponse{ID: "", Message: "failed to load post " + req.PostID + ": not found", StatusCode: http.StatusNotFound})
		return
	}

	commentUsername, err := p.getUsername(post.UserId)
	if err != nil {
		p.writeAPIError(w, &APIErrorResponse{ID: "", Message: "failed to get username", StatusCode: http.StatusInternalServerError})
		return
	}

	currentUsername := c.GHInfo.ForgejoUsername
	permalink, err := p.getPermaLink(req.PostID)
	if err != nil {
		p.writeAPIError(w, &APIErrorResponse{ID: "", Message: "failed to generate permalink", StatusCode: http.StatusInternalServerError})
		return
	}
	permalinkMessage := fmt.Sprintf("*@%s attached a* [message](%s) *from %s*\n\n", currentUsername, permalink, commentUsername)

	req.Comment = permalinkMessage + req.Comment
	comment := &github.IssueComment{
		Body: &req.Comment,
	}

	result, rawResponse, err := githubClient.Issues.CreateComment(c.Ctx, req.Owner, req.Repo, req.Number, comment)
	if err != nil {
		statusCode := 500
		if rawResponse != nil {
			statusCode = rawResponse.StatusCode
		}
		p.writeAPIError(w, &APIErrorResponse{ID: "", Message: "failed to create an issue comment: " + getFailReason(statusCode, req.Repo, currentUsername), StatusCode: statusCode})
		return
	}

	rootID := req.PostID
	if post.RootId != "" {
		// the original post was a reply
		rootID = post.RootId
	}

	permalinkReplyMessage := fmt.Sprintf("[Message](%v) attached to Forgejo issue [#%v](%v)", permalink, req.Number, result.GetHTMLURL())
	reply := &model.Post{
		Message:   permalinkReplyMessage,
		ChannelId: post.ChannelId,
		RootId:    rootID,
		UserId:    c.UserID,
	}

	err = p.client.Post.CreatePost(reply)
	if err != nil {
		p.writeAPIError(w, &APIErrorResponse{ID: "", Message: "failed to create notification post " + req.PostID, StatusCode: http.StatusInternalServerError})
		return
	}

	p.writeJSON(w, result)
}

func (p *Plugin) getLHSData(c *UserContext) (reviewResp []*github.Issue, assignmentResp []*github.Issue, openPRResp []*github.Issue, err error) {
	config := p.getConfiguration()
	forgejoClient := p.forgejoConnect(c.GHInfo)
	baseURL := config.getBaseURL()

	orgsList := config.getOrganizations()
	var resultReview, resultAssignee, resultOpenPR []*github.Issue
	for _, org := range orgsList {
		resultReviewData := getRequestResponse(c, forgejoClient, p.createRequestUrl(baseURL, org, "review_requested"))
		resultAssigneeData := getRequestResponse(c, forgejoClient, p.createRequestUrl(baseURL, org, "assigned"))
		resultOpenPRData := getRequestResponse(c, forgejoClient, p.createRequestUrl(baseURL, org, "created"))

		resultReview = fillGhIssue(resultReviewData, baseURL, resultReview)
		resultAssignee = fillGhIssue(resultAssigneeData, baseURL, resultAssignee)
		resultOpenPR = fillGhIssue(resultOpenPRData, baseURL, resultOpenPR)
	}
	return resultReview, resultAssignee, resultOpenPR, nil
}

func fillGhIssue(resultReviewData []FIssue, baseURL string, resultIssues []*github.Issue) []*github.Issue {
	for _, issue := range resultReviewData {
		labels := getGithubLabels(issue.Labels)
		reviewGithubIssue := newGithubIssue(issue, labels, baseURL)
		resultIssues = append(resultIssues, reviewGithubIssue)
	}
	return resultIssues
}

func getRequestResponse(c *UserContext, forgejoClient *http.Client, requestURL string) []FIssue {
	response, err := forgejoClient.Get(requestURL)
	if err != nil {
		c.Log.WithError(err).Warnf("Failed Forgejo issues request")
	}

	var result []FIssue
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		c.Log.WithError(err).Warnf("Error decoding FIssue - '%s' JSON body", requestURL)
		return nil
	}
	return result
}

func (p *Plugin) createRequestUrl(baseUrl string, org string, filter string) string {
	return fmt.Sprintf("%sapi/v1/repos/issues/search?owner=%s&%s=true&type=pulls&state=open&limit=100", baseUrl, org, filter)
}

func getGithubLabels(labels []*FLabel) []*github.Label {
	var githubLabels []*github.Label
	for _, label := range labels {
		githubLabels = append(githubLabels, &github.Label{
			Color: label.Color,
			Name:  label.Name,
		})
	}
	return githubLabels
}

func newGithubIssue(issue FIssue, labels []*github.Label, baseURL string) *github.Issue {
	var name = *issue.Repository.FullName
	repoURL := baseURL + name
	createdAtTime := github.Timestamp{Time: issue.CreatedAt.Time}
	updatedAtTime := github.Timestamp{Time: issue.UpdatedAt.Time}
	var milestoneTitle string
	if issue.Milestone == nil {
		milestoneTitle = ""
	} else {
		milestoneTitle = *issue.Milestone.Title
	}

	return &github.Issue{
		Number:        issue.Number,
		RepositoryURL: &repoURL,
		Title:         issue.Title,
		CreatedAt:     &createdAtTime,
		UpdatedAt:     &updatedAtTime,
		User: &github.User{
			Login: issue.User.Login,
		},
		Milestone: &github.Milestone{
			Title: &milestoneTitle,
		},
		HTMLURL: issue.HTMLURL,
		Labels:  labels,
	}
}

func (p *Plugin) getSidebarData(c *UserContext) (*SidebarContent, error) {
	reviewResp, assignmentResp, openPRResp, err := p.getLHSData(c)
	if err != nil {
		return nil, err
	}

	return &SidebarContent{
		PRs:         openPRResp,
		Assignments: assignmentResp,
		Reviews:     reviewResp,
		Unreads:     p.getUnreadsData(c),
	}, nil
}

func (p *Plugin) getSidebarContent(c *UserContext, w http.ResponseWriter, r *http.Request) {
	sidebarContent, err := p.getSidebarData(c)
	if err != nil {
		c.Log.WithError(err).Warnf("Failed to search for the sidebar data")
		p.writeAPIError(w, &APIErrorResponse{Message: "failed to search for the sidebar data", StatusCode: http.StatusInternalServerError})
		return
	}

	p.writeJSON(w, sidebarContent)
}

func (p *Plugin) postToDo(c *UserContext, w http.ResponseWriter, r *http.Request) {
	text, err := p.GetToDo(c.GHInfo)
	if err != nil {
		c.Log.WithError(err).Warnf("Failed to get Todos")
		p.writeAPIError(w, &APIErrorResponse{ID: "", Message: "Encountered an error getting the to do items.", StatusCode: http.StatusUnauthorized})
		return
	}

	p.CreateBotDMPost(c.UserID, text, "custom_git_todo")

	resp := struct {
		Status string
	}{"OK"}

	p.writeJSON(w, resp)
}

func (p *Plugin) updateSettings(c *UserContext, w http.ResponseWriter, r *http.Request) {
	var settings *UserSettings
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		c.Log.WithError(err).Warnf("Error decoding settings from JSON body")
		p.writeAPIError(w, &APIErrorResponse{Message: "invalid request body", StatusCode: http.StatusBadRequest})
		return
	}

	if settings == nil {
		p.client.Log.Error("Invalid request body.")
		p.writeAPIError(w, &APIErrorResponse{Message: "invalid request body", StatusCode: http.StatusBadRequest})
		return
	}

	info := c.GHInfo
	info.Settings = settings

	if err := p.storeGitHubUserInfo(info); err != nil {
		c.Log.WithError(err).Warnf("Failed to store Forgejo user info")
		p.writeAPIError(w, &APIErrorResponse{Message: "error occurred while updating settings", StatusCode: http.StatusInternalServerError})
		return
	}

	p.writeJSON(w, info.Settings)
}

func (p *Plugin) getIssueByNumber(c *UserContext, w http.ResponseWriter, r *http.Request) {
	owner := r.FormValue("owner")
	repo := r.FormValue("repo")
	number := r.FormValue("number")
	numberInt, err := strconv.Atoi(number)
	if err != nil {
		p.writeAPIError(w, &APIErrorResponse{Message: "Invalid param 'number'.", StatusCode: http.StatusBadRequest})
		return
	}

	githubClient := p.githubConnectUser(c.Context.Ctx, c.GHInfo)

	result, _, err := githubClient.Issues.Get(c.Ctx, owner, repo, numberInt)
	if err != nil {
		// If the issue is not found, it's probably behind a private repo.
		// Return an empty repose in this case.
		var gerr *github.ErrorResponse
		if errors.As(err, &gerr) && gerr.Response.StatusCode == http.StatusNotFound {
			c.Log.WithError(err).With(logger.LogContext{
				"owner":  owner,
				"repo":   repo,
				"number": numberInt,
			}).Debugf("Issue  not found")
			p.writeJSON(w, nil)
			return
		}

		c.Log.WithError(err).With(logger.LogContext{
			"owner":  owner,
			"repo":   repo,
			"number": numberInt,
		}).Debugf("Could not get issue")
		p.writeAPIError(w, &APIErrorResponse{Message: "Could not get issue", StatusCode: http.StatusInternalServerError})
		return
	}
	if result.Body != nil {
		*result.Body = mdCommentRegex.ReplaceAllString(result.GetBody(), "")
	}
	p.writeJSON(w, result)
}

func (p *Plugin) getPrByNumber(c *UserContext, w http.ResponseWriter, r *http.Request) {
	owner := r.FormValue("owner")
	repo := r.FormValue("repo")
	number := r.FormValue("number")

	numberInt, err := strconv.Atoi(number)
	if err != nil {
		p.writeAPIError(w, &APIErrorResponse{Message: "Invalid param 'number'.", StatusCode: http.StatusBadRequest})
		return
	}

	githubClient := p.githubConnectUser(c.Context.Ctx, c.GHInfo)

	result, _, err := githubClient.PullRequests.Get(c.Ctx, owner, repo, numberInt)
	if err != nil {
		// If the pull request is not found, it's probably behind a private repo.
		// Return an empty repose in this case.
		var gerr *github.ErrorResponse
		if errors.As(err, &gerr) && gerr.Response.StatusCode == http.StatusNotFound {
			c.Log.With(logger.LogContext{
				"owner":  owner,
				"repo":   repo,
				"number": numberInt,
			}).Debugf("Pull request not found")

			p.writeJSON(w, nil)
			return
		}

		c.Log.WithError(err).With(logger.LogContext{
			"owner":  owner,
			"repo":   repo,
			"number": numberInt,
		}).Debugf("Could not get pull request")
		p.writeAPIError(w, &APIErrorResponse{Message: "Could not get pull request", StatusCode: http.StatusInternalServerError})
		return
	}
	if result.Body != nil {
		*result.Body = mdCommentRegex.ReplaceAllString(result.GetBody(), "")
	}
	p.writeJSON(w, result)
}

func (p *Plugin) getLabels(c *UserContext, w http.ResponseWriter, r *http.Request) {
	owner, repo, err := parseRepo(r.URL.Query().Get("repo"))
	if err != nil {
		p.writeAPIError(w, &APIErrorResponse{Message: err.Error(), StatusCode: http.StatusBadRequest})
		return
	}

	githubClient := p.githubConnectUser(c.Context.Ctx, c.GHInfo)
	var allLabels []*github.Label
	opt := github.ListOptions{PerPage: 50}

	for {
		labels, resp, err := githubClient.Issues.ListLabels(c.Ctx, owner, repo, &opt)
		if err != nil {
			c.Log.WithError(err).Warnf("Failed to list labels")
			p.writeAPIError(w, &APIErrorResponse{Message: "Failed to fetch labels", StatusCode: http.StatusInternalServerError})
			return
		}
		allLabels = append(allLabels, labels...)
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	p.writeJSON(w, allLabels)
}

func (p *Plugin) getAssignees(c *UserContext, w http.ResponseWriter, r *http.Request) {
	owner, repo, err := parseRepo(r.URL.Query().Get("repo"))
	if err != nil {
		p.writeAPIError(w, &APIErrorResponse{Message: err.Error(), StatusCode: http.StatusBadRequest})
		return
	}

	githubClient := p.githubConnectUser(c.Context.Ctx, c.GHInfo)
	var allAssignees []*github.User
	opt := github.ListOptions{PerPage: 50}

	for {
		assignees, resp, err := githubClient.Issues.ListAssignees(c.Ctx, owner, repo, &opt)
		if err != nil {
			c.Log.WithError(err).Warnf("Failed to list assignees")
			p.writeAPIError(w, &APIErrorResponse{Message: "Failed to fetch assignees", StatusCode: http.StatusInternalServerError})
			return
		}
		allAssignees = append(allAssignees, assignees...)
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	p.writeJSON(w, allAssignees)
}

func (p *Plugin) getMilestones(c *UserContext, w http.ResponseWriter, r *http.Request) {
	owner, repo, err := parseRepo(r.URL.Query().Get("repo"))
	if err != nil {
		p.writeAPIError(w, &APIErrorResponse{Message: err.Error(), StatusCode: http.StatusBadRequest})
		return
	}

	githubClient := p.githubConnectUser(c.Context.Ctx, c.GHInfo)
	var allMilestones []*github.Milestone
	opt := github.ListOptions{PerPage: 50}

	for {
		milestones, resp, err := githubClient.Issues.ListMilestones(c.Ctx, owner, repo, &github.MilestoneListOptions{ListOptions: opt})
		if err != nil {
			c.Log.WithError(err).Warnf("Failed to list milestones")
			p.writeAPIError(w, &APIErrorResponse{Message: "Failed to fetch milestones", StatusCode: http.StatusInternalServerError})
			return
		}
		allMilestones = append(allMilestones, milestones...)
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	p.writeJSON(w, allMilestones)
}

func getRepositoryList(c context.Context, userName string, githubClient *github.Client, opt github.ListOptions) ([]*github.Repository, error) {
	var allRepos []*github.Repository
	for {
		repos, resp, err := githubClient.Repositories.List(c, userName, &github.RepositoryListOptions{ListOptions: opt})
		if err != nil {
			return nil, err
		}

		allRepos = append(allRepos, repos...)
		if resp.NextPage == 0 {
			break
		}

		opt.Page = resp.NextPage
	}

	return allRepos, nil
}

func getRepositoryListByOrg(c context.Context, org string, githubClient *github.Client, opt github.ListOptions) ([]*github.Repository, int, error) {
	var allRepos []*github.Repository
	for {
		repos, resp, err := githubClient.Repositories.ListByOrg(c, org, &github.RepositoryListByOrgOptions{Sort: "full_name", ListOptions: opt})
		if err != nil {
			return nil, resp.StatusCode, err
		}

		allRepos = append(allRepos, repos...)
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	return allRepos, http.StatusOK, nil
}

func (p *Plugin) getRepositories(c *UserContext, w http.ResponseWriter, r *http.Request) {
	githubClient := p.githubConnectUser(c.Context.Ctx, c.GHInfo)
	org := p.getConfiguration().ForgejoOrg

	var allRepos []*github.Repository
	var err error

	opt := github.ListOptions{PerPage: 50}

	if org == "" {
		allRepos, err = getRepositoryList(c.Ctx, "", githubClient, opt)
		if err != nil {
			c.Log.WithError(err).Warnf("Failed to list repositories")
			p.writeAPIError(w, &APIErrorResponse{Message: "Failed to fetch repositories", StatusCode: http.StatusInternalServerError})
			return
		}
	} else {
		orgsList := p.configuration.getOrganizations()
		for _, org := range orgsList {
			orgRepos, statusCode, err := getRepositoryListByOrg(c.Ctx, org, githubClient, opt)
			if err != nil {
				if statusCode == http.StatusNotFound {
					orgRepos, err = getRepositoryList(c.Ctx, org, githubClient, opt)
					if err != nil {
						c.Log.WithError(err).Warnf("Failed to list repositories", "Organization", org)
						p.writeAPIError(w, &APIErrorResponse{Message: "Failed to fetch repositories", StatusCode: http.StatusInternalServerError})
						return
					}
				} else {
					c.Log.WithError(err).Warnf("Failed to list repositories", "Organization", org)
					p.writeAPIError(w, &APIErrorResponse{Message: "Failed to fetch repositories", StatusCode: http.StatusInternalServerError})
					return
				}
			}

			if len(orgRepos) > 0 {
				allRepos = append(allRepos, orgRepos...)
			}
		}
	}

	// Only send down fields to client that are needed
	type RepositoryResponse struct {
		Name        string          `json:"name,omitempty"`
		FullName    string          `json:"full_name,omitempty"`
		Permissions map[string]bool `json:"permissions,omitempty"`
	}

	resp := make([]RepositoryResponse, len(allRepos))
	for i, r := range allRepos {
		resp[i].Name = r.GetName()
		resp[i].FullName = r.GetFullName()
		resp[i].Permissions = r.GetPermissions()
	}

	p.writeJSON(w, resp)
}

func (p *Plugin) createIssue(c *UserContext, w http.ResponseWriter, r *http.Request) {
	type IssueRequest struct {
		Title     string   `json:"title"`
		Body      string   `json:"body"`
		Repo      string   `json:"repo"`
		PostID    string   `json:"post_id"`
		ChannelID string   `json:"channel_id"`
		Labels    []string `json:"labels"`
		Assignees []string `json:"assignees"`
		Milestone int      `json:"milestone"`
	}

	// get data for the issue from the request body and fill IssueRequest object
	issue := &IssueRequest{}

	if err := json.NewDecoder(r.Body).Decode(&issue); err != nil {
		c.Log.WithError(err).Warnf("Error decoding JSON body")
		p.writeAPIError(w, &APIErrorResponse{ID: "", Message: "Please provide a JSON object.", StatusCode: http.StatusBadRequest})
		return
	}

	if issue.Title == "" {
		p.writeAPIError(w, &APIErrorResponse{ID: "", Message: "Please provide a valid issue title.", StatusCode: http.StatusBadRequest})
		return
	}

	if issue.Repo == "" {
		p.writeAPIError(w, &APIErrorResponse{ID: "", Message: "Please provide a valid repo name.", StatusCode: http.StatusBadRequest})
		return
	}

	if issue.PostID == "" && issue.ChannelID == "" {
		p.writeAPIError(w, &APIErrorResponse{ID: "", Message: "Please provide either a postID or a channelID", StatusCode: http.StatusBadRequest})
		return
	}

	mmMessage := ""
	var post *model.Post
	permalink := ""
	if issue.PostID != "" {
		var err error
		post, err = p.client.Post.GetPost(issue.PostID)
		if err != nil {
			p.writeAPIError(w, &APIErrorResponse{ID: "", Message: "failed to load post " + issue.PostID, StatusCode: http.StatusInternalServerError})
			return
		}
		if post == nil {
			p.writeAPIError(w, &APIErrorResponse{ID: "", Message: "failed to load post " + issue.PostID + ": not found", StatusCode: http.StatusNotFound})
			return
		}

		username, err := p.getUsername(post.UserId)
		if err != nil {
			p.writeAPIError(w, &APIErrorResponse{ID: "", Message: "failed to get username", StatusCode: http.StatusInternalServerError})
			return
		}

		permalink, err = p.getPermaLink(issue.PostID)
		if err != nil {
			p.writeAPIError(w, &APIErrorResponse{ID: "", Message: "failed to generate permalink", StatusCode: http.StatusInternalServerError})
			return
		}

		mmMessage = fmt.Sprintf("_Issue created from a [Mattermost message](%v) *by %s*._", permalink, username)
	}

	ghIssue := &github.IssueRequest{
		Title:     &issue.Title,
		Body:      &issue.Body,
		Labels:    &issue.Labels,
		Assignees: &issue.Assignees,
	}

	// submitting the request with an invalid milestone ID results in a 422 error
	// we make sure it's not zero here, because the webapp client might have left this field empty
	if issue.Milestone > 0 {
		ghIssue.Milestone = &issue.Milestone
	}

	if ghIssue.GetBody() != "" && mmMessage != "" {
		mmMessage = "\n\n" + mmMessage
	}
	*ghIssue.Body = ghIssue.GetBody() + mmMessage

	currentUser, err := p.client.User.Get(c.UserID)
	if err != nil {
		p.writeAPIError(w, &APIErrorResponse{ID: "", Message: "failed to load current user", StatusCode: http.StatusInternalServerError})
		return
	}

	splittedRepo := strings.Split(issue.Repo, "/")
	owner := splittedRepo[0]
	repoName := splittedRepo[1]

	githubClient := p.githubConnectUser(c.Context.Ctx, c.GHInfo)
	result, resp, err := githubClient.Issues.Create(c.Ctx, owner, repoName, ghIssue)
	if err != nil {
		if resp != nil && resp.Response.StatusCode == http.StatusGone {
			p.writeAPIError(w, &APIErrorResponse{ID: "", Message: "Issues are disabled on this repository.", StatusCode: http.StatusMethodNotAllowed})
			return
		}

		c.Log.WithError(err).Warnf("Failed to create issue")
		p.writeAPIError(w,
			&APIErrorResponse{
				ID: "",
				Message: "failed to create issue: " + getFailReason(resp.StatusCode,
					issue.Repo,
					currentUser.Username,
				),
				StatusCode: resp.StatusCode,
			})
		return
	}

	rootID := issue.PostID
	channelID := issue.ChannelID
	message := fmt.Sprintf("Created Forgejo issue [#%v](%v)", result.GetNumber(), result.GetHTMLURL())
	if post != nil {
		if post.RootId != "" {
			rootID = post.RootId
		}
		channelID = post.ChannelId
		message += fmt.Sprintf(" from a [message](%s)", permalink)
	}

	reply := &model.Post{
		Message:   message,
		ChannelId: channelID,
		RootId:    rootID,
		UserId:    c.UserID,
	}

	if post != nil {
		err = p.client.Post.CreatePost(reply)
	} else {
		p.client.Post.SendEphemeralPost(c.UserID, reply)
	}
	if err != nil {
		c.Log.WithError(err).Warnf("failed to create notification post")
		p.writeAPIError(w, &APIErrorResponse{ID: "", Message: "failed to create notification post, postID: " + issue.PostID + ", channelID: " + channelID, StatusCode: http.StatusInternalServerError})
		return
	}

	p.writeJSON(w, result)
}

func (p *Plugin) getConfig(w http.ResponseWriter, r *http.Request) {
	config := p.getConfiguration()

	p.writeJSON(w, config)
}

func (p *Plugin) getToken(w http.ResponseWriter, r *http.Request) {
	userID := r.FormValue("userID")
	if userID == "" {
		p.client.Log.Error("UserID not found.")
		p.writeAPIError(w, &APIErrorResponse{Message: "please provide a userID", StatusCode: http.StatusBadRequest})
		return
	}

	info, apiErr := p.getGitHubUserInfo(userID)
	if apiErr != nil {
		p.client.Log.Error("error occurred while getting the forgejo user info", "UserID", userID, "error", apiErr)
		p.writeAPIError(w, &APIErrorResponse{Message: apiErr.Error(), StatusCode: apiErr.StatusCode})
		return
	}

	p.writeJSON(w, info.Token)
}

// parseRepo parses the owner & repository name from the repo query parameter
func parseRepo(repoParam string) (owner, repo string, err error) {
	if repoParam == "" {
		return "", "", errors.New("repository cannot be blank")
	}

	splitted := strings.Split(repoParam, "/")
	if len(splitted) != 2 {
		return "", "", errors.New("invalid repository")
	}

	return splitted[0], splitted[1], nil
}
