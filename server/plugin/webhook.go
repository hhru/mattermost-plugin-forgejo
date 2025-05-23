package plugin

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // GitHub webhooks are signed using sha1 https://developer.github.com/webhooks/.
	"encoding/hex"
	"encoding/json"
	"html"
	"io"
	"log"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/google/go-github/v54/github"
	"github.com/microcosm-cc/bluemonday"

	"github.com/mattermost/mattermost/server/public/model"
)

const (
	actionOpened               = "opened"
	actionMarkedReadyForReview = "ready_for_review"
	actionClosed               = "closed"
	actionReopened             = "reopened"
	actionSubmitted            = "submitted"
	actionLabeled              = "labeled"
	actionAssigned             = "assigned"

	actionReviewed  = "reviewed"
	actionCreated   = "created"
	actionDeleted   = "deleted"
	actionEdited    = "edited"
	actionCompleted = "completed"

	workflowJobFail    = "failure"
	workflowJobSuccess = "success"

	postPropForgejoRepo       = "fg_repo"
	postPropForgejoObjectID   = "fg_object_id"
	postPropForgejoObjectType = "fg_object_type"

	forgejoObjectTypeIssue             = "issue"
	forgejoObjectTypeIssueComment      = "issue_comment"
	forgejoObjectTypePRReviewComment   = "pr_review_comment"
	forgejoObjectTypeDiscussionComment = "discussion_comment"
	forgejoEventHeader                 = "X-Forgejo-Event"
)

var (
	eventTypeMapping = map[string]interface{}{
		"issue_comment":         &FIssueCommentEvent{},
		"pull_request":          &FPullRequestEvent{},
		"pull_request_comment":  &FPullRequestReviewCommentEvent{},
		"pull_request_approved": &FPullRequestReviewEvent{},
		"pull_request_rejected": &FPullRequestReviewEvent{},
		"push":                  &FPushEvent{},
	}
)

// RenderConfig holds various configuration options to be used in a template
// for rendering an event.
type RenderConfig struct {
	Style string
}

// EventWithRenderConfig holds an event along with configuration options for
// rendering.
type EventWithRenderConfig struct {
	Event  interface{}
	Config RenderConfig
	Label  string
}

func verifyWebhookSignature(secret []byte, signature string, body []byte) (bool, error) {
	const signaturePrefix = "sha1="
	const signatureLength = 45

	if len(signature) != signatureLength || !strings.HasPrefix(signature, signaturePrefix) {
		return false, nil
	}

	actual := make([]byte, 20)
	_, err := hex.Decode(actual, []byte(signature[5:]))
	if err != nil {
		return false, err
	}

	sb, err := signBody(secret, body)
	if err != nil {
		return false, err
	}

	return hmac.Equal(sb, actual), nil
}

func signBody(secret, body []byte) ([]byte, error) {
	computed := hmac.New(sha1.New, secret)
	_, err := computed.Write(body)
	if err != nil {
		return nil, err
	}

	return computed.Sum(nil), nil
}

// GetEventWithRenderConfig wraps any forgejo Event into an EventWithRenderConfig
// which also contains per-subscription configuration options.
func GetEventWithRenderConfig(event interface{}, sub *Subscription) *EventWithRenderConfig {
	style := ""
	subscriptionLabel := ""
	if sub != nil {
		style = sub.RenderStyle()
		subscriptionLabel = sub.Label()
	}

	return &EventWithRenderConfig{
		Event: event,
		Config: RenderConfig{
			Style: style,
		},
		Label: subscriptionLabel,
	}
}

// WebhookBroker is a message broker for webhook events.
type WebhookBroker struct {
	sendGitHubPingEvent func(event *github.PingEvent)

	lock     sync.RWMutex // Protects closed and pingSubs
	closed   bool
	pingSubs []chan *github.PingEvent
}

func NewWebhookBroker(sendGitHubPingEvent func(event *github.PingEvent)) *WebhookBroker {
	return &WebhookBroker{
		sendGitHubPingEvent: sendGitHubPingEvent,
	}
}

func (wb *WebhookBroker) SubscribePings() <-chan *github.PingEvent {
	wb.lock.Lock()
	defer wb.lock.Unlock()

	ch := make(chan *github.PingEvent, 1)
	wb.pingSubs = append(wb.pingSubs, ch)

	return ch
}

func (wb *WebhookBroker) UnsubscribePings(ch <-chan *github.PingEvent) {
	wb.lock.Lock()
	defer wb.lock.Unlock()

	for i, sub := range wb.pingSubs {
		if sub == ch {
			wb.pingSubs = append(wb.pingSubs[:i], wb.pingSubs[i+1:]...)
			break
		}
	}
}

func (wb *WebhookBroker) publishPing(event *github.PingEvent, fromCluster bool) {
	wb.lock.Lock()
	defer wb.lock.Unlock()

	if wb.closed {
		return
	}

	for _, sub := range wb.pingSubs {
		// non-blocking send
		select {
		case sub <- event:
		default:
		}
	}

	if !fromCluster {
		wb.sendGitHubPingEvent(event)
	}
}

func (wb *WebhookBroker) Close() {
	wb.lock.Lock()
	defer wb.lock.Unlock()

	if !wb.closed {
		wb.closed = true

		for _, sub := range wb.pingSubs {
			close(sub)
		}
	}
}

func (p *Plugin) handleWebhook(w http.ResponseWriter, r *http.Request) {
	config := p.getConfiguration()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Bad request body", http.StatusBadRequest)
		return
	}

	signature := r.Header.Get("X-Hub-Signature")
	valid, err := verifyWebhookSignature([]byte(config.WebhookSecret), signature, body)
	if err != nil {
		p.client.Log.Warn("Failed to verify webhook signature", "error", err.Error())
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	if !valid {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	forgejoEventHeader := r.Header.Get(forgejoEventHeader)
	eventType, ok := eventTypeMapping[forgejoEventHeader]
	var event interface{}
	if ok {
		event = reflect.New(reflect.TypeOf(eventType).Elem()).Interface()
		r := json.Unmarshal(body, &event)
		err = r
	} else {
		e, r := github.ParseWebHook(forgejoEventHeader, body)
		event = e
		err = r
	}

	if err != nil {
		p.client.Log.Debug("Forgejo webhook content type should be set to \"application/json\"", "error", err.Error())
		http.Error(w, "wrong mime-type. should be \"application/json\"", http.StatusBadRequest)
		return
	}

	if config.EnableWebhookEventLogging {
		bodyByte, err := json.Marshal(event)
		if err != nil {
			p.client.Log.Warn("Error while Marshal Webhook Request", "error", err.Error())
			http.Error(w, "Error while Marshal Webhook Request", http.StatusBadRequest)
			return
		}
		p.client.Log.Debug("Webhook Event Log", "event", string(bodyByte))
	}

	var repo *github.Repository
	var handler func()

	switch event := event.(type) {
	case *github.PingEvent:
		handler = func() {
			p.webhookBroker.publishPing(event, false)
		}
	case *FPullRequestEvent:
		repo = &github.Repository{
			Private: event.Repo.Private,
		}
		handler = func() {
			p.postPullRequestEvent(event)
			p.handlePullRequestNotification(event)
			p.handlePRDescriptionMentionNotification(event)
		}
	case *github.IssuesEvent:
		repo = event.GetRepo()
		handler = func() {
			p.postIssueEvent(event)
			p.handleIssueNotification(event)
		}
	case *FIssueCommentEvent:
		repo = &github.Repository{
			Private: event.Repo.Private,
		}
		handler = func() {
			p.postIssueCommentEvent(event)
			p.handleCommentMentionNotification(event)
			p.handleCommentAuthorNotification(event)
			p.handleCommentAssigneeNotification(event)
			p.handleCommentReplyNotification(event)
		}
	case *FPullRequestReviewEvent:
		repo = &github.Repository{
			Private: event.Repo.Private,
		}
		handler = func() {
			p.postPullRequestReviewEvent(event)
			p.handlePullRequestReviewNotification(event)
		}
	case *FPullRequestReviewCommentEvent:
		repo = &github.Repository{
			Private: event.Repo.Private,
		}
		handler = func() {
			p.postPullRequestReviewCommentEvent(event)
		}
	case *FPushEvent:
		repo = &github.Repository{
			Private:  event.Repo.Private,
			FullName: event.Repo.Name,
		}
		handler = func() {
			p.postPushEvent(event)
		}
	case *github.CreateEvent:
		repo = event.GetRepo()
		handler = func() {
			p.postCreateEvent(event)
		}
	case *github.DeleteEvent:
		repo = event.GetRepo()
		handler = func() {
			p.postDeleteEvent(event)
		}
	case *github.StarEvent:
		repo = event.GetRepo()
		handler = func() {
			p.postStarEvent(event)
		}
	case *github.WorkflowJobEvent:
		repo = event.GetRepo()
		handler = func() {
			p.postWorkflowJobEvent(event)
		}
	case *github.ReleaseEvent:
		repo = event.GetRepo()
		handler = func() {
			p.postReleaseEvent(event)
		}
	case *github.DiscussionEvent:
		repo = event.GetRepo()
		handler = func() {
			p.postDiscussionEvent(event)
		}
	case *github.DiscussionCommentEvent:
		repo = event.GetRepo()
		handler = func() {
			p.postDiscussionCommentEvent(event)
		}
	}

	if handler == nil {
		return
	}

	if repo != nil && repo.GetPrivate() && !config.EnablePrivateRepo {
		return
	}

	handler()
}

func (p *Plugin) permissionToRepo(userID string, ownerAndRepo string) bool {
	if userID == "" {
		return false
	}

	config := p.getConfiguration()

	owner, repo := parseOwnerAndRepo(ownerAndRepo, config.getBaseURL())

	if owner == "" {
		return false
	}

	if err := p.checkOrg(owner); err != nil {
		return false
	}

	info, apiErr := p.getGitHubUserInfo(userID)
	if apiErr != nil {
		return false
	}
	ctx := context.Background()
	githubClient := p.githubConnectUser(ctx, info)

	if result, _, err := githubClient.Repositories.Get(ctx, owner, repo); result == nil || err != nil {
		if err != nil {
			p.client.Log.Warn("Failed fetch repository to check permission", "error", err.Error())
		}
		return false
	}

	return true
}

func (p *Plugin) excludeConfigOrgMember(username string, subscription *Subscription) bool {
	if !subscription.ExcludeOrgMembers() {
		return false
	}

	info, err := p.getGitHubUserInfo(subscription.CreatorID)
	if err != nil {
		p.client.Log.Warn("Failed to exclude org member", "error", err.Message)
		return false
	}

	githubClient := p.githubConnectUser(context.Background(), info)
	organization := p.getConfiguration().ForgejoOrg

	return p.isUserOrganizationMember(githubClient, username, organization)
}

func (p *Plugin) postPullRequestEvent(event *FPullRequestEvent) {
	repo := event.Repo

	subs := p.GetSubscribedChannelsForRepository(*repo.FullName, *repo.Private)
	if len(subs) == 0 {
		return
	}

	action := *event.Action
	switch action {
	case actionOpened,
		actionReopened,
		actionClosed:
	default:
		return
	}

	pr := *event.PullRequest
	isPRInDraftState := *pr.Draft
	//eventLabel := *event.Label.Name
	labels := make([]string, len(pr.Labels))
	for i, v := range pr.Labels {
		labels[i] = *v.Name
	}

	closedPRMessage, err := renderTemplate("closedPR", event)
	if err != nil {
		p.client.Log.Warn("Failed to render template", "error", err.Error())
		return
	}

	for _, sub := range subs {
		if !sub.Pulls() && !sub.PullsMerged() && !sub.PullsCreated() {
			continue
		}

		if sub.PullsMerged() && action != actionClosed && !sub.PullsCreated() {
			continue
		}

		if sub.PullsCreated() && action != actionOpened && !sub.PullsMerged() {
			continue
		}

		if sub.PullsMerged() && sub.PullsCreated() {
			if action != actionClosed && action != actionOpened {
				continue
			}
		}

		if p.excludeConfigOrgMember(*event.Sender.Login, sub) {
			continue
		}

		label := sub.Label()

		contained := false
		for _, v := range labels {
			if v == label {
				contained = true
			}
		}

		if !contained && label != "" {
			continue
		}

		repoName := strings.ToLower(*repo.FullName)
		prNumber := event.PullRequest.Number

		post := p.makeBotPost("", "custom_git_pr")

		post.AddProp(postPropForgejoRepo, repoName)
		post.AddProp(postPropForgejoObjectID, prNumber)
		post.AddProp(postPropForgejoObjectType, forgejoObjectTypeIssue)

		//if action == actionLabeled {
		//	if label != "" && label == eventLabel {
		//		pullRequestLabelledMessage, err := renderTemplate("pullRequestLabelled", event)
		//		if err != nil {
		//			p.client.Log.Warn("Failed to render template", "error", err.Error())
		//			return
		//		}
		//
		//		post.Message = pullRequestLabelledMessage
		//	} else {
		//		continue
		//	}
		//}

		if action == actionOpened {
			prNotificationType := "newPR"
			if isPRInDraftState {
				prNotificationType = "newDraftPR"
			}
			newPRMessage, err := renderTemplate(prNotificationType, GetEventWithRenderConfig(event, sub))
			if err != nil {
				p.client.Log.Warn("Failed to render template", "error", err.Error())
				return
			}

			post.Message = p.sanitizeDescription(newPRMessage)
		}

		if action == actionReopened {
			reopenedPRMessage, err := renderTemplate("reopenedPR", event)
			if err != nil {
				p.client.Log.Warn("Failed to render template", "error", err.Error())
				return
			}

			post.Message = p.sanitizeDescription(reopenedPRMessage)
		}

		//if action == actionMarkedReadyForReview {
		//	markedReadyToReviewPRMessage, err := renderTemplate("markedReadyToReviewPR", GetEventWithRenderConfig(event, sub))
		//	if err != nil {
		//		p.client.Log.Warn("Failed to render template", "error", err.Error())
		//		return
		//	}
		//
		//	post.Message = p.sanitizeDescription(markedReadyToReviewPRMessage)
		//}

		if action == actionClosed {
			post.Message = closedPRMessage
		}

		post.ChannelId = sub.ChannelID
		if err := p.client.Post.CreatePost(post); err != nil {
			p.client.Log.Warn("Error webhook post", "post", post, "error", err.Error())
		}
	}
}

func (p *Plugin) sanitizeDescription(description string) string {
	if strings.Contains(description, "<details>") {
		var policy = bluemonday.StrictPolicy()
		policy.SkipElementsContent("details")
		description = html.UnescapeString(policy.Sanitize(description))
	}
	return strings.TrimSpace(description)
}

func (p *Plugin) handlePRDescriptionMentionNotification(event *FPullRequestEvent) {
	action := *event.Action
	if action != actionOpened {
		return
	}

	body := *event.PullRequest.Body

	mentionedUsernames := parseForgejoUsernamesFromText(body)

	message, err := renderTemplate("pullRequestMentionNotification", event)
	if err != nil {
		p.client.Log.Warn("Failed to render template", "error", err.Error())
		return
	}

	for _, username := range mentionedUsernames {
		// Don't notify user of their own comment
		if username == *event.Sender.Login {
			continue
		}

		// Notifications for pull request authors are handled separately
		if username == *event.PullRequest.User.Login {
			continue
		}

		userID := p.getForgejoToUserIDMapping(username)
		if userID == "" {
			continue
		}

		if *event.Repo.Private && !p.permissionToRepo(userID, *event.Repo.FullName) {
			continue
		}

		channel, err := p.client.Channel.GetDirect(userID, p.BotUserID)
		if err != nil {
			continue
		}

		post := p.makeBotPost(message, "custom_git_mention")
		post.ChannelId = channel.Id

		if err = p.client.Post.CreatePost(post); err != nil {
			p.client.Log.Warn("Error webhook post", "post", post, "error", err.Error())
		}

		p.sendRefreshEvent(userID)
	}
}

func (p *Plugin) postIssueEvent(event *github.IssuesEvent) {
	repo := event.GetRepo()
	issue := event.GetIssue()
	action := event.GetAction()

	// This condition is made to check if the message doesn't get automatically labeled to prevent duplicated issue messages
	timeDiff := time.Until(issue.GetCreatedAt().Time) * -1
	if action == actionLabeled && timeDiff.Seconds() < 4.00 {
		return
	}

	subscribedChannels := p.GetSubscribedChannelsForRepository(repo.GetFullName(), repo.GetPrivate())
	if len(subscribedChannels) == 0 {
		return
	}

	issueTemplate := ""
	switch action {
	case actionOpened:
		issueTemplate = "newIssue"

	case actionClosed:
		issueTemplate = "closedIssue"

	case actionReopened:
		issueTemplate = "reopenedIssue"

	case actionLabeled:
		issueTemplate = "issueLabelled"

	default:
		return
	}

	eventLabel := event.GetLabel().GetName()
	labels := make([]string, len(issue.Labels))
	for i, v := range issue.Labels {
		labels[i] = v.GetName()
	}

	for _, sub := range subscribedChannels {
		if !sub.Issues() && !sub.IssueCreations() {
			continue
		}

		if sub.IssueCreations() && action != actionOpened && action != actionReopened && action != actionLabeled {
			continue
		}

		if p.excludeConfigOrgMember(event.GetSender().GetLogin(), sub) {
			continue
		}

		renderedMessage, err := renderTemplate(issueTemplate, GetEventWithRenderConfig(event, sub))
		if err != nil {
			p.client.Log.Warn("Failed to render template", "error", err.Error())
			return
		}
		renderedMessage = p.sanitizeDescription(renderedMessage)

		post := p.makeBotPost(renderedMessage, "custom_git_issue")

		repoName := strings.ToLower(repo.GetFullName())
		issueNumber := issue.Number

		post.AddProp(postPropForgejoRepo, repoName)
		post.AddProp(postPropForgejoObjectID, issueNumber)
		post.AddProp(postPropForgejoObjectType, forgejoObjectTypeIssue)

		label := sub.Label()

		contained := false
		for _, v := range labels {
			if v == label {
				contained = true
			}
		}

		if !contained && label != "" {
			continue
		}

		if action == actionLabeled {
			if label == "" || label != eventLabel {
				continue
			}
		}

		post.ChannelId = sub.ChannelID
		if err = p.client.Post.CreatePost(post); err != nil {
			p.client.Log.Warn("Error webhook post", "post", post, "error", err.Error())
		}
	}
}

func (p *Plugin) postPushEvent(event *FPushEvent) {
	repo := event.Repo

	subs := p.GetSubscribedChannelsForRepository(*repo.FullName, *repo.Private)

	if len(subs) == 0 {
		return
	}

	commits := event.Commits
	if len(commits) == 0 {
		return
	}

	setShowAuthorInCommitNotification(p.configuration.ShowAuthorInCommitNotification)
	pushedCommitsMessage, err := renderTemplate("pushedCommits", event)
	if err != nil {
		p.client.Log.Warn("Failed to render template", "error", err.Error())
		return
	}

	for _, sub := range subs {
		if !sub.Pushes() {
			continue
		}

		if p.excludeConfigOrgMember(*event.Sender.Login, sub) {
			continue
		}

		post := p.makeBotPost(pushedCommitsMessage, "custom_git_push")

		post.ChannelId = sub.ChannelID
		if err = p.client.Post.CreatePost(post); err != nil {
			p.client.Log.Warn("Error webhook post", "post", post, "error", err.Error())
		}
	}
}

func (p *Plugin) postCreateEvent(event *github.CreateEvent) {
	repo := event.GetRepo()

	subs := p.GetSubscribedChannelsForRepository(repo.GetFullName(), repo.GetPrivate())
	if len(subs) == 0 {
		return
	}

	typ := event.GetRefType()
	if typ != "tag" && typ != "branch" {
		return
	}

	newCreateMessage, err := renderTemplate("newCreateMessage", event)
	if err != nil {
		p.client.Log.Warn("Failed to render template", "error", err.Error())
		return
	}

	for _, sub := range subs {
		if !sub.Creates() {
			continue
		}

		if p.excludeConfigOrgMember(event.GetSender().GetLogin(), sub) {
			continue
		}

		post := p.makeBotPost(newCreateMessage, "custom_git_create")

		post.ChannelId = sub.ChannelID
		if err = p.client.Post.CreatePost(post); err != nil {
			p.client.Log.Warn("Error webhook post", "post", post, "error", err.Error())
		}
	}
}

func (p *Plugin) postDeleteEvent(event *github.DeleteEvent) {
	repo := event.GetRepo()

	subs := p.GetSubscribedChannelsForRepository(repo.GetFullName(), repo.GetPrivate())

	if len(subs) == 0 {
		return
	}

	typ := event.GetRefType()

	if typ != "tag" && typ != "branch" {
		return
	}

	newDeleteMessage, err := renderTemplate("newDeleteMessage", event)
	if err != nil {
		p.client.Log.Warn("Failed to render template", "error", err.Error())
		return
	}

	for _, sub := range subs {
		if !sub.Deletes() {
			continue
		}

		if p.excludeConfigOrgMember(event.GetSender().GetLogin(), sub) {
			continue
		}

		post := p.makeBotPost(newDeleteMessage, "custom_git_delete")
		post.ChannelId = sub.ChannelID
		if err = p.client.Post.CreatePost(post); err != nil {
			p.client.Log.Warn("Error webhook post", "post", post, "error", err.Error())
		}
	}
}

func (p *Plugin) postIssueCommentEvent(event *FIssueCommentEvent) {
	repo := event.Repo

	subs := p.GetSubscribedChannelsForRepository(*repo.FullName, *repo.Private)

	if len(subs) == 0 {
		return
	}

	if *event.Action != actionCreated {
		return
	}

	message, err := renderTemplate("issueComment", event)
	if err != nil {
		p.client.Log.Warn("Failed to render template", "error", err.Error())
		return
	}

	labels := make([]string, len(event.Issue.Labels))
	for i, v := range event.Issue.Labels {
		labels[i] = *v.Name
	}

	for _, sub := range subs {
		if !sub.IssueComments() {
			continue
		}

		if p.excludeConfigOrgMember(*event.Sender.Login, sub) {
			continue
		}

		label := sub.Label()

		contained := false
		for _, v := range labels {
			if v == label {
				contained = true
			}
		}

		if !contained && label != "" {
			continue
		}

		post := p.makeBotPost("", "custom_git_comment")

		repoName := strings.ToLower(*repo.FullName)
		commentID := event.Comment.ID

		post.AddProp(postPropForgejoRepo, repoName)
		post.AddProp(postPropForgejoObjectID, commentID)
		post.AddProp(postPropForgejoObjectType, forgejoObjectTypeIssueComment)

		if *event.Action == actionCreated {
			post.Message = message
		}

		post.ChannelId = sub.ChannelID

		if err = p.client.Post.CreatePost(post); err != nil {
			p.client.Log.Warn("Error webhook post", "post", post, "error", err.Error())
		}
	}
}

func (p *Plugin) senderMutedByReceiver(userID string, sender string) bool {
	var mutedUsernameBytes []byte
	err := p.store.Get(userID+"-muted-users", &mutedUsernameBytes)
	if err != nil {
		p.client.Log.Warn("Failed to get muted users", "userID", userID)
		return false
	}

	mutedUsernames := string(mutedUsernameBytes)
	return strings.Contains(mutedUsernames, sender)
}

func (p *Plugin) postPullRequestReviewEvent(event *FPullRequestReviewEvent) {
	repo := event.Repo

	subs := p.GetSubscribedChannelsForRepository(*repo.FullName, *repo.Private)
	if len(subs) == 0 {
		return
	}

	switch *event.Action {
	case actionCreated:
	case actionReviewed:
	default:
		p.client.Log.Debug("Unhandled action state", "state", *event.Action)
		return
	}

	switch *event.Review.Type {
	case "pull_request_review_approved":
	case "pull_request_review_rejected":
	default:
		p.client.Log.Debug("Unhandled review state", "state", *event.Review.Type)
		return
	}

	newReviewMessage, err := renderTemplate("pullRequestReviewEvent", event)
	if err != nil {
		p.client.Log.Warn("Failed to render template", "error", err.Error())
		return
	}

	labels := make([]string, len(event.PullRequest.Labels))
	for i, v := range event.PullRequest.Labels {
		labels[i] = *v.Name
	}

	for _, sub := range subs {
		if !sub.PullReviews() {
			continue
		}

		if p.excludeConfigOrgMember(*event.Sender.Login, sub) {
			continue
		}

		label := sub.Label()

		contained := false
		for _, v := range labels {
			if v == label {
				contained = true
			}
		}

		if !contained && label != "" {
			continue
		}

		post := p.makeBotPost(newReviewMessage, "custom_git_pull_review")

		post.ChannelId = sub.ChannelID
		if err = p.client.Post.CreatePost(post); err != nil {
			p.client.Log.Warn("Error webhook post", "post", post, "error", err.Error())
		}
	}
}

func (p *Plugin) postPullRequestReviewCommentEvent(event *FPullRequestReviewCommentEvent) {
	repo := *event.Repo

	subs := p.GetSubscribedChannelsForRepository(*repo.FullName, *repo.Private)
	if len(subs) == 0 {
		return
	}

	newReviewMessage, err := renderTemplate("newReviewComment", event)
	if err != nil {
		p.client.Log.Warn("Failed to render template", "error", err.Error())
		return
	}

	labels := make([]string, len(event.PullRequest.Labels))
	for i, v := range event.PullRequest.Labels {
		labels[i] = *v.Name
	}

	for _, sub := range subs {
		if !sub.PullReviews() {
			continue
		}

		if p.excludeConfigOrgMember(*event.Sender.Login, sub) {
			continue
		}

		label := sub.Label()

		contained := false
		for _, v := range labels {
			if v == label {
				contained = true
			}
		}

		if !contained && label != "" {
			continue
		}

		post := p.makeBotPost(newReviewMessage, "custom_git_pr_comment")

		repoName := strings.ToLower(*repo.FullName)
		commentID := *event.PullRequest.ID

		post.AddProp(postPropForgejoRepo, repoName)
		post.AddProp(postPropForgejoObjectID, commentID)
		post.AddProp(postPropForgejoObjectType, forgejoObjectTypePRReviewComment)

		post.ChannelId = sub.ChannelID
		if err = p.client.Post.CreatePost(post); err != nil {
			p.client.Log.Warn("Error webhook post", "post", post, "error", err.Error())
		}
	}
}

func (p *Plugin) handleCommentMentionNotification(event *FIssueCommentEvent) {
	action := *event.Action
	if action == actionEdited || action == actionDeleted {
		return
	}

	body := *event.Comment.Body

	// Try to parse out email footer junk
	if strings.Contains(body, "notifications@forgejo.com") {
		body = strings.Split(body, "\n\nOn")[0]
	}

	mentionedUsernames := parseForgejoUsernamesFromText(body)

	message, err := renderTemplate("commentMentionNotification", event)
	if err != nil {
		p.client.Log.Warn("Failed to render template", "error", err.Error())
		return
	}

	assignees := event.Issue.Assignees

	for _, username := range mentionedUsernames {
		assigneeMentioned := false
		for _, assignee := range assignees {
			if username == *assignee.Login {
				assigneeMentioned = true
				break
			}
		}

		// This has been handled in "handleCommentAssigneeNotification" function
		if assigneeMentioned {
			continue
		}

		// Don't notify user of their own comment
		if username == *event.Sender.Login {
			continue
		}

		// Notifications for issue authors are handled separately
		if username == *event.Issue.User.Login {
			continue
		}

		userID := p.getForgejoToUserIDMapping(username)
		if userID == "" {
			continue
		}

		if *event.Repo.Private && !p.permissionToRepo(userID, *event.Repo.FullName) {
			continue
		}

		channel, err := p.client.Channel.GetDirect(userID, p.BotUserID)
		if err != nil {
			continue
		}

		post := p.makeBotPost(message, "custom_git_mention")

		post.ChannelId = channel.Id
		if err = p.client.Post.CreatePost(post); err != nil {
			p.client.Log.Warn("Error creating mention post", "error", err.Error())
		}

		p.sendRefreshEvent(userID)
	}
}

func (p *Plugin) handleCommentAuthorNotification(event *FIssueCommentEvent) {
	author := *event.Issue.User.Login
	if author == *event.Sender.Login {
		return
	}

	action := *event.Action
	if action == actionEdited || action == actionDeleted {
		return
	}

	authorUserID := p.getForgejoToUserIDMapping(author)
	if authorUserID == "" {
		return
	}

	if *event.Repo.Private && !p.permissionToRepo(authorUserID, *event.Repo.FullName) {
		return
	}

	splitURL := strings.Split(*event.Issue.HTMLURL, "/")
	if len(splitURL) < 2 {
		return
	}

	var templateName string
	switch splitURL[len(splitURL)-2] {
	case "pulls":
		templateName = "commentAuthorPullRequestNotification"
	case "issues":
		templateName = "commentAuthorIssueNotification"
	default:
		p.client.Log.Debug("Unhandled issue type", "type", splitURL[len(splitURL)-2])
		return
	}

	if p.senderMutedByReceiver(authorUserID, *event.Sender.Login) {
		p.client.Log.Debug("Commenter is muted, skipping notification")
		return
	}

	message, err := renderTemplate(templateName, event)
	if err != nil {
		p.client.Log.Warn("Failed to render template", "error", err.Error())
		return
	}

	p.CreateBotDMPost(authorUserID, message, "custom_git_author")
	p.sendRefreshEvent(authorUserID)
}

func (p *Plugin) handleCommentAssigneeNotification(event *FIssueCommentEvent) {
	author := event.Issue.User.Login
	assignees := event.Issue.Assignees
	repoName := event.Repo.FullName

	splitURL := strings.Split(*event.Issue.HTMLURL, "/")
	if len(splitURL) < 2 {
		return
	}

	eventType := splitURL[len(splitURL)-2]
	var templateName string
	switch eventType {
	case "pulls":
		templateName = "commentAssigneePullRequestNotification"
	case "issues":
		templateName = "commentAssigneeIssueNotification"
	default:
		p.client.Log.Debug("Unhandled issue type", "Type", eventType)
		return
	}

	mentionedUsernames := parseForgejoUsernamesFromText(*event.Comment.Body)

	for _, assignee := range assignees {
		usernameMentioned := false
		template := templateName
		for _, username := range mentionedUsernames {
			if username == *assignee.Login {
				usernameMentioned = true
				break
			}
		}

		if usernameMentioned {
			switch eventType {
			case "pulls":
				template = "commentAssigneeSelfMentionPullRequestNotification"
			case "issues":
				template = "commentAssigneeSelfMentionIssueNotification"
			}
		}

		userID := p.getForgejoToUserIDMapping(*assignee.Login)
		if userID == "" {
			continue
		}

		if author == assignee.Login {
			continue
		}
		if event.Sender.Login == assignee.Login {
			continue
		}

		if !p.permissionToRepo(userID, *repoName) {
			continue
		}

		assigneeID := p.getForgejoToUserIDMapping(*assignee.Login)
		if assigneeID == "" {
			continue
		}

		if p.senderMutedByReceiver(assigneeID, *event.Sender.Login) {
			p.client.Log.Debug("Commenter is muted, skipping notification")
			continue
		}

		message, err := renderTemplate(template, event)
		if err != nil {
			p.client.Log.Warn("Failed to render template", "error", err.Error())
			continue
		}
		p.CreateBotDMPost(assigneeID, message, "custom_git_assignee")
		p.sendRefreshEvent(assigneeID)
	}
}

func (p *Plugin) handleCommentReplyNotification(event *FIssueCommentEvent) {
	prID := *event.Issue.Number
	targetCommentID := *event.Comment.ID
	excludeAuthor := *event.Sender.Login
	issueAuthor := *event.Issue.User.Login
	owner := *event.Repo.Owner.Login
	repo := *event.Repo.Name

	participants, _ := p.findThreadParticipants(excludeAuthor, issueAuthor, owner, repo, prID, targetCommentID)
	if participants == nil {
		return
	}

	excludedUsers := make(map[string]struct{})
	excludedUsers[excludeAuthor] = struct{}{}

	if event.Comment.Body != nil && *event.Comment.Body != "" {
		mentionedInTarget := parseForgejoUsernamesFromText(*event.Comment.Body)
		for _, user := range mentionedInTarget {
			excludedUsers[user] = struct{}{}
		}
	}

	message, err := renderTemplate("commentReply", event)
	if err != nil {
		p.client.Log.Warn("Failed to render template", "error", err.Error())
		return
	}
	assignees := event.Issue.Assignees
	for username := range participants {
		assigneeMentioned := false
		for _, assignee := range assignees {
			if username == *assignee.Login {
				assigneeMentioned = true
				break
			}
		}

		// This has been handled in "handleCommentAssigneeNotification" function
		if assigneeMentioned {
			continue
		}

		// Don't notify user of their own comment
		if username == *event.Sender.Login {
			continue
		}

		// Notifications for issue authors are handled separately
		if username == *event.Issue.User.Login {
			continue
		}

		userID := p.getForgejoToUserIDMapping(username)
		if userID == "" {
			continue
		}

		if *event.Repo.Private && !p.permissionToRepo(userID, *event.Repo.FullName) {
			continue
		}

		channel, err := p.client.Channel.GetDirect(userID, p.BotUserID)
		if err != nil {
			continue
		}

		post := p.makeBotPost(message, "custom_git_mention")

		post.ChannelId = channel.Id
		if err = p.client.Post.CreatePost(post); err != nil {
			p.client.Log.Warn("Error creating mention post", "error", err.Error())
		}

		p.sendRefreshEvent(userID)
	}
}

func (p *Plugin) findThreadParticipants(excludeAuthor string, issueAuthor string, owner string, repo string, prID int, targetCommentID int) (map[string]struct{}, bool) {
	authorId := p.getForgejoToUserIDMapping(excludeAuthor)
	ghClient, apiErr := p.GetGitHubClient(context.Background(), authorId)
	if apiErr != nil {
		issueAuthorId := p.getForgejoToUserIDMapping(issueAuthor)
		ghClient, apiErr = p.GetGitHubClient(context.Background(), issueAuthorId)
		if apiErr != nil {
			return nil, true
		}
	}

	// GetReviews fetches all reviews for a pull request
	var allReviews []*github.PullRequestReview
	listReviewsOpts := &github.ListOptions{PerPage: 100}
	for {
		reviews, resp, err := ghClient.PullRequests.ListReviews(context.Background(), owner, repo, prID, listReviewsOpts)
		if err != nil {
			//return nil, fmt.Errorf("failed to list reviews for PR %d: %w", prID, err)
		}
		allReviews = append(allReviews, reviews...)
		if resp.NextPage == 0 {
			break
		}
		listReviewsOpts.Page = resp.NextPage
	}

	var allCommentsInThread []*github.PullRequestComment
	var targetComment *github.PullRequestComment

	found := false
	for _, review := range allReviews {
		if review.ID == nil {
			log.Printf("Warning: skipping review with nil ID in PR %d", prID)
			continue
		}

		// GetReviewComments fetches all comments for a specific review
		var reviewComments []*github.PullRequestComment
		listReviewCommentsOpts := &github.ListOptions{PerPage: 100}
		for {
			comments, resp, err := ghClient.PullRequests.ListReviewComments(context.Background(), owner, repo, prID, *review.ID, listReviewCommentsOpts)
			if err != nil {
				log.Printf("Warning: failed to get comments for review %d in PR %d: %v", *review.ID, prID, err)
				// Decide if this is a fatal error or if we can continue to other reviews
				break // Breaking here for this review, will try next review
			}
			reviewComments = append(reviewComments, comments...)
			if resp.NextPage == 0 {
				break
			}
			listReviewCommentsOpts.Page = resp.NextPage
		}

		// If an error occurred fetching comments for this specific review, we might have partial data or none.
		// The current logic will just move to the next review if the inner loop was broken by an error.
		for _, comment := range reviewComments {
			if comment.ID != nil && *comment.ID == int64(targetCommentID) {
				targetComment = comment
				allCommentsInThread = reviewComments
				found = true
				break
			}
		}
		if found {
			break
		}
	}

	if !found || targetComment == nil {
		return nil, true
		//return nil, fmt.Errorf("comment with ID %d not found in PR %d", targetCommentID, prID)
	}

	participants := make(map[string]struct{})
	for _, comment := range allCommentsInThread {
		if comment.User != nil && comment.User.Login != nil && *comment.User.Login != "" {
			participants[*comment.User.Login] = struct{}{}
		}
	}
	return participants, false
}

func (p *Plugin) handlePullRequestNotification(event *FPullRequestEvent) {
	author := *event.PullRequest.User.Login
	sender := *event.Sender.Login
	repoName := *event.Repo.FullName
	isPrivate := *event.Repo.Private

	requestedReviewer := ""
	requestedUserID := ""
	authorUserID := ""
	assigneeUserID := ""

	switch *event.Action {
	case "review_requested":
		requestedReviewer = *event.RequestedReviewer.Login
		if requestedReviewer == sender {
			return
		}
		requestedUserID = p.getForgejoToUserIDMapping(requestedReviewer)
		if p.ignoreRequestedReview(event, requestedUserID) || isPrivate && !p.permissionToRepo(requestedUserID, repoName) {
			requestedUserID = ""
		}
	case actionClosed:
		if author == sender {
			return
		}
		authorUserID = p.getForgejoToUserIDMapping(author)
		if isPrivate && !p.permissionToRepo(authorUserID, repoName) {
			authorUserID = ""
		}
	case actionReopened:
		if author == sender {
			return
		}
		authorUserID = p.getForgejoToUserIDMapping(author)
		if isPrivate && !p.permissionToRepo(authorUserID, repoName) {
			authorUserID = ""
		}
	case actionAssigned:
		assignee := *event.PullRequest.Assignee.Login
		if assignee == sender {
			return
		}
		assigneeUserID = p.getForgejoToUserIDMapping(assignee)
		if isPrivate && !p.permissionToRepo(assigneeUserID, repoName) {
			assigneeUserID = ""
		}
	default:
		p.client.Log.Debug("Unhandled event action", "action", event.GetAction())
		return
	}

	message, err := renderTemplate("pullRequestNotification", event)
	if err != nil {
		p.client.Log.Warn("Failed to render template", "error", err.Error())
		return
	}

	if len(requestedUserID) > 0 {
		p.CreateBotDMPost(requestedUserID, message, "custom_git_review_request")
		p.sendRefreshEvent(requestedUserID)
	}

	p.postIssueNotification(message, authorUserID, assigneeUserID)
}

func (p *Plugin) ignoreRequestedReview(event *FPullRequestEvent, requestedUserID string) bool {
	if requestedUserID == "" || len(event.PullRequest.RequestedReviewersTeams) == 0 {
		return false
	}
	reviewers := event.PullRequest.RequestedReviewers
	if event.RequestedReviewer != nil && len(reviewers) > 0 {
		requestedReviewer := *event.RequestedReviewer.Login
		for _, prReviewer := range reviewers {
			if *prReviewer.Login == requestedReviewer {
				return false
			}
		}
	}
	userInfo, response := p.getGitHubUserInfo(requestedUserID)
	if response != nil {
		p.client.Log.Warn("Failed to get stored userInfo", "error", response.Error())
		return false
	}
	if userInfo.Settings.DisableTeamNotifications {
		return true
	}
	excludedRepos := userInfo.Settings.ExcludeTeamReviewNotifications
	if len(excludedRepos) == 0 {
		return false
	}
	currentRepo := *event.Repo.FullName
	for _, excludedRepo := range excludedRepos {
		if excludedRepo == currentRepo {
			return true
		}
	}
	return false
}

func (p *Plugin) handleIssueNotification(event *github.IssuesEvent) {
	author := event.GetIssue().GetUser().GetLogin()
	sender := event.GetSender().GetLogin()
	if author == sender {
		return
	}
	repoName := event.GetRepo().GetFullName()
	isPrivate := event.GetRepo().GetPrivate()

	message := ""
	authorUserID := ""
	assigneeUserID := ""

	switch event.GetAction() {
	case actionClosed:
		authorUserID = p.getForgejoToUserIDMapping(author)
		if isPrivate && !p.permissionToRepo(authorUserID, repoName) {
			authorUserID = ""
		}
	case actionReopened:
		authorUserID = p.getForgejoToUserIDMapping(author)
		if isPrivate && !p.permissionToRepo(authorUserID, repoName) {
			authorUserID = ""
		}
	case actionAssigned:
		assignee := event.GetAssignee().GetLogin()
		if assignee == sender {
			return
		}
		assigneeUserID = p.getForgejoToUserIDMapping(assignee)
		if isPrivate && !p.permissionToRepo(assigneeUserID, repoName) {
			assigneeUserID = ""
		}
	default:
		p.client.Log.Debug("Unhandled event action", "action", event.GetAction())
		return
	}

	message, err := renderTemplate("issueNotification", event)
	if err != nil {
		p.client.Log.Warn("Failed to render template", "error", err.Error())
		return
	}

	p.postIssueNotification(message, authorUserID, assigneeUserID)
}

func (p *Plugin) postIssueNotification(message, authorUserID, assigneeUserID string) {
	if len(authorUserID) > 0 {
		p.CreateBotDMPost(authorUserID, message, "custom_git_author")
		p.sendRefreshEvent(authorUserID)
	}

	if len(assigneeUserID) > 0 {
		p.CreateBotDMPost(assigneeUserID, message, "custom_git_assigned")
		p.sendRefreshEvent(assigneeUserID)
	}
}

func (p *Plugin) handlePullRequestReviewNotification(event *FPullRequestReviewEvent) {
	author := *event.PullRequest.User.Login
	if author == *event.Sender.Login {
		return
	}

	//there is no such action in forgejo
	//if *event.Action != actionSubmitted {
	//	return
	//}

	authorUserID := p.getForgejoToUserIDMapping(author)
	if authorUserID == "" {
		return
	}

	if *event.Repo.Private && !p.permissionToRepo(authorUserID, *event.Repo.FullName) {
		return
	}

	message, err := renderTemplate("pullRequestReviewNotification", event)
	if err != nil {
		p.client.Log.Warn("Failed to render template", "error", err.Error())
		return
	}

	p.CreateBotDMPost(authorUserID, message, "custom_git_review")
	p.sendRefreshEvent(authorUserID)
}

func (p *Plugin) postStarEvent(event *github.StarEvent) {
	repo := event.GetRepo()

	subs := p.GetSubscribedChannelsForRepository(repo.GetFullName(), repo.GetPrivate())

	if len(subs) == 0 {
		return
	}

	newStarMessage, err := renderTemplate("newRepoStar", event)
	if err != nil {
		p.client.Log.Warn("Failed to render template", "error", err.Error())
		return
	}

	for _, sub := range subs {
		if !sub.Stars() {
			continue
		}

		if p.excludeConfigOrgMember(event.GetSender().GetLogin(), sub) {
			continue
		}

		post := p.makeBotPost(newStarMessage, "custom_git_star")

		post.ChannelId = sub.ChannelID
		if err = p.client.Post.CreatePost(post); err != nil {
			p.client.Log.Warn("Error webhook post", "post", post, "error", err.Error())
		}
	}
}

func (p *Plugin) postWorkflowJobEvent(event *github.WorkflowJobEvent) {
	if event.GetAction() != actionCompleted {
		return
	}

	// Create a post only when the workflow job is completed and has either failed or succeeded
	if event.GetWorkflowJob().GetConclusion() != workflowJobFail && event.GetWorkflowJob().GetConclusion() != workflowJobSuccess {
		return
	}

	repo := event.GetRepo()
	subs := p.GetSubscribedChannelsForRepository(repo.GetFullName(), repo.GetPrivate())

	if len(subs) == 0 {
		return
	}

	newWorkflowJobMessage, err := renderTemplate("newWorkflowJob", event)
	if err != nil {
		p.client.Log.Warn("Failed to render template", "Error", err.Error())
		return
	}

	for _, sub := range subs {
		if !sub.Workflows() {
			continue
		}

		post := &model.Post{
			UserId:    p.BotUserID,
			Type:      "custom_git_workflow_job",
			Message:   newWorkflowJobMessage,
			ChannelId: sub.ChannelID,
		}

		if err = p.client.Post.CreatePost(post); err != nil {
			p.client.Log.Warn("Error webhook post", "Post", post, "Error", err.Error())
		}
	}
}

func (p *Plugin) makeBotPost(message, postType string) *model.Post {
	return &model.Post{
		UserId:  p.BotUserID,
		Type:    postType,
		Message: message,
	}
}

func (p *Plugin) postReleaseEvent(event *github.ReleaseEvent) {
	if event.GetAction() != actionCreated && event.GetAction() != actionDeleted {
		return
	}

	repo := event.GetRepo()
	subs := p.GetSubscribedChannelsForRepository(repo.GetFullName(), repo.GetPrivate())

	if len(subs) == 0 {
		return
	}

	newReleaseMessage, err := renderTemplate("newReleaseEvent", event)
	if err != nil {
		p.client.Log.Warn("Failed to render template", "Error", err.Error())
		return
	}

	for _, sub := range subs {
		if !sub.Release() {
			continue
		}

		post := &model.Post{
			UserId:    p.BotUserID,
			Type:      "custom_git_release",
			Message:   newReleaseMessage,
			ChannelId: sub.ChannelID,
		}

		if err = p.client.Post.CreatePost(post); err != nil {
			p.client.Log.Warn("Error webhook post", "Post", post, "Error", err.Error())
		}
	}
}

func (p *Plugin) postDiscussionEvent(event *github.DiscussionEvent) {
	repo := event.GetRepo()

	subs := p.GetSubscribedChannelsForRepository(repo.GetFullName(), repo.GetPrivate())
	if len(subs) == 0 {
		return
	}

	newDiscussionMessage, err := renderTemplate("newDiscussion", event)
	if err != nil {
		p.client.Log.Warn("Failed to render template", "error", err.Error())
		return
	}

	for _, sub := range subs {
		if !sub.Discussions() {
			continue
		}

		if p.excludeConfigOrgMember(event.GetSender().GetLogin(), sub) {
			continue
		}

		post := p.makeBotPost(newDiscussionMessage, "custom_git_discussion")

		repoName := strings.ToLower(repo.GetFullName())
		discussionNumber := event.GetDiscussion().GetNumber()

		post.AddProp(postPropForgejoRepo, repoName)
		post.AddProp(postPropForgejoObjectID, discussionNumber)
		post.AddProp(postPropForgejoObjectType, "discussion")
		post.ChannelId = sub.ChannelID
		if err = p.client.Post.CreatePost(post); err != nil {
			p.client.Log.Warn("Error creating discussion notification post", "Post", post, "Error", err.Error())
		}
	}
}

func (p *Plugin) postDiscussionCommentEvent(event *github.DiscussionCommentEvent) {
	repo := event.GetRepo()

	subs := p.GetSubscribedChannelsForRepository(repo.GetFullName(), repo.GetPrivate())
	if len(subs) == 0 {
		return
	}

	if event.GetAction() != actionCreated {
		return
	}

	newDiscussionCommentMessage, err := renderTemplate("newDiscussionComment", event)
	if err != nil {
		p.client.Log.Warn("Failed to render template", "error", err.Error())
		return
	}
	for _, sub := range subs {
		if !sub.DiscussionComments() {
			continue
		}

		if p.excludeConfigOrgMember(event.GetSender().GetLogin(), sub) {
			continue
		}

		post := p.makeBotPost(newDiscussionCommentMessage, "custom_git_dis_comment")

		repoName := strings.ToLower(repo.GetFullName())
		commentID := event.GetComment().GetID()

		post.AddProp(postPropForgejoRepo, repoName)
		post.AddProp(postPropForgejoObjectID, commentID)
		post.AddProp(postPropForgejoObjectType, forgejoObjectTypeDiscussionComment)

		post.ChannelId = sub.ChannelID
		if err = p.client.Post.CreatePost(post); err != nil {
			p.client.Log.Warn("Error creating discussion comment post", "Post", post, "Error", err.Error())
		}
	}
}
