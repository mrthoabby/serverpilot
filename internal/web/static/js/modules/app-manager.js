/* ServerPilot Application Manager vNext */
"use strict";

(function() {
  var root = document.getElementById("panel-app-manager");
  if (!root) return;

  var content = document.getElementById("amContent");
  var dialog = document.getElementById("amDialog");
  var dialogTitle = document.getElementById("amDialogTitle");
  var dialogEyebrow = document.getElementById("amDialogEyebrow");
  var dialogBody = document.getElementById("amDialogBody");
  var dialogFooter = document.getElementById("amDialogFooter");
  var iconRoot = "/static/icons/tabler/";
  var state = {
    loaded: false,
    view: "project",
    currentProjectID: "",
    currentApplicationID: "",
    currentApplicationTab: "overview",
    currentEnvironmentID: "",
    currentReleaseID: "",
    currentDeploymentID: "",
    connection: null,
    repositories: [],
    applications: [],
    projects: [],
    agents: [],
    releases: [],
    applicationFilter: "all",
    projectDraft: null,
    query: ""
  };

  function h(value) { return window.escapeHtml(String(value == null ? "" : value)); }
  function dataOf(response) { return response && Object.prototype.hasOwnProperty.call(response, "data") ? response.data : response; }
  function icon(name, className) { return '<img src="' + iconRoot + h(name) + '.svg" alt=""' + (className ? ' class="' + h(className) + '"' : "") + '>'; }
  function label(value) { return String(value || "idle").replace(/_/g, " ").replace(/\b\w/g, function(c) { return c.toUpperCase(); }); }
  function initials(value) {
    var parts = String(value || "ServerPilot").split(/[-_\s]+/).filter(Boolean);
    return (parts.length > 1 ? parts[0][0] + parts[1][0] : parts[0].slice(0, 2)).toUpperCase();
  }
  function relative(value) {
    if (!value) return "Never";
    var seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
    if (seconds < 60) return seconds + "s ago";
    if (seconds < 3600) return Math.floor(seconds / 60) + "m ago";
    if (seconds < 86400) return Math.floor(seconds / 3600) + "h ago";
    return Math.floor(seconds / 86400) + "d ago";
  }
  function shortDigest(value) {
    if (!value) return "—";
    var digest = String(value);
    return digest.length > 23 ? digest.slice(0, 19) + "…" : digest;
  }
  function statusClass(status) {
    if (["healthy", "ready", "success", "online", "local"].indexOf(status) >= 0) return "am-status-success";
    if (["failed", "timed_out", "offline"].indexOf(status) >= 0) return "am-status-danger";
    if (["waiting_for_image", "queued", "running", "deploying"].indexOf(status) >= 0) return "am-status-info";
    return "am-status-warning";
  }
  function statusBadge(status) { return '<span class="am-status ' + statusClass(status) + '">' + h(label(status)) + '</span>'; }
  function environmentChip(environment) { return '<span class="am-chip am-env-' + h(environment.type) + '">' + h(environment.name) + ' · ' + h(label(environment.type)) + '</span>'; }
  function appTypeLabel(type) { return type === "nextjs" ? "Next.js Frontend" : "REST API"; }
  function appTypeShortLabel(type) { return type === "nextjs" ? "Web" : "API"; }
  function appTypeIcon(type) { return icon(type === "nextjs" ? "world" : "server"); }
  function autoDeployLabel(mode) {
    if (mode === "tag") return "Version tag";
    if (mode === "release") return "Published release";
    return "Manual";
  }
  function repositoryIdentity(repo) {
    var name = h(repo.full_name);
    var link = repo.html_url ? '<a class="am-repository-link" href="' + h(repo.html_url) + '" target="_blank" rel="noopener noreferrer"><span class="am-mono">' + name + '</span>' + icon("external-link") + '</a>' : '<span class="am-mono">' + name + '</span>';
    return '<span class="am-repository-identity">' + link + '<button type="button" class="am-icon-button am-copy-button" data-copy-repository="' + name + '" aria-label="Copy repository name" title="Copy repository name">' + icon("copy") + '</button></span>';
  }
  async function copyText(value) {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(value);
      return;
    }
    var field = document.createElement("textarea");
    field.value = value;
    field.setAttribute("readonly", "");
    field.style.position = "fixed";
    field.style.opacity = "0";
    document.body.appendChild(field);
    field.select();
    var copied = document.execCommand("copy");
    field.remove();
    if (!copied) throw new Error("Repository name could not be copied");
  }
  function button(text, actionName, primary, iconName, attrs) {
    return '<button type="button" class="am-button' + (primary ? " am-button-primary" : "") + '" data-am-action="' + h(actionName) + '"' + (attrs || "") + '>' + (iconName ? icon(iconName) : "") + h(text) + '</button>';
  }
  function pageHeader(title, description, actions, breadcrumb) {
    return '<header class="am-page-header"><div>' + (breadcrumb ? '<div class="am-breadcrumb">' + h(breadcrumb) + '</div>' : "") + '<h1>' + h(title) + '</h1><p>' + h(description || "") + '</p></div><div class="am-actions">' + (actions || "") + '</div></header>';
  }
  function emptyState(title, description, actionName, actionLabel) {
    return '<div class="am-empty"><div><div class="am-empty-symbol">' + icon("package") + '</div><h2>' + h(title) + '</h2><p>' + h(description) + '</p>' + (actionName ? button(actionLabel, actionName, true, "plus") : "") + '</div></div>';
  }
  function nativeViews() {
    return ["amResourcesView", "amPlatformSettingsView", "amTerminalSettingsView"].map(function(id) { return document.getElementById(id); }).filter(Boolean);
  }
  function showDynamicContent() {
    content.hidden = false;
    nativeViews().forEach(function(view) { view.hidden = true; });
  }
  function showNativeView(id) {
    content.hidden = true;
    nativeViews().forEach(function(view) { view.hidden = view.id !== id; });
  }
  function loading() { showDynamicContent(); content.innerHTML = '<div class="am-skeleton" aria-label="Loading"></div>'; }
  function errorState(message) {
    showDynamicContent();
    content.innerHTML = pageHeader("Something went wrong", "Application Manager could not load this view.", button("Retry", "retry", true, "refresh")) + '<div class="am-alert am-alert-danger">' + h(message || "Please retry.") + '</div>';
  }
  function preferredEnvironment(environments) {
    var priority = { production: 1, staging: 2, test: 3 };
    return environments.slice().sort(function(a, b) { return (priority[a.type] || 4) - (priority[b.type] || 4); })[0] || null;
  }

  async function fetchAll(force) {
    if (state.loaded && !force) return;
    var responses = await Promise.all([
      apiFetch("/api/app-manager/github"),
      apiFetch("/api/app-manager/repositories?limit=200"),
      apiFetch("/api/app-manager/applications?assignment=all&limit=200"),
      apiFetch("/api/app-manager/projects?limit=200"),
      apiFetch("/api/app-manager/agents"),
      apiFetch("/api/app-manager/releases?limit=100")
    ]);
    state.connection = dataOf(responses[0]);
    state.repositories = dataOf(responses[1]) || [];
    state.applications = dataOf(responses[2]) || [];
    state.projects = dataOf(responses[3]) || [];
    state.agents = dataOf(responses[4]) || [];
    state.releases = dataOf(responses[5]) || [];
    state.loaded = true;
    if (!state.currentProjectID && state.projects.length) state.currentProjectID = state.projects[0].id;
    updateIdentity();
    renderSelectors();
  }

  function updateIdentity() {
    var handle = state.connection ? state.connection.account_login : "";
    document.getElementById("amAccountName").textContent = "ServerPilot";
    document.getElementById("amAccountHandle").textContent = handle ? "@" + handle : "GitHub not connected";
    document.getElementById("amAccountMonogram").textContent = "SP";
    document.getElementById("amProfileMonogram").textContent = initials(handle || "SP");
    document.getElementById("amProjectCount").textContent = state.projects.length;
    document.getElementById("amApplicationCount").textContent = state.applications.length;
    document.getElementById("amAgentSummary").textContent = state.agents.filter(function(agent) { return agent.status === "online" || agent.status === "local"; }).length + " agents connected";
  }

  function renderSelectors() {
    document.getElementById("amProjectOptions").innerHTML = state.projects.map(function(project) {
      return '<button type="button" class="am-selector-option ' + (project.id === state.currentProjectID ? "active" : "") + '" data-project-id="' + h(project.id) + '"><span>' + h(project.name) + '</span><small>' + h(project.application_count) + ' applications</small></button>';
    }).join("") || '<div class="am-muted" style="padding:10px">No projects yet</div>';
    document.getElementById("amApplicationOptions").innerHTML = state.applications.map(function(app) {
      return '<button type="button" class="am-selector-option ' + (app.id === state.currentApplicationID ? "active" : "") + '" data-application-id="' + h(app.id) + '"><span>' + h(app.name) + '</span><small>' + h(app.repository) + '</small></button>';
    }).join("") || '<div class="am-muted" style="padding:10px">No applications yet</div>';
  }

  function setSidebarSection(name, open) {
    var section = document.getElementById(name === "projects" ? "amProjectsSection" : "amApplicationsSection");
    var toggle = document.getElementById(name === "projects" ? "amProjectSelector" : "amApplicationSelector");
    var menu = document.getElementById(name === "projects" ? "amProjectMenu" : "amApplicationMenu");
    section.classList.toggle("open", open);
    menu.hidden = !open;
    toggle.setAttribute("aria-expanded", open ? "true" : "false");
    toggle.querySelector(".am-chevron").src = iconRoot + (open ? "chevron-up.svg" : "chevron-down.svg");
  }

  function markNavigation(view) {
    document.querySelectorAll("[data-am-view]").forEach(function(item) { item.classList.toggle("active", item.dataset.amView === view); });
  }

  function renderCurrent() {
    showDynamicContent();
    if (!state.connection && state.view !== "github" && state.view !== "settings" && state.view !== "resources") { renderOnboarding(); return; }
    markNavigation(state.view);
    if (state.view === "wizard") return;
    if (state.view === "application" && state.currentApplicationID) { renderApplicationDetail(state.currentApplicationID, state.currentApplicationTab, state.currentEnvironmentID); return; }
    if (state.view === "environment" && state.currentApplicationID && state.currentEnvironmentID) { renderEnvironmentDetail(state.currentApplicationID, state.currentEnvironmentID); return; }
    if (state.view === "release" && state.currentReleaseID) { renderReleaseDetail(state.currentReleaseID); return; }
    if (state.view === "deployment" && state.currentDeploymentID) { renderDeploymentDetail(state.currentDeploymentID); return; }
    if (state.view === "repositories") { renderRepositories(); return; }
    if (state.view === "resources") { renderResources(); return; }
    if (state.view === "github") { renderGitHub(); return; }
    if (state.view === "settings") { renderSettings(); return; }
    if (state.view === "applications") { renderApplications(); return; }
    if (state.currentProjectID && state.projects.length) { renderProjectDetail(state.currentProjectID); return; }
    renderApplications();
  }

  function renderOnboarding() {
    showDynamicContent();
    markNavigation("github");
    content.innerHTML = pageHeader("Connect GitHub", "Install the ServerPilot GitHub App to discover repositories and version images.", button("Configure GitHub App", "configure-github", true, "brand-github")) +
      '<div class="am-panel" style="padding:28px;max-width:840px"><div class="am-page-title-row"><span class="am-page-mark">' + icon("brand-github") + '</span><div><h2 style="margin-bottom:4px">One account, only authorized repositories</h2><p class="am-muted">Credentials are encrypted on this server. Signed tag and Release webhooks create one shared repository version with per-application image artifacts.</p></div></div></div>';
  }

  function applicationCard(app) {
    var env = preferredEnvironment(app.environments || []);
    return '<button type="button" class="am-card" data-application-id="' + h(app.id) + '"><div class="am-card-top"><div class="am-card-title"><span class="am-type-tile">' + appTypeIcon(app.type) + '</span><div><strong>' + h(app.name) + '</strong></div></div>' + statusBadge(env ? env.status : "attention") + '</div><p class="am-card-description">' + h(app.description || "No description provided.") + '</p><div class="am-chips"><span class="am-chip">' + appTypeIcon(app.type) + h(appTypeShortLabel(app.type)) + '</span><span class="am-chip am-mono">' + icon("brand-github") + h(app.repository) + '</span></div><div class="am-card-rule"></div><div class="am-card-footer"><span>' + (env ? environmentChip(env) : '<span class="am-chip">No environment</span>') + '</span><strong class="am-mono">' + h(env && env.current_version ? env.current_version : "No version") + '</strong><span>' + icon("clock") + h(env && env.last_deployed_at ? relative(env.last_deployed_at) : "Not deployed") + '</span></div></button>';
  }

  function renderProjectDetail(projectID) {
    showDynamicContent();
    var project = state.projects.find(function(item) { return item.id === projectID; });
    if (!project) { errorState("Project not found"); return; }
    state.view = "project";
    state.currentProjectID = projectID;
    state.currentApplicationID = "";
    markNavigation("project");
    setSidebarSection("projects", true);
    renderSelectors();
    var apps = state.applications.filter(function(app) { return app.project_id === projectID; });
    var actions = button("Settings", "configure-project", false, "settings", ' data-project-id="' + h(projectID) + '"') + button("New application", "create-application", true, "plus");
    content.innerHTML = '<div class="am-breadcrumb">Projects &nbsp;›&nbsp; ' + h(project.name) + '</div><header class="am-page-header"><div><div class="am-page-title-row"><span class="am-page-mark">' + h(initials(project.name)) + '</span><h1>' + h(project.name) + '</h1></div><p style="margin-top:8px">' + h(project.description || "Applications and shared runtime configuration.") + '</p><div class="am-page-meta">' + icon("packages") + '<span>' + h(apps.length) + ' applications</span><span>Project variables inherited at deploy time</span></div></div><div class="am-actions">' + actions + '</div></header>' +
      (apps.length ? '<div class="am-grid">' + apps.map(applicationCard).join("") + '</div>' : emptyState("This project needs an application", "A project cannot remain empty. Create an application and assign it here.", "create-application", "New application"));
  }

  function renderApplications() {
    showDynamicContent();
    state.view = "applications";
    markNavigation("applications");
    setSidebarSection("applications", true);
    var query = state.query.toLowerCase();
    var apps = state.applications.filter(function(app) {
      var assignmentMatches = state.applicationFilter === "all" || state.applicationFilter === "assigned" && app.project_id || state.applicationFilter === "unassigned" && !app.project_id;
      return assignmentMatches && (!query || app.name.toLowerCase().includes(query) || app.repository.toLowerCase().includes(query) || (app.project_name || "").toLowerCase().includes(query));
    });
    var filters = '<div class="am-segmented">' + ["all", "assigned", "unassigned"].map(function(filter) { return '<button type="button" class="' + (state.applicationFilter === filter ? "active" : "") + '" data-am-filter="' + filter + '">' + h(label(filter)) + '</button>'; }).join("") + '</div>';
    content.innerHTML = pageHeader("Applications", "Deployable applications linked to synchronized GitHub repositories.", button("New application", "create-application", true, "plus")) + filters + (apps.length ? '<div class="am-grid">' + apps.map(applicationCard).join("") + '</div>' : emptyState("No applications found", "Create an application from an authorized repository.", "create-application", "New application"));
  }

  function renderRepositories() {
    showDynamicContent();
    state.view = "repositories";
    markNavigation("repositories");
    var query = state.query.toLowerCase();
    var repos = state.repositories.filter(function(repo) { return !query || repo.full_name.toLowerCase().includes(query) || (repo.language || "").toLowerCase().includes(query); });
    var rows = repos.map(function(repo) {
      return '<tr><td>' + repositoryIdentity(repo) + '<div class="am-muted">' + (repo.private ? "Private" : "Public") + '</div></td><td class="am-mono">' + h(repo.default_branch) + '</td><td>' + h(repo.language || "—") + '</td><td>' + h(repo.application_count) + '</td><td>' + h(relative(repo.last_synced_at)) + '</td><td class="am-table-actions">' + button("Create application", "create-application", false, "plus", ' data-repository-id="' + h(repo.id) + '"') + '</td></tr>';
    }).join("");
    content.innerHTML = pageHeader("Repositories", "Repositories authorized through the connected GitHub App.", button("Sync now", "sync-github", false, "refresh")) + (rows ? '<div class="am-table-wrap"><table class="am-table"><thead><tr><th>Repository</th><th>Branch</th><th>Language</th><th>Applications</th><th>Last sync</th><th></th></tr></thead><tbody>' + rows + '</tbody></table></div>' : emptyState("No repositories", "Grant repository access in the GitHub App installation.", "sync-github", "Sync now"));
  }

  function renderGitHub() {
    showDynamicContent();
    state.view = "github";
    markNavigation("github");
    if (!state.connection) { renderOnboarding(); return; }
    var conn = state.connection;
    var rows = state.repositories.map(function(repo) {
      return '<div class="am-list-row"><span class="am-list-avatar">' + h(initials(repo.name)) + '</span><div class="am-list-row-main">' + repositoryIdentity(repo) + '<span class="am-muted">Default branch ' + h(repo.default_branch) + ' · ' + h(repo.language || "Unknown") + '</span></div><span class="am-chip">' + icon(repo.private ? "lock" : "world") + (repo.private ? "Private" : "Public") + '</span></div>';
    }).join("");
    var headerActions = button("Sync now", "sync-github", false, "refresh") + button("Manage installation", "configure-github", false, "settings");
    content.innerHTML = pageHeader("GitHub", "Manage the GitHub App installation, connected account and authorized repositories.", "") +
      '<div class="am-card"><div class="am-card-top"><div class="am-card-title"><span class="am-type-tile">' + icon("brand-github") + '</span><div><h2 style="margin:0">' + h(conn.account_login) + ' ' + statusBadge("healthy") + '</h2><div class="am-muted">' + h(conn.account_type) + ' · @' + h(conn.account_login) + ' · GitHub App installed</div><div class="am-muted">' + icon("refresh") + ' Last synced ' + h(relative(conn.last_synced_at)) + ' · ' + h(state.repositories.length) + ' repositories authorized</div></div></div><div class="am-actions">' + headerActions + '</div></div></div>' +
      '<section class="am-section am-list-panel"><div class="am-list-header"><div><h2 style="margin:0">Authorized repositories</h2><div class="am-muted">Only these repositories can be linked to applications.</div></div>' + button("Edit access", "configure-github", false) + '</div>' + rows + '</section>';
  }

  function setupStatus(text, kind) {
    var status = kind === "complete" ? "am-status-success" : kind === "optional" || kind === "available" ? "am-status-info" : "am-status-warning";
    return '<span class="am-status ' + status + '">' + h(text) + '</span>';
  }

  function setupStep(number, iconName, title, description, status, actionHTML) {
    return '<div class="am-setup-step"><span class="am-setup-step-number">' + h(number) + '</span><span class="am-setup-step-icon">' + icon(iconName) + '</span><div class="am-setup-step-copy"><strong>' + h(title) + '</strong><span>' + h(description) + '</span></div><div class="am-setup-step-meta">' + status + (actionHTML || "") + '</div></div>';
  }

  function renderResources() {
    state.view = "resources";
    markNavigation("resources");
    showNativeView("amResourcesView");
    if (window.loadResources) window.loadResources({ force: true });
  }

  function renderSettings() {
    showDynamicContent();
    state.view = "settings";
    markNavigation("settings");
    var connectedAgents = state.agents.filter(function(agent) { return agent.status === "online" || agent.status === "local"; });
    var environmentCount = state.applications.reduce(function(total, app) { return total + (app.environments || []).length; }, 0);
    var applicationsConfigured = state.applications.length > 0 && state.applications.every(function(app) { return (app.environments || []).length > 0; });
    var requiredChecks = [Boolean(state.connection), state.repositories.length > 0, applicationsConfigured, connectedAgents.length > 0, state.releases.length > 0];
    var completedChecks = requiredChecks.filter(Boolean).length;
    var readinessPercent = Math.round(completedChecks / requiredChecks.length * 100);
    var firstApplication = state.applications[0] || null;
    var githubAction = state.connection ? '<button type="button" class="am-button" data-am-view="github">Manage</button>' : button("Connect", "configure-github", false, "brand-github");
    var repositoryAction = state.repositories.length ? '<button type="button" class="am-button" data-am-view="repositories">View repositories</button>' : button("Sync repositories", "sync-github", false, "refresh");
    var applicationAction = firstApplication ? '<button type="button" class="am-button" data-application-id="' + h(firstApplication.id) + '">Open application</button>' : button("Create application", "create-application", false, "plus");
    var workflowAction = firstApplication ? button("Copy workflow", "copy-workflow", false, "copy", ' data-application-id="' + h(firstApplication.id) + '"') : button("Create application", "create-application", false, "plus");
    var registryStatus = state.connection && state.connection.registry_configured ? setupStatus("Completed", "complete") : setupStatus("Optional for public images", "optional");
    var registryAction = '<button type="button" class="am-button" data-am-view="github">Registry settings</button>';
    var releaseAction = firstApplication ? '<button type="button" class="am-button" data-application-id="' + h(firstApplication.id) + '">Open application</button>' : button("Create application", "create-application", false, "plus");
    var guideSteps = setupStep(1, "brand-github", "Connect GitHub", "Authorize one GitHub account or organization and its repositories.", state.connection ? setupStatus("Completed", "complete") : setupStatus("Needs configuration", "pending"), githubAction) +
      setupStep(2, "folder-code", "Synchronize a repository", "ServerPilot applications can only be created from authorized repositories.", state.repositories.length ? setupStatus("Completed", "complete") : setupStatus("Needs configuration", "pending"), repositoryAction) +
      setupStep(3, "packages", "Prepare an application", "Set the Dockerfile, build context and container port. Current: " + state.applications.length + " applications · " + environmentCount + " environments.", applicationsConfigured ? setupStatus("Completed", "complete") : setupStatus("Needs configuration", "pending"), applicationAction) +
      setupStep(4, "code", "Install the GitHub Actions workflow", "Copy the generated workflow into .github/workflows so version tags publish the expected GHCR image.", firstApplication ? setupStatus("Ready to copy", "available") : setupStatus("Needs an application", "pending"), workflowAction) +
      setupStep(5, "shield-lock", "Configure private registry access", "Public GHCR images need no token. Private images require a registry username and classic PAT with read:packages.", registryStatus, registryAction) +
      setupStep(6, "server", "Choose a deployment server", "Use this ServerPilot host or pair a remote agent before deploying an environment.", connectedAgents.length ? setupStatus("Completed", "complete") : setupStatus("Needs configuration", "pending"), button("Pair server", "pair-agent", false, "plus")) +
      setupStep(7, "rocket", "Publish a version and deploy", "Push a semantic version tag, let the workflow publish the image, then deploy manually or by policy.", state.releases.length ? setupStatus("Completed", "complete") : setupStatus("No version detected", "pending"), releaseAction);
    var agentRows = state.agents.map(function(agent) {
      return '<div class="am-list-row"><span class="am-list-avatar">' + icon("server") + '</span><div class="am-list-row-main"><strong>' + h(agent.name) + '</strong><span class="am-muted am-mono">' + h(agent.id) + ' · ' + h(agent.version || "Local controller") + '</span></div>' + statusBadge(agent.status) + '</div>';
    }).join("");
    var guideTemplate = document.getElementById("amDeploymentGuideTemplate");
    var guideReference = guideTemplate ? guideTemplate.innerHTML : "";
    content.innerHTML = pageHeader("Settings", "ServerPilot Application Manager preferences and connected deployment agents.", button("Pair server", "pair-agent", true, "plus")) +
      '<section class="am-deployment-guide"><div class="am-guide-header"><div><span class="am-eyebrow">Getting started</span><h2>Deployment setup</h2><p>Everything a repository and application need before ServerPilot can deploy it safely.</p></div><div class="am-guide-progress"><strong>' + h(completedChecks) + ' of ' + h(requiredChecks.length) + ' ready</strong><span>' + h(readinessPercent) + '%</span><div class="am-guide-progress-track"><span style="width:' + h(readinessPercent) + '%"></span></div></div></div><div class="am-setup-flow" aria-label="Deployment flow"><span>' + icon("git-branch") + '<strong>Version tag</strong></span>' + icon("chevron-right") + '<span>' + icon("brand-github") + '<strong>GitHub Action</strong></span>' + icon("chevron-right") + '<span>' + icon("package") + '<strong>GHCR image</strong></span>' + icon("chevron-right") + '<span>' + icon("shield-lock") + '<strong>Digest check</strong></span>' + icon("chevron-right") + '<span>' + icon("rocket") + '<strong>Deploy</strong></span></div><div class="am-setup-steps">' + guideSteps + '</div></section>' +
      guideReference +
      '<div class="am-grid"><div class="am-card"><span class="am-eyebrow">Account</span><h2 style="margin:8px 0 4px">ServerPilot</h2><div class="am-muted">' + h(state.connection ? "@" + state.connection.account_login : "GitHub not connected") + '</div></div><div class="am-card"><span class="am-eyebrow">Integration</span><h2 style="margin:8px 0 4px">GitHub & GHCR</h2><div class="am-muted">Credentials remain encrypted and secrets are write-only.</div></div></div>' +
      '<section class="am-section am-list-panel"><div class="am-list-header"><div><h2 style="margin:0">Deployment servers</h2><div class="am-muted">Local controller and paired agents.</div></div></div>' + agentRows + '</section>';
    var platformSettings = document.getElementById("amPlatformSettingsView");
    var terminalSettings = document.getElementById("amTerminalSettingsView");
    if (platformSettings) platformSettings.hidden = false;
    if (terminalSettings) terminalSettings.hidden = false;
    if (window.loadSettings) window.loadSettings();
  }

  function environmentCards(app, latestReady) {
    return (app.environments || []).map(function(env) {
      return '<div class="am-card"><div class="am-card-top"><div>' + environmentChip(env) + '<h2 style="margin:12px 0 4px">' + h(env.name) + '</h2></div>' + statusBadge(env.status) + '</div><div class="am-card-rule"></div><div class="am-form-grid"><div><span class="am-muted">Server</span><div>' + h(env.agent_id || "This server") + '</div></div><div><span class="am-muted">Version</span><div class="am-mono">' + h(env.current_version || "Not deployed") + '</div></div><div><span class="am-muted">Domain</span><div class="am-truncate">' + h(env.domain || "No domain") + '</div></div><div><span class="am-muted">Deploy policy</span><div>' + h(autoDeployLabel(env.auto_deploy_mode)) + '</div></div></div><div class="am-actions am-card-actions"><button class="am-button" type="button" data-environment-id="' + h(env.id) + '" data-parent-application-id="' + h(app.id) + '">View environment</button>' + button("Deploy", "deploy", true, "rocket", ' data-environment-id="' + h(env.id) + '" data-artifact-id="' + h(latestReady ? latestReady.id : "") + '"' + (latestReady ? "" : " disabled")) + '</div></div>';
    }).join("");
  }

  function releaseTable(rows) {
    return rows ? '<div class="am-table-wrap"><table class="am-table"><thead><tr><th>Version</th><th>Image</th><th>Image status</th><th>Digest</th><th>Detected</th></tr></thead><tbody>' + rows + '</tbody></table></div>' : emptyState("No versions detected", "Push a semantic version tag after installing the generated workflow.", null, null);
  }
  function deploymentTable(rows) {
    return rows ? '<div class="am-table-wrap"><table class="am-table"><thead><tr><th>Status</th><th>Environment</th><th>Trigger</th><th>Actor</th><th>Digest</th><th>Started</th></tr></thead><tbody>' + rows + '</tbody></table></div>' : emptyState("No deployments yet", "Deployments appear after a release image is ready.", null, null);
  }
  function configurationRows(entries, secrets) {
    var filtered = (entries || []).filter(function(entry) { return Boolean(entry.secret) === secrets; });
    if (!filtered.length) return '<div class="am-list-row"><span class="am-muted">No ' + (secrets ? "secrets" : "variables") + ' configured.</span></div>';
    return filtered.map(function(entry) {
      return '<div class="am-list-row"><div class="am-list-row-main"><strong class="am-mono">' + h(entry.key) + '</strong></div><span class="am-mono am-muted">' + (entry.secret ? "••••••••••••" : h(entry.value || "")) + '</span><span class="am-muted">' + h(relative(entry.updated_at)) + '</span></div>';
    }).join("");
  }
  function mergeConfiguration(projectEntries, environmentEntries) {
    var values = new Map();
    (projectEntries || []).forEach(function(entry) { values.set(entry.key + ":" + Boolean(entry.secret), entry); });
    (environmentEntries || []).forEach(function(entry) { values.set(entry.key + ":" + Boolean(entry.secret), entry); });
    return Array.from(values.values()).sort(function(a, b) { return a.key.localeCompare(b.key); });
  }

  async function renderApplicationDetail(id, selectedTab, selectedEnvironmentID) {
    loading();
    try {
      var responses = await Promise.all([
        apiFetch("/api/app-manager/applications/detail?id=" + encodeURIComponent(id)),
        apiFetch("/api/app-manager/artifacts?application_id=" + encodeURIComponent(id) + "&limit=100"),
        apiFetch("/api/app-manager/deployments?limit=200")
      ]);
      var app = dataOf(responses[0]);
      var artifacts = dataOf(responses[1]) || [];
      var environmentIDs = new Set((app.environments || []).map(function(env) { return env.id; }));
      var deployments = (dataOf(responses[2]) || []).filter(function(item) { return environmentIDs.has(item.environment_id); });
      var tab = selectedTab || "overview";
      var preferred = preferredEnvironment(app.environments || []);
      var selectedEnv = (app.environments || []).find(function(env) { return env.id === selectedEnvironmentID; }) || preferred;
      var config = null;
      if (tab === "configuration" && selectedEnv) config = dataOf(await apiFetch("/api/app-manager/configuration/summary?environment_id=" + encodeURIComponent(selectedEnv.id))) || {};
      var latestReady = artifacts.find(function(item) { return item.status === "ready"; });
      state.currentApplicationID = app.id;
      state.currentProjectID = app.project_id || state.currentProjectID;
      state.currentApplicationTab = tab;
      state.currentEnvironmentID = selectedEnv ? selectedEnv.id : "";
      state.view = "application";
      setSidebarSection("applications", true);
      renderSelectors();
      markNavigation("application");

      var tabIcons = { overview: "layout-grid", environments: "layers-subtract", deployments: "rocket", configuration: "adjustments-horizontal", activity: "activity" };
      var tabs = ["overview", "environments", "deployments", "configuration", "activity"].map(function(name) {
        return '<button type="button" class="' + (tab === name ? "active" : "") + '" data-app-tab="' + name + '" data-application-id="' + h(app.id) + '">' + icon(tabIcons[name]) + h(label(name)) + '</button>';
      }).join("");
      var cards = environmentCards(app, latestReady);
      var artifactRows = artifacts.map(function(item) {
        return '<tr data-release-id="' + h(item.release_id) + '"><td class="am-mono">' + h(item.image_reference.split(":").pop()) + '</td><td class="am-mono am-truncate" title="' + h(item.image_reference) + '">' + h(item.image_reference) + '</td><td>' + statusBadge(item.status) + '</td><td class="am-mono" title="' + h(item.image_digest || "") + '">' + h(shortDigest(item.image_digest)) + '</td><td>' + h(relative(item.created_at)) + '</td></tr>';
      }).join("");
      var deploymentRows = deployments.map(function(item) {
        var environment = (app.environments || []).find(function(env) { return env.id === item.environment_id; });
        return '<tr data-deployment-id="' + h(item.id) + '"><td>' + statusBadge(item.status) + '</td><td>' + h(environment ? environment.name : "Unknown") + '</td><td>' + h(label(item.trigger)) + '</td><td>' + h(item.actor) + '</td><td class="am-mono" title="' + h(item.image_digest || "") + '">' + h(item.image_digest ? shortDigest(item.image_digest) : "Pending") + '</td><td>' + h(relative(item.created_at)) + '</td></tr>';
      }).join("");
      var body = "";
      if (tab === "overview") body = '<section class="am-section"><div class="am-section-head"><h2>Environments</h2></div><div class="am-grid">' + cards + '</div></section><section class="am-section"><div class="am-section-head"><h2>Latest version images</h2></div>' + releaseTable(artifactRows) + '</section>';
      if (tab === "environments") body = '<section class="am-section"><div class="am-section-head"><div><h2>Environments</h2><div class="am-muted">Every environment owns one standalone container.</div></div></div><div class="am-grid">' + cards + '</div></section>';
      if (tab === "deployments") body = '<section class="am-section"><div class="am-section-head"><h2>Deployments</h2></div>' + deploymentTable(deploymentRows) + '</section>';
      if (tab === "activity") body = '<section class="am-section"><div class="am-panel am-feed">' + (deployments.map(function(item) { return '<button class="am-feed-item am-feed-button" type="button" data-deployment-id="' + h(item.id) + '"><span class="am-feed-dot"></span><div><strong>' + h(label(item.trigger)) + ' deployment</strong><div class="am-muted">' + h(item.actor) + '</div></div><div>' + statusBadge(item.status) + '<div class="am-muted">' + h(relative(item.created_at)) + '</div></div></button>'; }).join("") || '<div class="am-feed-item"><span class="am-feed-dot"></span><div>No activity yet</div></div>') + '</div></section>';
      if (tab === "configuration") {
        var merged = mergeConfiguration(config.project, config.environment);
        var environmentTabs = (app.environments || []).map(function(env) { return '<button type="button" class="' + (selectedEnv && env.id === selectedEnv.id ? "active" : "") + '" data-config-environment="' + h(env.id) + '" data-application-id="' + h(app.id) + '">' + h(env.name) + '</button>'; }).join("");
        body = '<section class="am-section"><div class="am-segmented">' + environmentTabs + '</div><div class="am-list-panel"><div class="am-list-header"><div><h2 style="margin:0">' + icon("adjustments-horizontal") + ' Variables</h2><div class="am-muted">Project defaults merged with environment values; environment wins.</div></div>' + button("Add variable", "configure-environment", false, "plus", ' data-environment-id="' + h(selectedEnv.id) + '"') + '</div>' + configurationRows(merged, false) + '</div><div class="am-list-panel" style="margin-top:24px"><div class="am-list-header"><div><h2 style="margin:0">' + icon("lock") + ' Secrets</h2><div class="am-muted">Encrypted and never displayed in full.</div></div>' + button("Add secret", "configure-environment", false, "plus", ' data-environment-id="' + h(selectedEnv.id) + '"') + '</div><div class="am-alert" style="border-width:0 0 1px;border-radius:0">Secret values are write-only and resolved only in memory during deployment.</div>' + configurationRows(merged, true) + '</div></section>';
      }

      var deployAttrs = preferred ? ' data-environment-id="' + h(preferred.id) + '" data-artifact-id="' + h(latestReady ? latestReady.id : "") + '"' + (latestReady ? "" : " disabled") : " disabled";
      var actions = '<a class="am-button" href="https://github.com/' + h(app.repository) + '" target="_blank" rel="noopener">' + icon("brand-github") + 'Repository' + icon("external-link") + '</a>' + button("Settings", "configure-environment", false, "settings", preferred ? ' data-environment-id="' + h(preferred.id) + '"' : " disabled") + button("Deploy", "deploy", true, "rocket", deployAttrs);
      content.innerHTML = '<div class="am-breadcrumb">' + h(app.project_name || "Applications") + ' &nbsp;›&nbsp; ' + h(app.name) + '</div><header class="am-page-header"><div><div class="am-page-title-row"><span class="am-type-tile">' + appTypeIcon(app.type) + '</span><h1>' + h(app.name) + '</h1></div><p style="margin-top:8px">' + h(app.description || "Application managed by ServerPilot.") + '</p><div class="am-page-meta">' + (preferred ? statusBadge(preferred.status) : "") + '<span class="am-chip">' + appTypeIcon(app.type) + h(appTypeShortLabel(app.type)) + '</span><span class="am-chip am-mono">' + icon("brand-github") + h(app.repository) + '</span><span>' + h(preferred && preferred.type === "production" ? "Production " : "") + '<strong class="am-mono">' + h(preferred && preferred.current_version ? preferred.current_version : "Not deployed") + '</strong></span></div></div><div class="am-actions">' + actions + '</div></header><nav class="am-tabs" aria-label="Application sections">' + tabs + '</nav>' + body;
      content.dataset.applicationId = app.id;
    } catch (err) { errorState(err.message); }
  }

  async function renderEnvironmentDetail(applicationID, environmentID) {
    loading();
    try {
      var responses = await Promise.all([
        apiFetch("/api/app-manager/applications/detail?id=" + encodeURIComponent(applicationID)),
        apiFetch("/api/app-manager/artifacts?application_id=" + encodeURIComponent(applicationID) + "&limit=100"),
        apiFetch("/api/app-manager/deployments?environment_id=" + encodeURIComponent(environmentID) + "&limit=100"),
        apiFetch("/api/app-manager/configuration/summary?environment_id=" + encodeURIComponent(environmentID))
      ]);
      var app = dataOf(responses[0]);
      var artifacts = dataOf(responses[1]) || [];
      var deployments = dataOf(responses[2]) || [];
      var config = dataOf(responses[3]) || {};
      var env = (app.environments || []).find(function(item) { return item.id === environmentID; });
      if (!env) throw new Error("Environment not found");
      state.currentApplicationID = app.id;
      state.currentEnvironmentID = env.id;
      state.view = "environment";
      var latestReady = artifacts.find(function(item) { return item.status === "ready"; });
      var rows = deployments.map(function(item) { return '<tr data-deployment-id="' + h(item.id) + '"><td>' + statusBadge(item.status) + '</td><td>' + h(label(item.trigger)) + '</td><td>' + h(item.actor) + '</td><td class="am-mono">' + h(item.image_digest ? shortDigest(item.image_digest) : "Pending") + '</td><td>' + h(relative(item.created_at)) + '</td></tr>'; }).join("");
      var merged = mergeConfiguration(config.project, config.environment);
      var actions = '<button class="am-button" type="button" data-back-application="' + h(app.id) + '">' + icon("chevron-left") + 'Back</button>' + button("Deploy policy", "deploy-policy", false, "settings", ' data-environment-id="' + h(env.id) + '" data-deploy-mode="' + h(env.auto_deploy_mode) + '"') + button("Rollback", "rollback", false, "refresh", ' data-environment-id="' + h(env.id) + '"') + button("Deploy", "deploy", true, "rocket", ' data-environment-id="' + h(env.id) + '" data-artifact-id="' + h(latestReady ? latestReady.id : "") + '"' + (latestReady ? "" : " disabled"));
      content.innerHTML = pageHeader(env.name, "Standalone container environment for " + app.name + ".", actions, app.name + " › Environments › " + env.name) + '<div class="am-chips">' + environmentChip(env) + statusBadge(env.status) + '</div><div class="am-grid am-summary-grid"><div class="am-card"><span class="am-muted">Version</span><h3 class="am-mono">' + h(env.current_version || "Not deployed") + '</h3></div><div class="am-card"><span class="am-muted">Domain</span><h3 class="am-mono am-truncate">' + h(env.domain || "No domain") + '</h3></div><div class="am-card"><span class="am-muted">Deploy policy</span><h3>' + h(autoDeployLabel(env.auto_deploy_mode)) + '</h3></div></div><section class="am-section"><div class="am-section-head"><h2>Deployment history</h2></div>' + deploymentTable(rows) + '</section><section class="am-section"><div class="am-section-head"><div><h2>Runtime configuration</h2><div class="am-muted">Project values are applied first; this environment wins on duplicate keys.</div></div>' + button("Manage values", "configure-environment", false, "settings", ' data-environment-id="' + h(env.id) + '"') + '</div><div class="am-list-panel">' + configurationRows(merged, false) + configurationRows(merged, true) + '</div></section>';
    } catch (err) { errorState(err.message); }
  }

  async function renderReleaseDetail(id) {
    loading();
    try {
      var release = dataOf(await apiFetch("/api/app-manager/releases/detail?id=" + encodeURIComponent(id)));
      state.currentReleaseID = release.id;
      state.view = "release";
      var rows = (release.artifacts || []).map(function(item) {
        return '<tr data-application-id="' + h(item.application_id) + '"><td><strong>' + h(item.application) + '</strong></td><td class="am-mono am-truncate">' + h(item.image_reference) + '</td><td>' + statusBadge(item.status) + '</td><td class="am-mono">' + h(shortDigest(item.image_digest)) + '</td><td>' + h(item.failure_code || "—") + '</td></tr>';
      }).join("");
      var sources = (release.tag_detected ? '<span class="am-chip">Version tag detected</span>' : '') + (release.release_published ? '<span class="am-chip">GitHub Release published</span>' : '');
      content.innerHTML = pageHeader("Version " + release.tag, release.name || "Shared repository version.", button("Applications", "applications", false, "chevron-left"), "Versions › " + release.tag) + '<div class="am-chips">' + sources + '</div><div class="am-panel am-release-meta"><div><span>Commit</span><strong class="am-mono">' + h(release.commit_sha || "—") + '</strong></div><div><span>Last detected</span><strong>' + h(relative(release.published_at)) + '</strong></div></div><section class="am-section"><div class="am-section-head"><div><h2>Application image artifacts</h2><div class="am-muted">The version is shared; each application image is verified independently.</div></div></div><div class="am-table-wrap"><table class="am-table"><thead><tr><th>Application</th><th>Expected image</th><th>Status</th><th>Digest</th><th>Failure</th></tr></thead><tbody>' + rows + '</tbody></table></div></section>';
    } catch (err) { errorState(err.message); }
  }

  async function renderDeploymentDetail(id) {
    loading();
    try {
      var deployment = dataOf(await apiFetch("/api/app-manager/deployments/detail?id=" + encodeURIComponent(id)));
      state.currentDeploymentID = deployment.id;
      state.view = "deployment";
      content.innerHTML = pageHeader("Deployment", "Immutable image deployment executed by ServerPilot.", button("Applications", "applications", false, "chevron-left"), "Deployments › " + deployment.id.slice(0, 8)) + '<div class="am-chips">' + statusBadge(deployment.status) + '<span class="am-chip">' + h(label(deployment.trigger)) + '</span></div><div class="am-grid am-summary-grid"><div class="am-card"><span class="am-muted">Environment</span><h3 class="am-mono am-truncate">' + h(deployment.environment_id) + '</h3></div><div class="am-card"><span class="am-muted">Actor</span><h3>' + h(deployment.actor) + '</h3></div></div><section class="am-section"><div class="am-panel am-log-panel"><div><span>Container</span><strong class="am-mono">' + h(deployment.container_name || "Pending") + '</strong></div><div><span>Image digest</span><strong class="am-mono am-truncate">' + h(deployment.image_digest || "Pending") + '</strong></div><pre class="am-mono">' + h(deployment.log_summary || "No operational log is available. Secret values are never recorded.") + '</pre></div></section>';
    } catch (err) { errorState(err.message); }
  }

  function openDialog(eyebrow, title, body, footer) {
    dialogEyebrow.textContent = eyebrow;
    dialogTitle.textContent = title;
    dialogBody.innerHTML = body;
    dialogFooter.innerHTML = footer || '<button class="am-button" value="cancel">Close</button>';
    dialog.showModal();
  }
  function closeDialog() { if (dialog.open) dialog.close(); }
  function parseVariables(text, secret) {
    return text.split(/\n/).map(function(line) { return line.trim(); }).filter(Boolean).map(function(line) {
      var index = line.indexOf("=");
      if (index < 1) throw new Error("Use KEY=value on every configuration line");
      return { key: line.slice(0, index).trim(), value: line.slice(index + 1), secret: secret };
    });
  }

  function githubDialog() {
    var connection = state.connection || {};
    var reconnectNotice = connection.id ? '<div class="am-alert">Saving replaces the current GitHub and registry credentials. ServerPilot will also generate a new webhook secret.</div>' : '';
    var connectedAccount = connection.id ? '<div class="am-connection-summary"><span class="am-list-avatar">' + h(initials(connection.account_login)) + '</span><div><strong>@' + h(connection.account_login) + '</strong><small>' + h(connection.account_type) + ' · Installation ' + h(connection.installation_id) + '</small></div>' + statusBadge("healthy") + '</div>' : '';
    openDialog("Secure integration", connection.id ? "Reconnect GitHub App" : "Connect GitHub App", reconnectNotice + connectedAccount + '<div class="am-form-grid am-setup-form"><div class="am-field"><label for="amGhAppID">App ID</label><input id="amGhAppID" class="am-mono" inputmode="numeric" pattern="[0-9]+" maxlength="20" autocomplete="off" value="' + h(connection.app_id || "") + '" placeholder="123456"><small>Found on the GitHub App settings page.</small></div><div class="am-field"><label for="amGhKeyFile">Private key file</label><input id="amGhKeyFile" type="file" accept=".pem,application/x-pem-file"><small>Upload the .pem file generated by GitHub.</small></div><div class="am-field am-field-full"><label for="amGhPrivateKey">Private key</label><textarea id="amGhPrivateKey" class="am-mono" autocomplete="off" spellcheck="false" placeholder="-----BEGIN RSA PRIVATE KEY-----"></textarea><small>Write-only and encrypted before storage. Uploading a file fills this field locally.</small></div></div><div class="am-discovery-note">' + icon("brand-github") + '<div><strong>Detected automatically</strong><span>Account, account type, avatar and Installation ID are read directly from the single GitHub App installation.</span></div></div><details class="am-disclosure"><summary><span>' + icon("package") + '<span><strong>Private GHCR images</strong><small>Optional · public images need no credentials</small></span></span>' + icon("chevron-down") + '</summary><div class="am-form-grid"><div class="am-field"><label for="amGhRegistryUser">Registry username</label><input id="amGhRegistryUser" autocomplete="username" placeholder="github-user-or-bot"><small>The user or bot that owns the token, not the organization.</small></div><div class="am-field"><label for="amGhPAT">PAT classic</label><input id="amGhPAT" type="password" autocomplete="new-password" placeholder="ghp_••••••••"><small>Requires only <span class="am-mono">read:packages</span>.</small></div></div></details>', '<button class="am-button" value="cancel">Cancel</button><button class="am-button am-button-primary" type="button" id="amSaveGitHub">' + (connection.id ? "Reconnect" : "Connect GitHub") + '</button>');
    document.getElementById("amGhKeyFile").addEventListener("change", function() {
      var file = this.files && this.files[0];
      if (!file) return;
      if (file.size > 32 * 1024) { showToast("Private key file is too large", "error"); this.value = ""; return; }
      var reader = new FileReader();
      reader.addEventListener("load", function() { document.getElementById("amGhPrivateKey").value = String(reader.result || ""); });
      reader.addEventListener("error", function() { showToast("Could not read the private key file", "error"); });
      reader.readAsText(file);
    });
    document.getElementById("amSaveGitHub").addEventListener("click", async function() {
      var target = this; target.disabled = true;
      try {
        var registryUsername = document.getElementById("amGhRegistryUser").value.trim();
        var registryPAT = document.getElementById("amGhPAT").value.trim();
        if (Boolean(registryUsername) !== Boolean(registryPAT)) throw new Error("Registry username and PAT must be provided together");
        var setup = dataOf(await apiFetch("/api/app-manager/github/configure", { method: "POST", body: { app_id: Number(document.getElementById("amGhAppID").value), private_key: document.getElementById("amGhPrivateKey").value, registry_username: registryUsername, registry_pat: registryPAT } }));
        await reload();
        var webhookURL = window.location.origin + "/webhooks/github/app-manager";
        openDialog("Connection ready", "Finish webhook setup", '<div class="am-success-panel">' + icon("circle-check") + '<div><strong>Connected to @' + h(setup.connection.account_login) + '</strong><span>ServerPilot detected the ' + h(setup.connection.account_type.toLowerCase()) + ' installation automatically.</span></div></div><div class="am-alert">Copy these values to the GitHub App webhook settings now. The secret is shown only once.</div><div class="am-alert"><strong>Permissions &amp; events:</strong> grant repository Contents read access and subscribe to Push, Release and Repository.</div><div class="am-copy-field"><label>Payload URL</label><div><code id="amWebhookURL"></code><button class="am-icon-button" type="button" id="amCopyWebhookURL" aria-label="Copy webhook URL">' + icon("copy") + '</button></div></div><div class="am-copy-field"><label>Webhook secret</label><div><code id="amWebhookSecret"></code><button class="am-icon-button" type="button" id="amCopyWebhookSecret" aria-label="Copy webhook secret">' + icon("copy") + '</button></div></div>', '<button class="am-button am-button-primary" value="cancel">Done</button>');
        document.getElementById("amWebhookURL").textContent = webhookURL;
        document.getElementById("amWebhookSecret").textContent = setup.webhook_secret;
        document.getElementById("amCopyWebhookURL").addEventListener("click", function() { copyText(webhookURL).then(function() { showToast("Webhook URL copied", "success"); }).catch(function(err) { showToast(err.message, "error"); }); });
        document.getElementById("amCopyWebhookSecret").addEventListener("click", function() { copyText(setup.webhook_secret).then(function() { showToast("Webhook secret copied", "success"); }).catch(function(err) { showToast(err.message, "error"); }); });
      } catch (err) { showToast(err.message, "error"); target.disabled = false; }
    });
  }

  function projectDialog(selectedApplicationID) {
    var unassigned = state.applications.filter(function(app) { return !app.project_id; });
    var draft = state.projectDraft || { name: "", description: "", variables: "", secrets: "", application_ids: [] };
    if (selectedApplicationID && draft.application_ids.indexOf(selectedApplicationID) < 0) draft.application_ids.push(selectedApplicationID);
    var picker = unassigned.length ? unassigned.map(function(app) { return '<label class="am-check"><input type="checkbox" name="amProjectApp" value="' + h(app.id) + '" ' + (draft.application_ids.indexOf(app.id) >= 0 ? "checked" : "") + '><span><strong>' + h(app.name) + '</strong> <span class="am-muted">' + h(app.repository) + '</span></span></label>'; }).join("") : '<div class="am-empty am-empty-compact"><div><h3>Create an application first</h3><p>A project must contain at least one unassigned application.</p>' + button("Create application", "create-application", true, "plus", ' data-return-to-project="true"') + '</div></div>';
    openDialog("Project", "Create project", '<div class="am-form-grid"><div class="am-field"><label for="amProjectName">Name</label><input id="amProjectName" maxlength="80" value="' + h(draft.name) + '"></div><div class="am-field"><label for="amProjectDescription">Description</label><input id="amProjectDescription" maxlength="500" value="' + h(draft.description) + '"></div><div class="am-field am-field-full"><label>Applications</label><div class="am-panel" style="padding:12px">' + picker + '</div></div><div class="am-field"><label for="amProjectVariables">Global variables</label><textarea id="amProjectVariables" placeholder="LOG_LEVEL=info">' + h(draft.variables) + '</textarea></div><div class="am-field"><label for="amProjectSecrets">Global secrets</label><textarea id="amProjectSecrets" placeholder="DATABASE_URL=…">' + h(draft.secrets) + '</textarea></div></div>', '<button class="am-button" value="cancel">Cancel</button><button class="am-button am-button-primary" type="button" id="amCreateProject">Create project</button>');
    var createButton = document.getElementById("amCreateProject");
    function updateState() { createButton.disabled = !unassigned.length || !document.getElementById("amProjectName").value.trim() || !document.querySelector('input[name="amProjectApp"]:checked'); }
    dialogBody.addEventListener("input", updateState);
    dialogBody.addEventListener("change", updateState);
    createButton.addEventListener("click", async function() {
      createButton.disabled = true;
      try {
        var ids = Array.from(document.querySelectorAll('input[name="amProjectApp"]:checked')).map(function(input) { return input.value; });
        var variables = parseVariables(document.getElementById("amProjectVariables").value, false).concat(parseVariables(document.getElementById("amProjectSecrets").value, true));
        var project = dataOf(await apiFetch("/api/app-manager/projects/create", { method: "POST", body: { name: document.getElementById("amProjectName").value.trim(), description: document.getElementById("amProjectDescription").value.trim(), application_ids: ids, variables: variables } }));
        state.projectDraft = null; closeDialog(); showToast("Project created", "success"); await fetchAll(true); renderProjectDetail(project.id);
      } catch (err) { showToast(err.message, "error"); createButton.disabled = false; }
    });
    updateState();
  }

  function captureProjectDraft() {
    var name = document.getElementById("amProjectName");
    if (!name) return;
    state.projectDraft = { name: name.value, description: document.getElementById("amProjectDescription").value, variables: document.getElementById("amProjectVariables").value, secrets: document.getElementById("amProjectSecrets").value, application_ids: Array.from(document.querySelectorAll('input[name="amProjectApp"]:checked')).map(function(input) { return input.value; }) };
  }

  function applicationWizard(preselectedRepository, returnToProject) {
    showDynamicContent();
    state.view = "wizard";
    markNavigation("wizard");
    var draft = { step: 0, repository_id: preselectedRepository || "", name: "", description: "", type: "nextjs", dockerfile: "Dockerfile", build_context: ".", container_port: 3000, project_id: "", environments: [newEnvironment("test", "test"), newEnvironment("staging", "staging"), newEnvironment("production", "production")] };
    var titles = ["Repository", "Basics", "Type", "Build", "Environments", "Configuration", "GitHub Actions", "Review"];
    var descriptions = ["Choose from repositories authorized through the GitHub App.", "Name the application and optionally assign it to a project.", "Select the runtime profile used for sensible defaults.", "Define the immutable image build inputs.", "Create one or more Test, Staging or Production environments.", "Configure servers, routing and runtime values.", "Review the copy-ready workflow generated by ServerPilot.", "Confirm every setting before creating the application."];
    function newEnvironment(name, type) { return { name: name, type: type, domain: "", site_enabled: false, ssl_enabled: false, health_path: "/", auto_deploy_mode: "manual", agent_id: "", variables: "", secrets: "" }; }
    function field(id) { var element = document.getElementById(id); return element ? element.value.trim() : ""; }
    function collect() {
      if (draft.step === 1) { draft.name = field("amAppName"); draft.description = field("amAppDescription"); draft.project_id = field("amAppProject"); }
      if (draft.step === 3) { draft.dockerfile = field("amAppDockerfile"); draft.build_context = field("amAppContext"); draft.container_port = Number(field("amAppPort")); }
      if (draft.step === 4) draft.environments = Array.from(content.querySelectorAll(".am-environment-editor")).map(function(box) { return Object.assign({}, draft.environments[Number(box.dataset.index)], { name: box.querySelector('[data-field="name"]').value.trim(), type: box.querySelector('[data-field="type"]').value }); });
      if (draft.step === 5) draft.environments = Array.from(content.querySelectorAll(".am-environment-editor")).map(function(box) { var old = draft.environments[Number(box.dataset.index)]; return Object.assign({}, old, { agent_id: box.querySelector('[data-field="agent"]').value, domain: box.querySelector('[data-field="domain"]').value.trim(), site_enabled: box.querySelector('[data-field="site"]').checked, ssl_enabled: box.querySelector('[data-field="ssl"]').checked, health_path: box.querySelector('[data-field="health"]').value.trim(), auto_deploy_mode: box.querySelector('[data-field="auto-mode"]').value, variables: box.querySelector('[data-field="variables"]').value, secrets: box.querySelector('[data-field="secrets"]').value }); });
    }
    function valid() {
      if (draft.step === 0) return Boolean(draft.repository_id);
      if (draft.step === 1) return Boolean(field("amAppName"));
      if (draft.step === 2) return Boolean(draft.type);
      if (draft.step === 3) { var port = Number(field("amAppPort")); return Boolean(field("amAppDockerfile") && field("amAppContext") && port > 0 && port < 65536); }
      if (draft.step === 4) { var editors = Array.from(content.querySelectorAll(".am-environment-editor")); return editors.length > 0 && editors.every(function(box) { return box.querySelector('[data-field="name"]').value.trim(); }); }
      if (draft.step === 5) {
        return Array.from(content.querySelectorAll(".am-environment-editor")).every(function(box) {
          var ssl = box.querySelector('[data-field="ssl"]').checked;
          var site = box.querySelector('[data-field="site"]').checked;
          var domain = box.querySelector('[data-field="domain"]').value.trim();
          if (!box.querySelector('[data-field="health"]').value.trim() || (ssl && (!site || !domain))) return false;
          try { parseVariables(box.querySelector('[data-field="variables"]').value, false); parseVariables(box.querySelector('[data-field="secrets"]').value, true); return true; } catch (_) { return false; }
        });
      }
      return true;
    }
    function stepBody() {
      if (draft.step === 0) return state.repositories.map(function(repo) { return '<button class="am-repository-choice ' + (draft.repository_id === repo.id ? "selected" : "") + '" type="button" data-wizard-repository="' + h(repo.id) + '">' + icon("brand-github") + '<span><strong class="am-mono">' + h(repo.full_name) + '</strong><small>' + h(repo.default_branch) + ' · ' + h(repo.language || "Unknown") + '</small></span>' + (repo.private ? icon("lock") : "") + '</button>'; }).join("") || emptyState("No repositories", "Synchronize GitHub before creating an application.", null, null);
      if (draft.step === 1) {
        var projectField = returnToProject ? '<input id="amAppProject" type="hidden" value=""><div class="am-readonly">Unassigned until the new project is created</div>' : '<select id="amAppProject"><option value="">No project</option>' + state.projects.map(function(project) { return '<option value="' + h(project.id) + '" ' + (project.id === draft.project_id ? "selected" : "") + '>' + h(project.name) + '</option>'; }).join("") + '</select>';
        return '<div class="am-form-grid"><div class="am-field am-field-full"><label for="amAppName">Application name</label><input id="amAppName" value="' + h(draft.name) + '" placeholder="orders-api"></div><div class="am-field am-field-full"><label for="amAppDescription">Description</label><textarea id="amAppDescription" placeholder="What does this application do?">' + h(draft.description) + '</textarea></div><div class="am-field am-field-full"><label for="amAppProject">Project</label>' + projectField + '</div></div>';
      }
      if (draft.step === 2) return '<div class="am-choice-grid"><button type="button" class="am-choice ' + (draft.type === "nextjs" ? "selected" : "") + '" data-wizard-type="nextjs"><span class="am-choice-icon">' + icon("world") + '</span><strong>Next.js Frontend</strong><div class="am-muted">Managed web application with HTTP health checks.</div></button><button type="button" class="am-choice ' + (draft.type === "rest-api" ? "selected" : "") + '" data-wizard-type="rest-api"><span class="am-choice-icon">' + icon("server") + '</span><strong>REST API</strong><div class="am-muted">Containerized HTTP API exposed through ServerPilot.</div></button></div>';
      if (draft.step === 3) {
        var repo = state.repositories.find(function(item) { return item.id === draft.repository_id; });
        var preview = repo && draft.name ? "ghcr.io/" + repo.owner.toLowerCase() + "/sp-" + repo.name.toLowerCase() + "-" + draft.name.toLowerCase().replace(/[^a-z0-9]+/g, "-") : "Generated after basics";
        return '<div class="am-form-grid"><div class="am-field"><label for="amAppDockerfile">Dockerfile path</label><input id="amAppDockerfile" value="' + h(draft.dockerfile) + '"></div><div class="am-field"><label for="amAppContext">Build context</label><input id="amAppContext" value="' + h(draft.build_context) + '"></div><div class="am-field"><label for="amAppPort">Container port</label><input id="amAppPort" type="number" min="1" max="65535" value="' + h(draft.container_port) + '"></div><div class="am-field"><label>GHCR image</label><input class="am-mono" value="' + h(preview) + '" readonly></div></div>';
      }
      if (draft.step === 4) return '<div class="am-alert">Names are customizable; every environment must be Test, Staging or Production.</div>' + draft.environments.map(function(env, index) { return '<div class="am-environment-editor" data-index="' + index + '"><div class="am-form-grid"><div class="am-field"><label>Name</label><input data-field="name" value="' + h(env.name) + '"></div><div class="am-field"><label>Type</label><select data-field="type">' + ["test", "staging", "production"].map(function(type) { return '<option ' + (type === env.type ? "selected" : "") + '>' + type + '</option>'; }).join("") + '</select></div></div><button class="am-button am-button-danger" type="button" data-remove-environment="' + index + '" style="margin-top:12px">Remove</button></div>'; }).join("") + '<button class="am-button" type="button" id="amAddEnvironment" style="margin-top:12px">' + icon("plus") + 'Add environment</button>';
      if (draft.step === 5) return draft.environments.map(function(env, index) { return '<div class="am-environment-editor" data-index="' + index + '"><h3>' + h(env.name) + ' ' + environmentChip(env) + '</h3><div class="am-form-grid"><div class="am-field"><label>Server</label><select data-field="agent"><option value="">This server</option>' + state.agents.filter(function(agent) { return agent.id !== "local"; }).map(function(agent) { return '<option value="' + h(agent.id) + '" ' + (agent.id === env.agent_id ? "selected" : "") + '>' + h(agent.name) + '</option>'; }).join("") + '</select></div><div class="am-field"><label>Domain</label><input data-field="domain" value="' + h(env.domain) + '" placeholder="app.example.com"></div><div class="am-field"><label>Health path</label><input data-field="health" value="' + h(env.health_path) + '"></div><div class="am-field"><label>Automatic deployment</label><select data-field="auto-mode"><option value="manual" ' + (env.auto_deploy_mode === "manual" ? "selected" : "") + '>Manual</option><option value="tag" ' + (env.auto_deploy_mode === "tag" ? "selected" : "") + '>On version tag</option><option value="release" ' + (env.auto_deploy_mode === "release" ? "selected" : "") + '>On published release</option></select><span class="am-field-help">Version tags must use semantic form such as v2.14.3.</span></div><div class="am-field"><label>Variables</label><textarea data-field="variables" placeholder="LOG_LEVEL=info">' + h(env.variables) + '</textarea></div><div class="am-field"><label>Secrets</label><textarea data-field="secrets" placeholder="DATABASE_URL=…">' + h(env.secrets) + '</textarea></div><div class="am-field"><label class="am-check"><input type="checkbox" data-field="site" ' + (env.site_enabled ? "checked" : "") + '> Managed site</label><label class="am-check"><input type="checkbox" data-field="ssl" ' + (env.ssl_enabled ? "checked" : "") + '> SSL</label></div></div></div>'; }).join("");
      if (draft.step === 6) return '<div class="am-list-panel"><div class="am-list-header"><div><h2 style="margin:0">Per-application GitHub Actions workflow</h2><div class="am-muted">Builds this application whenever a semantic version tag is pushed.</div></div>' + icon("brand-github") + '</div><div style="padding:20px"><p class="am-muted">The generated workflow never bakes runtime variables or secrets into the image. It publishes using the <span class="am-mono">sp-repository-application:&lt;version-tag&gt;</span> convention. ServerPilot verifies the GHCR image digest before any automatic deployment.</p></div></div>';
      return '<div class="am-form-grid"><div><span class="am-muted">Application</span><h3>' + h(draft.name) + '</h3></div><div><span class="am-muted">Type</span><h3>' + h(appTypeLabel(draft.type)) + '</h3></div><div><span class="am-muted">Repository</span><h3 class="am-mono">' + h((state.repositories.find(function(repo) { return repo.id === draft.repository_id; }) || {}).full_name || "") + '</h3></div><div><span class="am-muted">Project</span><h3>' + h((state.projects.find(function(project) { return project.id === draft.project_id; }) || {}).name || "No project") + '</h3></div></div><div class="am-card-rule"></div><div class="am-chips">' + draft.environments.map(environmentChip).join("") + '</div>';
    }
    function updateNext() { var next = document.getElementById("amWizardNext"); if (next) next.disabled = !valid(); }
    function renderStep() {
      var steps = titles.map(function(title, index) { return '<div class="am-wizard-step ' + (index < draft.step ? "complete" : index === draft.step ? "current" : "") + '"><span class="am-wizard-step-number">' + (index + 1) + '</span><span>' + h(title) + '</span></div>'; }).join("");
      content.innerHTML = '<div class="am-wizard-head"><div class="am-breadcrumb">Repositories &nbsp;›&nbsp; New application</div><h1>Create application</h1><p class="am-muted">Start from a repository, choose a type and configure environments. You can change operational settings later.</p></div><div class="am-wizard-layout"><aside class="am-wizard-steps">' + steps + '</aside><section class="am-wizard-panel"><header class="am-wizard-panel-head"><h2>' + h(titles[draft.step] === "Basics" ? "Basic details" : titles[draft.step]) + '</h2><p class="am-muted">' + h(descriptions[draft.step]) + '</p></header><div class="am-wizard-body">' + stepBody() + '</div><footer class="am-wizard-footer"><button class="am-button" type="button" id="amWizardBack" ' + (draft.step ? "" : "disabled") + '>' + icon("chevron-left") + 'Back</button><div class="am-wizard-footer-right"><button class="am-button am-button-primary" type="button" id="amWizardNext">' + (draft.step === 7 ? "Create application" : "Continue") + icon("chevron-right") + '</button></div></footer></section></div>';
      document.getElementById("amWizardBack").addEventListener("click", function() { collect(); draft.step--; renderStep(); });
      document.getElementById("amWizardNext").addEventListener("click", async function() { collect(); if (!valid()) return; if (draft.step === 7) { await save(); return; } draft.step++; renderStep(); });
      content.querySelectorAll("[data-wizard-repository]").forEach(function(item) { item.addEventListener("click", function() { draft.repository_id = item.dataset.wizardRepository; renderStep(); }); });
      content.querySelectorAll("[data-wizard-type]").forEach(function(item) { item.addEventListener("click", function() { draft.type = item.dataset.wizardType; renderStep(); }); });
      var activePanel = content.querySelector(".am-wizard-panel");
      activePanel.addEventListener("input", updateNext);
      activePanel.addEventListener("change", updateNext);
      var add = document.getElementById("amAddEnvironment");
      if (add) add.addEventListener("click", function() { collect(); draft.environments.push(newEnvironment("", "test")); renderStep(); });
      content.querySelectorAll("[data-remove-environment]").forEach(function(item) { item.addEventListener("click", function() { collect(); if (draft.environments.length === 1) { showToast("At least one environment is required", "error"); return; } draft.environments.splice(Number(item.dataset.removeEnvironment), 1); renderStep(); }); });
      updateNext();
    }
    async function save() {
      var next = document.getElementById("amWizardNext"); next.disabled = true;
      try {
        var payload = { repository_id: draft.repository_id, name: draft.name, description: draft.description, type: draft.type, dockerfile: draft.dockerfile, build_context: draft.build_context, container_port: draft.container_port, environments: draft.environments.map(function(env) { return { name: env.name, type: env.type, agent_id: env.agent_id || null, domain: env.domain, site_enabled: env.site_enabled, ssl_enabled: env.ssl_enabled, health_path: env.health_path, auto_deploy_mode: env.auto_deploy_mode, configuration: parseVariables(env.variables, false).concat(parseVariables(env.secrets, true)) }; }) };
        if (draft.project_id) payload.project_id = draft.project_id;
        var created = dataOf(await apiFetch("/api/app-manager/applications/create", { method: "POST", body: payload }));
        showToast("Application created", "success"); await fetchAll(true);
        if (returnToProject) projectDialog(created.id); else renderApplicationDetail(created.id);
      } catch (err) { showToast(err.message, "error"); next.disabled = false; }
    }
    renderStep();
  }

  function configurationDialog(ownerType, ownerID, title) {
    apiFetch("/api/app-manager/configuration?owner_type=" + encodeURIComponent(ownerType) + "&owner_id=" + encodeURIComponent(ownerID)).then(function(response) {
      var entries = dataOf(response) || [];
      var variables = entries.filter(function(entry) { return !entry.secret; }).map(function(entry) { return entry.key + "=" + entry.value; }).join("\n");
      var secrets = entries.filter(function(entry) { return entry.secret; }).map(function(entry) { return entry.key + "=KEEP_EXISTING_SECRET"; }).join("\n");
      openDialog("Configuration", title, '<div class="am-alert">Secrets are write-only. Saving replaces the complete configuration set.</div><div class="am-form-grid" style="margin-top:16px"><div class="am-field"><label for="amConfigVariables">Variables</label><textarea id="amConfigVariables">' + h(variables) + '</textarea></div><div class="am-field"><label for="amConfigSecrets">Secrets</label><textarea id="amConfigSecrets" placeholder="SECRET_KEY=new value">' + h(secrets) + '</textarea></div></div>', '<button class="am-button" value="cancel">Cancel</button><button class="am-button am-button-primary" type="button" id="amSaveConfiguration">Save configuration</button>');
      document.getElementById("amSaveConfiguration").addEventListener("click", async function() {
        try {
          var secretEntries = parseVariables(document.getElementById("amConfigSecrets").value, true);
          if (secretEntries.some(function(entry) { return entry.value === "KEEP_EXISTING_SECRET"; })) throw new Error("Replace placeholder secrets with new values or remove their lines");
          await apiFetch("/api/app-manager/configuration/replace", { method: "POST", body: { owner_type: ownerType, owner_id: ownerID, entries: parseVariables(document.getElementById("amConfigVariables").value, false).concat(secretEntries) } });
          closeDialog(); showToast("Configuration saved", "success");
          if (state.currentApplicationID) renderApplicationDetail(state.currentApplicationID, "configuration", ownerType === "environment" ? ownerID : "");
        } catch (err) { showToast(err.message, "error"); }
      });
    }).catch(function(err) { showToast(err.message, "error"); });
  }

  function deployPolicyDialog(environmentID, currentMode) {
    var body = '<div class="am-field"><label for="amDeployPolicy">Automatic deployment</label><select id="amDeployPolicy"><option value="manual" ' + (currentMode === "manual" ? "selected" : "") + '>Manual</option><option value="tag" ' + (currentMode === "tag" ? "selected" : "") + '>On version tag</option><option value="release" ' + (currentMode === "release" ? "selected" : "") + '>On published release</option></select><span class="am-field-help">Images are verified in GHCR and resolved to an immutable digest before deployment.</span></div>';
    openDialog("Deployment", "Choose deploy policy", body, '<button class="am-button" value="cancel">Cancel</button><button class="am-button am-button-primary" type="button" id="amSaveDeployPolicy">Save policy</button>');
    document.getElementById("amSaveDeployPolicy").addEventListener("click", async function() {
      try {
        await apiFetch("/api/app-manager/environments/deploy-policy", { method: "POST", body: { environment_id: environmentID, mode: document.getElementById("amDeployPolicy").value } });
        closeDialog();
        showToast("Deploy policy updated", "success");
        await renderEnvironmentDetail(state.currentApplicationID, environmentID);
      } catch (err) { showToast(err.message, "error"); }
    });
  }

  function pairAgentDialog() {
    openDialog("Remote server", "Pair ServerPilot agent", '<div class="am-field"><label for="amAgentName">Server name</label><input id="amAgentName" placeholder="prod-us-east-1"></div><div id="amPairingResult" style="margin-top:14px"></div>', '<button class="am-button" value="cancel">Close</button><button class="am-button am-button-primary" type="button" id="amCreatePairingToken">Generate pairing token</button>');
    document.getElementById("amCreatePairingToken").addEventListener("click", async function() {
      try {
        var name = document.getElementById("amAgentName").value.trim();
        var result = dataOf(await apiFetch("/api/app-manager/agents/pairing-token", { method: "POST", body: { name: name } }));
        var command = "sudo sp agent pair --controller " + window.location.origin + " --name " + name + " --token " + result.token;
        document.getElementById("amPairingResult").innerHTML = '<div class="am-alert">One-time token expires ' + h(new Date(result.expires_at).toLocaleTimeString()) + '</div><pre class="am-mono" id="amPairCommand" style="white-space:pre-wrap;background:var(--am-ink);padding:12px;border-radius:8px"></pre><button class="am-button" type="button" id="amCopyPairCommand">Copy command</button>';
        document.getElementById("amPairCommand").textContent = command;
        document.getElementById("amCopyPairCommand").addEventListener("click", function() { navigator.clipboard.writeText(command).then(function() { showToast("Pairing command copied", "success"); }); });
      } catch (err) { showToast(err.message, "error"); }
    });
  }

  async function reload() { state.loaded = false; await fetchAll(true); renderCurrent(); }
  async function action(target) {
    var name = target.dataset.amAction;
    if (!name) return;
    if (name === "applications") { renderApplications(); return; }
    if (name === "retry") { loading(); try { await reload(); } catch (err) { errorState(err.message); } return; }
    if (name === "configure-github") { githubDialog(); return; }
    if (name === "create-project") { projectDialog(); return; }
    if (name === "create-application") {
      var returnToProject = target.dataset.returnToProject === "true";
      if (returnToProject) captureProjectDraft();
      closeDialog();
      applicationWizard(target.dataset.repositoryId || "", returnToProject);
      return;
    }
    if (name === "sync-github") {
      target.disabled = true;
      try { await apiFetch("/api/app-manager/github/sync", { method: "POST", body: {} }); showToast("Repositories and versions synchronized", "success"); await reload(); } catch (err) { showToast(err.message, "error"); target.disabled = false; }
      return;
    }
    if (name === "pair-agent") { pairAgentDialog(); return; }
    if (name === "configure-environment") { configurationDialog("environment", target.dataset.environmentId, "Environment variables"); return; }
    if (name === "deploy-policy") { deployPolicyDialog(target.dataset.environmentId, target.dataset.deployMode); return; }
    if (name === "configure-project") { configurationDialog("project", target.dataset.projectId, "Project global variables"); return; }
    if (name === "check-artifacts") { try { await apiFetch("/api/app-manager/artifacts/check", { method: "POST", body: {} }); showToast("Registry images checked", "success"); await renderApplicationDetail(content.dataset.applicationId); } catch (err) { showToast(err.message, "error"); } return; }
    if (name === "copy-workflow") { try { var workflowApplicationID = target.dataset.applicationId || content.dataset.applicationId; if (!workflowApplicationID) throw new Error("Choose an application first"); var result = dataOf(await apiFetch("/api/app-manager/applications/workflow?application_id=" + encodeURIComponent(workflowApplicationID))); await copyText(result.workflow); showToast("Workflow copied", "success"); } catch (err) { showToast(err.message, "error"); } return; }
    if (name === "deploy") {
      if (!target.dataset.artifactId || !window.confirm("Deploy this version image to the selected environment?")) return;
      target.disabled = true;
      try { await apiFetch("/api/app-manager/deployments/create", { method: "POST", body: { environment_id: target.dataset.environmentId, artifact_id: target.dataset.artifactId, trigger: "manual" } }); showToast("Deployment started", "success"); await reload(); } catch (err) { showToast(err.message, "error"); target.disabled = false; }
      return;
    }
    if (name === "rollback") {
      if (!window.confirm("Roll back this environment to its previous successful image?")) return;
      target.disabled = true;
      try { var deployment = dataOf(await apiFetch("/api/app-manager/deployments/rollback", { method: "POST", body: { environment_id: target.dataset.environmentId } })); showToast("Rollback started", "success"); await renderDeploymentDetail(deployment.id); } catch (err) { showToast(err.message, "error"); target.disabled = false; }
    }
  }

  root.addEventListener("click", function(event) {
    var copyRepository = event.target.closest("[data-copy-repository]");
    if (copyRepository) {
      event.preventDefault();
      event.stopPropagation();
      copyText(copyRepository.dataset.copyRepository).then(function() { showToast("Repository name copied", "success"); }).catch(function(err) { showToast(err.message, "error"); });
      return;
    }
    var actionTarget = event.target.closest("[data-am-action]"); if (actionTarget) { action(actionTarget); return; }
    var viewTarget = event.target.closest("[data-am-view]"); if (viewTarget) { state.view = viewTarget.dataset.amView; closeMobileSidebar(); renderCurrent(); return; }
    var filterTarget = event.target.closest("[data-am-filter]"); if (filterTarget) { state.applicationFilter = filterTarget.dataset.amFilter; renderApplications(); return; }
    var configEnvironment = event.target.closest("[data-config-environment]"); if (configEnvironment) { renderApplicationDetail(configEnvironment.dataset.applicationId, "configuration", configEnvironment.dataset.configEnvironment); return; }
    var tabTarget = event.target.closest("[data-app-tab]"); if (tabTarget) { renderApplicationDetail(tabTarget.dataset.applicationId, tabTarget.dataset.appTab); return; }
    var environmentTarget = event.target.closest("[data-environment-id]"); if (environmentTarget && environmentTarget.dataset.parentApplicationId) { renderEnvironmentDetail(environmentTarget.dataset.parentApplicationId, environmentTarget.dataset.environmentId); return; }
    var backApplication = event.target.closest("[data-back-application]"); if (backApplication) { renderApplicationDetail(backApplication.dataset.backApplication, "environments"); return; }
    var deploymentTarget = event.target.closest("[data-deployment-id]"); if (deploymentTarget) { renderDeploymentDetail(deploymentTarget.dataset.deploymentId); return; }
    var releaseTarget = event.target.closest("[data-release-id]"); if (releaseTarget) { renderReleaseDetail(releaseTarget.dataset.releaseId); return; }
    var appTarget = event.target.closest("[data-application-id]"); if (appTarget) { renderApplicationDetail(appTarget.dataset.applicationId); closeMobileSidebar(); return; }
    var projectTarget = event.target.closest("[data-project-id]"); if (projectTarget) { renderProjectDetail(projectTarget.dataset.projectId); closeMobileSidebar(); }
  });

  document.getElementById("amProjectSelector").addEventListener("click", function() { setSidebarSection("projects", this.getAttribute("aria-expanded") !== "true"); });
  document.getElementById("amApplicationSelector").addEventListener("click", function() { setSidebarSection("applications", this.getAttribute("aria-expanded") !== "true"); });
  function filterOptions(inputID, containerID) {
    document.getElementById(inputID).addEventListener("input", function() {
      var query = this.value.toLowerCase();
      document.querySelectorAll("#" + containerID + " .am-selector-option").forEach(function(item) { item.hidden = !item.textContent.toLowerCase().includes(query); });
    });
  }
  filterOptions("amProjectSearch", "amProjectOptions");
  filterOptions("amApplicationSearch", "amApplicationOptions");
  document.getElementById("amGlobalSearch").addEventListener("input", function() { state.query = this.value.trim(); if (state.view === "repositories") renderRepositories(); else renderApplications(); });
  document.addEventListener("keydown", function(event) {
    if (event.key === "Escape") closeMobileSidebar();
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k" && root.classList.contains("active")) { event.preventDefault(); document.getElementById("amGlobalSearch").focus(); }
  });
  function openMobileSidebar() { root.classList.add("sidebar-open"); document.getElementById("amMobileMenu").setAttribute("aria-expanded", "true"); }
  function closeMobileSidebar() { root.classList.remove("sidebar-open"); document.getElementById("amMobileMenu").setAttribute("aria-expanded", "false"); }
  document.getElementById("amMobileMenu").addEventListener("click", openMobileSidebar);
  document.getElementById("amSidebarClose").addEventListener("click", closeMobileSidebar);
  document.getElementById("amSidebarBackdrop").addEventListener("click", closeMobileSidebar);

  window.loadApplicationManager = async function(options) {
    options = options || {};
    // The shell calls tab loaders when switching modules. The Application
    // Manager DOM is already preserved, so loading it again would destroy the
    // current detail view or an in-progress wizard draft.
    if (state.loaded && !options.force) return;
    if (state.loaded && (state.view === "wizard" || dialog.open)) {
      if (options.manual) showToast("Finish or cancel the open form before refreshing", "warning");
      return;
    }
    loading();
    try { await fetchAll(options.force); renderCurrent(); }
    catch (err) { errorState(err.message); }
  };
  window.openApplicationManagerSettings = function(prefillDomain) {
    state.view = "settings";
    renderCurrent();
    window.setTimeout(function() {
      var input = document.getElementById("settingsDomainInput");
      if (!input) return;
      if (prefillDomain && !input.value) input.value = prefillDomain;
      input.focus();
    }, 50);
  };
  window.SP.loadApplicationManager = window.loadApplicationManager;
})();
