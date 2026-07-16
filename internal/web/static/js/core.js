/* ServerPilot dashboard core: helpers, state, auth, tabs */
"use strict";

window.SP = window.SP || {};

  // ── Helpers ──
  function esc(str) {
    var d = document.createElement("div");
    d.textContent = str;
    return d.innerHTML;
  }

  function setText(el, text) {
    if (el) el.textContent = text;
  }

  function onEl(id, event, handler) {
    var el = document.getElementById(id);
    if (el) el.addEventListener(event, handler);
    return el;
  }

  (function initNavbarMoreMenu() {
    var moreBtn = document.getElementById("navbarMoreBtn");
    var secondary = document.getElementById("navbarSecondary");
    if (!moreBtn || !secondary) return;

    function closeMenu() {
      secondary.classList.remove("open");
      moreBtn.setAttribute("aria-expanded", "false");
    }

    moreBtn.addEventListener("click", function(e) {
      e.stopPropagation();
      var open = secondary.classList.toggle("open");
      moreBtn.setAttribute("aria-expanded", open ? "true" : "false");
    });

    document.addEventListener("click", function(e) {
      if (!secondary.classList.contains("open")) return;
      if (moreBtn.contains(e.target) || secondary.contains(e.target)) return;
      closeMenu();
    });

    document.addEventListener("keydown", function(e) {
      if (e.key === "Escape") closeMenu();
    });

    secondary.addEventListener("click", function() {
      if (window.matchMedia("(min-width: 1024px)").matches) return;
      closeMenu();
    });
  })();

  function escapeHtml(str) {
    var div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  function showToast(message, type) {
    var container = document.getElementById("toastContainer");
    var toast = document.createElement("div");
    toast.className = "toast toast-" + type;
    var icon = document.createElement("span");
    icon.className = "toast-icon";
    setText(icon, type === "success" ? "\u2713" : "\u2717");
    var msg = document.createElement("span");
    setText(msg, message);
    toast.appendChild(icon);
    toast.appendChild(msg);
    container.appendChild(toast);
    setTimeout(function() {
      toast.classList.add("removing");
      setTimeout(function() { toast.remove(); }, 300);
    }, 4000);
  }

  function prepareApiFetchOptions(opts) {
    opts = opts || {};
    var prepared = Object.assign({}, opts);
    prepared.credentials = "same-origin";
    // Client identity headers — always sent on every API call.
    // The backend logs any request that arrives without these as a potential scanner/bot.
    prepared.headers = Object.assign({
      "X-SP-Client": "dashboard",
      "X-SP-Build": "1",
      "X-SP-Source": "ui"
    }, opts.headers || {});
    if (prepared.body && typeof prepared.body === "object" && !(prepared.body instanceof FormData)) {
      prepared.headers["Content-Type"] = "application/json";
      prepared.body = JSON.stringify(prepared.body);
    }
    return prepared;
  }

  var reauthInFlight = null;

  async function promptReauth() {
    if (reauthInFlight) return reauthInFlight;
    reauthInFlight = (async function() {
      if (settingsData && settingsData.email_login_enabled && window.confirm("Use email code for reauthentication? Cancel to use password.")) {
        await apiFetchInternal("/api/session/reauth/email/request-code", { method: "POST", body: {} }, false);
        var emailCode = window.prompt("Enter the 6-digit email code.");
        if (!emailCode) throw new Error("reauthentication cancelled");
        await apiFetchInternal("/api/session/reauth/email/verify-code", {
          method: "POST",
          body: { code: emailCode.trim() }
        }, false);
        showToast("Reauthenticated", "success");
        return;
      }
      var password = window.prompt("Re-enter your ServerPilot admin password to continue.");
      if (!password) throw new Error("reauthentication cancelled");
      var mfaCode = "";
      if (settingsData && settingsData.mfa_enabled) {
        mfaCode = window.prompt("Enter your 6-digit MFA code.");
        if (!mfaCode) throw new Error("MFA code required");
      }
      await apiFetchInternal("/api/session/reauth", {
        method: "POST",
        body: { password: password, mfa_code: mfaCode }
      }, false);
      showToast("Reauthenticated", "success");
    })();
    try { return await reauthInFlight; }
    finally { reauthInFlight = null; }
  }

  async function apiFetch(url, opts) {
    return apiFetchInternal(url, opts, true);
  }

  async function apiFetchInternal(url, opts, allowReauth) {
    var resp = await fetch(url, prepareApiFetchOptions(opts));
    if (resp.status === 401) {
      showLogin();
      throw new Error("Unauthorized");
    }
    if (!resp.ok) {
      var errText = "";
      // Read body as text first; resp.json() on empty body throws
      // "Unexpected end of input" which we don't want propagating.
      try {
        var bodyText = await resp.text();
        if (bodyText && bodyText.trim()) {
          try {
            var j = JSON.parse(bodyText);
            errText = j.error || j.message || resp.statusText;
          } catch(e) {
            errText = resp.statusText || bodyText.slice(0, 200);
          }
        } else {
          errText = resp.statusText || "request failed";
        }
      } catch(e) {
        errText = resp.statusText || "request failed";
      }
      if (resp.status === 403 && errText === "recent reauthentication required" && allowReauth) {
        await promptReauth();
        return apiFetchInternal(url, opts, false);
      }
      throw new Error(errText);
    }
    var ct = resp.headers.get("content-type") || "";
    if (ct.includes("application/json")) {
      // Defensive: a 200 with Content-Type:application/json but an empty
      // body would make resp.json() throw "Unexpected end of input" and
      // the calling code would see that as an Uncaught SyntaxError. Read
      // as text and parse only when there is actually something to parse.
      var raw = await resp.text();
      if (!raw || !raw.trim()) return null;
      try { return JSON.parse(raw); }
      catch(e) {
        throw new Error("invalid JSON response from server");
      }
    }
    return null;
  }

  // ── State ──
  var containers = [];
  var sites = [];
  var mappings = { mapped: [], unmappedContainers: [], orphanedSites: [], dashboardSites: [] };
  var containerLabels = {}; // { containerName: "api"|"nestjs"|"back" }
  var containerReplicas = [];
  var _replicaPreview = null;
  var _replicaMode = "create";
  var _replicaSyncName = "";
  var editEnvEditor = null;
  var createAppEnvEditor = null;
  var createEnvFileEditor = null;
  var replicaEnvEditor = null;
  var settingsData = {
    domain: "",
    ssl_enabled: false,
    insecure_blocked: false,
    host_guard: false,
    mfa_enabled: false,
    email_login_enabled: false,
    email_login_address: "",
    email_delivery_url: "",
    email_delivery_scope: "auth",
    email_delivery_template: "serverpilot_login_code",
    email_delivery_timeout_sec: 5,
    email_delivery_token_configured: false,
    port: 0
  };
  var pendingMFASecret = "";

  // Shared fetch cache: dedupes in-flight requests (O(1) keys) and reuses a
  // short-lived snapshot so tab switches / modal refreshes avoid repeat API work.
  SP.cache = SP.cache || {};
  SP.inFlight = SP.inFlight || {};
  var CORE_CACHE_MS = 4000;

  function apiList(resp) {
    if (resp && resp.data) return resp.data;
    return Array.isArray(resp) ? resp : [];
  }

  function mappingsFromPayload(mappingsData) {
    mappingsData = mappingsData || {};
    return {
      mapped: mappingsData.mapped || [],
      unmappedContainers: mappingsData.unmappedContainers || [],
      orphanedSites: mappingsData.orphanedSites || [],
      dashboardSites: mappingsData.dashboardSites || [],
      standalone_redirects: mappingsData.standalone_redirects || [],
      unassigned_sites: mappingsData.unassigned_sites || []
    };
  }

  function applyDashboardCoreState(core) {
    containers = core.containers || [];
    sites = core.sites || [];
    mappings = mappingsFromPayload(core.mappingsData);
    window.containers = containers;
    window.sites = sites;
    window.mappings = mappings;
  }

  function invalidateDashboardCoreCache() {
    delete SP.cache.dashboardCore;
    delete SP.inFlight.dashboardCore;
    delete SP.cache.composeProjects;
    delete SP.inFlight.composeProjects;
  }

  async function fetchDashboardCore(opts) {
    var force = opts && opts.force;
    var key = "dashboardCore";
    var now = Date.now();
    if (!force && SP.cache[key] && (now - SP.cache[key].ts) < CORE_CACHE_MS) {
      return SP.cache[key].value;
    }
    if (!force && SP.inFlight[key]) {
      return SP.inFlight[key];
    }
    SP.inFlight[key] = Promise.all([
      apiFetch("/api/containers"),
      apiFetch("/api/sites"),
      apiFetch("/api/mappings"),
      loadLabels(),
      loadReplicas()
    ]).then(function(results) {
      var value = {
        containers: apiList(results[0]),
        sites: apiList(results[1]),
        mappingsData: (results[2] && results[2].data) ? results[2].data : results[2]
      };
      SP.cache[key] = { ts: Date.now(), value: value };
      delete SP.inFlight[key];
      return value;
    }).catch(function(err) {
      delete SP.inFlight[key];
      throw err;
    });
    return SP.inFlight[key];
  }

  async function fetchComposeProjects(opts) {
    var force = opts && opts.force;
    var key = "composeProjects";
    var now = Date.now();
    if (!force && SP.cache[key] && (now - SP.cache[key].ts) < CORE_CACHE_MS) {
      return SP.cache[key].value;
    }
    if (!force && SP.inFlight[key]) {
      return SP.inFlight[key];
    }
    SP.inFlight[key] = apiFetch("/api/compose/projects").catch(function() {
      return { data: [] };
    }).then(function(resp) {
      var value = (resp && resp.data) ? resp.data : [];
      SP.cache[key] = { ts: Date.now(), value: value };
      delete SP.inFlight[key];
      return value;
    }).catch(function(err) {
      delete SP.inFlight[key];
      throw err;
    });
    return SP.inFlight[key];
  }

  function showSpinner(el) {
    if (!el) return;
    el.innerHTML = "";
    var s = document.createElement("div");
    s.className = "spinner";
    var ring = document.createElement("div");
    ring.className = "spinner-ring";
    s.appendChild(ring);
    s.appendChild(document.createTextNode("Loading..."));
    el.appendChild(s);
  }

  window.invalidateDashboardCoreCache = invalidateDashboardCoreCache;
  window.fetchDashboardCore = fetchDashboardCore;
  window.fetchComposeProjects = fetchComposeProjects;
  window.applyDashboardCoreState = applyDashboardCoreState;
  window.showSpinner = showSpinner;

  function initEnvEditors() {
    if (!editEnvEditor && document.getElementById("editEnvEditorRoot")) {
      editEnvEditor = EnvEditor.mount(document.getElementById("editEnvEditorRoot"), {
        defaultFriendly: false,
        textareaStyle: "width:100%;height:320px;padding:0.75rem;background:var(--bg-primary);border:1px solid var(--border);border-radius:8px;color:var(--text-primary);font-family:monospace;font-size:0.8125rem;resize:vertical;box-sizing:border-box;line-height:1.6;"
      });
    }
    if (!createAppEnvEditor && document.getElementById("createAppEnvEditorRoot")) {
      createAppEnvEditor = EnvEditor.mount(document.getElementById("createAppEnvEditorRoot"), {
        defaultFriendly: false
      });
    }
    if (!createEnvFileEditor && document.getElementById("createEnvFileEditorRoot")) {
      createEnvFileEditor = EnvEditor.mount(document.getElementById("createEnvFileEditorRoot"), {
        defaultFriendly: false
      });
    }
    if (!replicaEnvEditor && document.getElementById("replicaEnvEditorRoot")) {
      replicaEnvEditor = EnvEditor.mount(document.getElementById("replicaEnvEditorRoot"), {
        defaultFriendly: true
      });
    }
  }

  initEnvEditors();
  var images = [];
  var selectedImageIDs = {};
  var activeTab = "containers";

  // Tab load functions — each loads data for its tab.
  var tabLoaders = {
    containers: function(opts) { return loadContainers(opts); },
    sites:      function(opts) { return loadSites(opts); },
    images:     function(opts) { return loadImages(opts); },
    mappings:   function(opts) { return loadMappings(opts); },
    resources:  function(opts) { return loadResources(opts); },
    apps:       function(opts) { loadManagedApps(); loadDependencies(); return loadApps(); },
    users:      function(opts) { loadSystemUsers(); return loadDeployUsers(); },
    cases:      function(opts) { return loadCases(); },
    db:         function(opts) { return loadDBConnections(); },
    settings:   function(opts) { return loadSettings(); }
  };

  // ── Single global auto-refresh: fixed 30s, active tab only ──
  // No per-tab configurable timers — simpler, less memory pressure,
  // and prevents aggressive polling that causes gradual RSS growth.
  var globalRefreshTimer = null;
  var REFRESH_INTERVAL = 30000; // 30 seconds, fixed

  function startGlobalRefresh() {
    stopGlobalRefresh();
    globalRefreshTimer = setInterval(function() {
      // Skip auto-refresh for tabs that only need manual refresh.
      var noAutoRefresh = { apps: true, cases: true };
      if (activeTab && tabLoaders[activeTab] && !noAutoRefresh[activeTab]) {
        tabLoaders[activeTab]({ silent: true });
      }
    }, REFRESH_INTERVAL);
  }

  function stopGlobalRefresh() {
    if (globalRefreshTimer) { clearInterval(globalRefreshTimer); globalRefreshTimer = null; }
  }

  function updateTabTimestamp(tab) {
    var el = document.getElementById("ts-" + tab);
    if (el) setText(el, "Updated: " + new Date().toLocaleTimeString());
  }

  // ── Login / Logout ──

  // SECURITY: If credentials leaked into the URL as query params (e.g. from a
  // browser autofill bug, bookmark, or direct link), strip them immediately so
  // they don't persist in browser history, server logs, or the Referer header.
  (function() {
    var params = new URLSearchParams(window.location.search);
    if (params.has("username") || params.has("password")) {
      params.delete("username");
      params.delete("password");
      var cleanURL = window.location.pathname + (params.toString() ? "?" + params.toString() : "");
      window.history.replaceState({}, "", cleanURL);
    }
  })();

  var loginScreen = document.getElementById("loginScreen");
  var dashboard = document.getElementById("dashboard");
  var loginOptions = { email_login_enabled: false };

  // Both screens start hidden via CSS (display:none) to prevent login flash on reload.
  // showLogin() or showDashboard() will reveal the correct one after init() checks the session.

  function showLogin() {
    loginScreen.style.display = "flex";
    dashboard.style.display = "none";
    stopGlobalRefresh();
    if (window.SP && SP.jobs && SP.jobs.stop) SP.jobs.stop();
    loadLoginOptions();
  }

  function showDashboard() {
    loginScreen.style.display = "none";
    dashboard.style.display = "block";
    loadRollbackInfo();
    // Load the active tab immediately, then start the 30s refresh cycle.
    if (tabLoaders[activeTab]) tabLoaders[activeTab]();
    startGlobalRefresh();
    // Begin watching background operations (unified process center).
    if (window.SP && SP.jobs && SP.jobs.start) SP.jobs.start();
  }

  async function loadLoginOptions() {
    try {
      var resp = await apiFetch("/api/login/options");
      loginOptions = (resp && resp.data) ? resp.data : (resp || loginOptions);
    } catch(e) {
      loginOptions = { email_login_enabled: false };
    }
    var box = document.getElementById("emailLoginBox");
    if (box) box.style.display = loginOptions.email_login_enabled ? "block" : "none";
  }

  onEl("loginForm", "submit", async function(e) {
    e.preventDefault();
    var errEl = document.getElementById("loginError");
    errEl.style.display = "none";
    var btn = document.getElementById("loginBtn");
    btn.disabled = true;
    setText(btn, "Signing in...");
    try {
      await apiFetch("/api/login", {
        method: "POST",
        body: {
          username: document.getElementById("username").value,
          password: document.getElementById("password").value,
          mfa_code: document.getElementById("mfaCode").value.trim()
        }
      });
      showDashboard();
    } catch(err) {
      errEl.style.display = "block";
      setText(errEl, err.message === "Unauthorized" ? "Invalid credentials" : err.message);
    } finally {
      btn.disabled = false;
      setText(btn, "Sign In");
    }
  });

  onEl("emailLoginToggleBtn", "click", function() {
    var panel = document.getElementById("emailLoginPanel");
    if (!panel) return;
    panel.style.display = panel.style.display === "none" ? "block" : "none";
  });

  onEl("emailLoginRequestBtn", "click", async function() {
    var errEl = document.getElementById("loginError");
    errEl.style.display = "none";
    var btn = this;
    var email = document.getElementById("emailLoginEmail").value.trim();
    if (!email) {
      errEl.style.display = "block";
      setText(errEl, "Enter your email first");
      return;
    }
    btn.disabled = true;
    setText(btn, "Sending...");
    try {
      await apiFetch("/api/login/email/request-code", { method: "POST", body: { email: email } });
      document.getElementById("emailLoginCodeBox").style.display = "block";
      setText(errEl, "If email login is configured, a code was sent.");
      errEl.style.display = "block";
    } catch(err) {
      errEl.style.display = "block";
      setText(errEl, "Could not request email code");
    } finally {
      btn.disabled = false;
      setText(btn, "Send Code");
    }
  });

  onEl("emailLoginVerifyBtn", "click", async function() {
    var errEl = document.getElementById("loginError");
    errEl.style.display = "none";
    var btn = this;
    btn.disabled = true;
    setText(btn, "Verifying...");
    try {
      await apiFetch("/api/login/email/verify-code", {
        method: "POST",
        body: {
          email: document.getElementById("emailLoginEmail").value.trim(),
          code: document.getElementById("emailLoginCode").value.trim()
        }
      });
      showDashboard();
    } catch(err) {
      errEl.style.display = "block";
      setText(errEl, "Invalid or expired code");
    } finally {
      btn.disabled = false;
      setText(btn, "Verify Code");
    }
  });

  onEl("logoutBtn", "click", async function() {
    try { await apiFetch("/api/logout", { method: "POST" }); } catch(e) {}
    showLogin();
  });

  // ── Navbar (bind early so a later init error cannot disable these) ──
  function copyTextToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function(resolve, reject) {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      try { document.execCommand("copy") ? resolve() : reject(new Error("copy failed")); }
      catch(e) { reject(e); }
      finally { document.body.removeChild(ta); }
    });
  }

  async function checkForUpdates() {
    var checkBtn = document.getElementById("checkUpdatesBtn");
    if (!checkBtn) {
      showToast("Check Updates unavailable — hard refresh (Ctrl+Shift+R)", "error");
      return;
    }
    checkBtn.disabled = true;
    setText(checkBtn, "Checking...");
    try {
      var resp = await apiFetch("/api/version-check");
      var data = resp && resp.data ? resp.data : resp;
      if (data && data.update_available) {
        var banner = document.getElementById("updateBanner");
        var vText = document.getElementById("updateVersionText");
        setText(vText, "v" + data.current + " \u2192 v" + data.latest);
        if (banner) banner.style.display = "flex";
        checkBtn.style.display = "none";
        showToast("New version v" + data.latest + " available!", "success");
      } else {
        showToast("You are up to date (v" + (data ? data.current : "?") + ")", "success");
      }
    } catch(e) {
      showToast("Failed to check for updates: " + e.message, "error");
    } finally {
      checkBtn.disabled = false;
      setText(checkBtn, "\uD83D\uDD0D Check Updates");
    }
  }

  async function copyPublicIp() {
    var btn = document.getElementById("copyPublicIpBtn");
    if (!btn) {
      showToast("Copy IP unavailable — hard refresh (Ctrl+Shift+R)", "error");
      return;
    }
    btn.disabled = true;
    var original = "\uD83D\uDCCB Copy IP";
    setText(btn, "Loading...");
    try {
      var resp = await apiFetch("/api/system");
      var data = resp && resp.data ? resp.data : resp;
      var ip = data && data.public_ip;
      if (!ip) {
        showToast("Public IP unavailable", "error");
        return;
      }
      await copyTextToClipboard(ip);
      showToast("Public IP copied: " + ip, "success");
    } catch(e) {
      showToast("Failed to copy IP: " + e.message, "error");
    } finally {
      btn.disabled = false;
      setText(btn, original);
    }
  }

  onEl("checkUpdatesBtn", "click", checkForUpdates);
  onEl("copyPublicIpBtn", "click", copyPublicIp);
  onEl("refreshBtn", "click", function() {
    if (tabLoaders[activeTab]) tabLoaders[activeTab]();
  });
  onEl("updateBtn", "click", async function() {
    var btn = document.getElementById("updateBtn");
    if (!btn) return;
    btn.disabled = true;
    setText(btn, "Updating...");
    try {
      var resp = await apiFetch("/api/update", { method: "POST" });
      var data = resp && resp.data ? resp.data : resp;
      showToast(data.message || "Update complete", "success");
      var banner = document.getElementById("updateBanner");
      var checkBtn = document.getElementById("checkUpdatesBtn");
      if (banner) banner.style.display = "none";
      if (checkBtn) checkBtn.style.display = "";
      setTimeout(function() { window.location.reload(); }, 3000);
    } catch(err) {
      showToast("Update failed: " + err.message, "error");
      btn.disabled = false;
      setText(btn, "Update");
    }
  });
  window.checkForUpdates = checkForUpdates;

  // ── Rollback ──
  async function loadRollbackInfo() {
    try {
      var resp = await apiFetch("/api/rollback/info");
      var data = resp && resp.data ? resp.data : resp;
      var prev = data && data.previous_version;
      var banner = document.getElementById("rollbackBanner");
      var vText  = document.getElementById("rollbackVersionText");
      if (prev && banner && vText) {
        setText(vText, "Rollback to v" + prev);
        banner.style.display = "flex";
      } else if (banner) {
        banner.style.display = "none";
      }
    } catch(_) { /* non-fatal */ }
  }

  onEl("rollbackBtn", "click", async function() {
    var btn = document.getElementById("rollbackBtn");
    var vText = document.getElementById("rollbackVersionText");
    var targetVersion = vText ? vText.textContent.replace("Rollback to ", "") : "the previous version";
    if (!confirm("Roll back to " + targetVersion + "? The server will restart.")) return;
    if (!btn) return;
    btn.disabled = true;
    setText(btn, "Rolling back...");
    try {
      var resp = await apiFetch("/api/rollback", { method: "POST" });
      var data = resp && resp.data ? resp.data : resp;
      showToast(data.message || "Rollback complete", "success");
      document.getElementById("rollbackBanner").style.display = "none";
      setTimeout(function() { window.location.reload(); }, 3500);
    } catch(err) {
      showToast("Rollback failed: " + err.message, "error");
      btn.disabled = false;
      setText(btn, "Rollback");
    }
  });

  // ── Tabs ──
  document.querySelectorAll(".tab-btn").forEach(function(btn) {
    btn.addEventListener("click", function() {
      document.querySelectorAll(".tab-btn").forEach(function(b) { b.classList.remove("active"); });
      document.querySelectorAll(".tab-panel").forEach(function(p) { p.classList.remove("active"); });
      btn.classList.add("active");
      activeTab = btn.dataset.tab;
      document.getElementById("panel-" + activeTab).classList.add("active");
      // Immediately load data for the selected tab (click = manual refresh).
      if (tabLoaders[activeTab]) tabLoaders[activeTab]();
    });
  });

  // ── Data Loading ──

  // ── Containers ──
