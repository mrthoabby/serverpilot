/* Settings + keyboard shortcuts */
"use strict";

  async function loadSettings() {
    try {
      var resp = await apiFetch("/api/settings");
      var data = (resp && resp.data) ? resp.data : resp;
      settingsData = data || settingsData;
    } catch(err) {
      // Ignore — will show default state.
    }
    renderSettings();
  }

  function renderSettings() {
    var domainInput = document.getElementById("settingsDomainInput");
    var domainBtn = document.getElementById("settingsDomainBtn");
    var domainStatus = document.getElementById("settingsDomainStatus");
    var sslBtn = document.getElementById("settingsSSLBtn");
    var sslStatus = document.getElementById("settingsSSLStatus");
    var blockBtn = document.getElementById("settingsBlockBtn");
    var blockStatus = document.getElementById("settingsBlockStatus");
    var hostGuardBtn = document.getElementById("settingsHostGuardBtn");
    var hostGuardStatus = document.getElementById("settingsHostGuardStatus");
    var hostGuardNum = document.getElementById("settingsHostGuardNum");
    var step1Num = document.querySelector("#settingsStep1 .settings-step-num");
    var step2Num = document.querySelector("#settingsStep2 .settings-step-num");
    var step3Num = document.querySelector("#settingsStep3 .settings-step-num");
    var step2 = document.getElementById("settingsStep2");
    var step3 = document.getElementById("settingsStep3");
    var mfaStatus = document.getElementById("settingsMFAStatus");
    var mfaNum = document.getElementById("settingsMFANum");
    var mfaSetupBtn = document.getElementById("settingsMFASetupBtn");
    var mfaDisableBtn = document.getElementById("settingsMFADisableBtn");
    var mfaSetupBox = document.getElementById("settingsMFASetupBox");
    var sessionPolicy = document.getElementById("settingsSessionPolicy");
    var emailLoginEnabled = document.getElementById("settingsEmailLoginEnabled");
    var emailLoginAddress = document.getElementById("settingsEmailLoginAddress");
    var emailDeliveryURL = document.getElementById("settingsEmailDeliveryURL");
    var emailDeliveryToken = document.getElementById("settingsEmailDeliveryToken");
    var emailDeliveryScope = document.getElementById("settingsEmailDeliveryScope");
    var emailDeliveryTemplate = document.getElementById("settingsEmailDeliveryTemplate");
    var emailDeliveryTimeout = document.getElementById("settingsEmailDeliveryTimeout");
    var emailLoginStatus = document.getElementById("settingsEmailLoginStatus");
    var emailLoginNum = document.getElementById("settingsEmailLoginNum");

    var emailInput = document.getElementById("settingsEmailInput");
    var emailBtn = document.getElementById("settingsEmailBtn");

    // Step 1: Domain & Email
    if (settingsData.domain) {
      domainInput.value = settingsData.domain;
      domainStatus.textContent = "Configured";
      domainStatus.className = "settings-step-status configured";
      step1Num.classList.add("done");
      setText(domainBtn, "Update Domain");
    } else {
      domainInput.value = "";
      domainStatus.textContent = "Not set";
      domainStatus.className = "settings-step-status pending";
      step1Num.classList.remove("done");
      setText(domainBtn, "Save Domain");
    }
    // Email
    if (settingsData.email) {
      emailInput.value = settingsData.email;
      setText(emailBtn, "Update Email");
    } else {
      emailInput.value = "";
      setText(emailBtn, "Save Email");
    }

    // Step 2: SSL
    if (settingsData.domain) {
      step2.classList.remove("disabled");
      if (settingsData.ssl_enabled) {
        sslStatus.textContent = "Enabled";
        sslStatus.className = "settings-step-status configured";
        step2Num.classList.add("done");
        sslBtn.disabled = true;
        setText(sslBtn, "SSL Enabled");
        sslBtn.className = "btn btn-sm btn-outline";
      } else {
        sslStatus.textContent = "Not enabled";
        sslStatus.className = "settings-step-status pending";
        step2Num.classList.remove("done");
        sslBtn.disabled = false;
        setText(sslBtn, "Enable SSL");
        sslBtn.className = "btn btn-sm btn-success";
      }
    } else {
      step2.classList.add("disabled");
      sslStatus.textContent = "Set domain first";
      sslStatus.className = "settings-step-status pending";
      sslBtn.disabled = true;
    }

    // Step 3: Block insecure (toggle — can enable and disable)
    if (settingsData.ssl_enabled) {
      step3.classList.remove("disabled");
      blockBtn.disabled = false;
      blockBtn.style.display = "inline-flex";
      if (settingsData.insecure_blocked) {
        blockStatus.textContent = "Blocked — HTTP redirects to HTTPS";
        blockStatus.className = "settings-step-status configured";
        step3Num.classList.add("done");
        setText(blockBtn, "Allow HTTP (Disable Block)");
        blockBtn.className = "btn btn-sm btn-outline";
      } else {
        blockStatus.textContent = "HTTP still allowed";
        blockStatus.className = "settings-step-status pending";
        step3Num.classList.remove("done");
        setText(blockBtn, "Block Insecure Traffic");
        blockBtn.className = "btn btn-sm btn-warning";
      }
    } else {
      step3.classList.add("disabled");
      blockStatus.textContent = "Enable SSL first";
      blockStatus.className = "settings-step-status pending";
      blockBtn.disabled = true;
      blockBtn.style.display = "inline-flex";
    }

    if (settingsData.host_guard) {
      hostGuardStatus.textContent = "Installed";
      hostGuardStatus.className = "settings-step-status configured";
      hostGuardNum.classList.add("done");
      hostGuardBtn.disabled = true;
      setText(hostGuardBtn, "Host Guard Installed");
      hostGuardBtn.className = "btn btn-sm btn-outline";
    } else {
      hostGuardStatus.textContent = "Not installed";
      hostGuardStatus.className = "settings-step-status pending";
      hostGuardNum.classList.remove("done");
      hostGuardBtn.disabled = false;
      setText(hostGuardBtn, "Install Host Guard");
      hostGuardBtn.className = "btn btn-sm btn-warning";
    }

    if (settingsData.mfa_enabled) {
      mfaStatus.textContent = "Enabled";
      mfaStatus.className = "settings-step-status configured";
      mfaNum.classList.add("done");
      mfaSetupBtn.style.display = "none";
      mfaDisableBtn.style.display = "inline-flex";
      mfaSetupBox.style.display = "none";
      pendingMFASecret = "";
    } else {
      mfaStatus.textContent = "Not enabled";
      mfaStatus.className = "settings-step-status pending";
      mfaNum.classList.remove("done");
      mfaSetupBtn.style.display = "inline-flex";
      mfaDisableBtn.style.display = "none";
    }

    var idleMin = settingsData.session_idle_sec ? Math.round(settingsData.session_idle_sec / 60) : 30;
    var absoluteHours = settingsData.session_max_sec ? Math.round(settingsData.session_max_sec / 3600) : 12;
    var reauthMin = settingsData.reauth_max_sec ? Math.round(settingsData.reauth_max_sec / 60) : 15;
    sessionPolicy.textContent = "Idle " + idleMin + "m / absolute " + absoluteHours + "h / reauth " + reauthMin + "m";

    if (emailLoginEnabled) emailLoginEnabled.checked = !!settingsData.email_login_enabled;
    if (emailLoginAddress) emailLoginAddress.value = settingsData.email_login_address || "";
    if (emailDeliveryURL) emailDeliveryURL.value = settingsData.email_delivery_url || "";
    if (emailDeliveryToken) emailDeliveryToken.value = "";
    if (emailDeliveryScope) emailDeliveryScope.value = settingsData.email_delivery_scope || "auth";
    if (emailDeliveryTemplate) emailDeliveryTemplate.value = settingsData.email_delivery_template || "serverpilot_login_code";
    if (emailDeliveryTimeout) emailDeliveryTimeout.value = settingsData.email_delivery_timeout_sec || 5;
    if (emailLoginStatus) {
      var configured = settingsData.email_login_enabled && settingsData.email_login_address && settingsData.email_delivery_url && settingsData.email_delivery_token_configured;
      emailLoginStatus.textContent = configured ? "Enabled" : (settingsData.email_login_enabled ? "Incomplete" : "Disabled");
      emailLoginStatus.className = "settings-step-status " + (configured ? "configured" : "pending");
      if (emailLoginNum) emailLoginNum.classList.toggle("done", !!configured);
    }
    loadSessions();
  }

  // Save domain
  onEl("settingsDomainBtn", "click", async function() {
    var btn = this;
    var domain = document.getElementById("settingsDomainInput").value.trim();
    if (!domain) {
      showToast("Enter a domain first", "error");
      return;
    }
    btn.disabled = true;
    setText(btn, "Creating site...");
    try {
      await apiFetch("/api/settings/domain", { method: "POST", body: { domain: domain } });
      showToast("Domain set and nginx site created for " + domain, "success");
      await loadSettings();
      await loadSites();
    } catch(err) {
      showToast("Failed: " + err.message, "error");
    } finally {
      btn.disabled = false;
      setText(btn, settingsData.domain ? "Update Domain" : "Save Domain");
    }
  });

  // Save email
  onEl("settingsEmailBtn", "click", async function() {
    var btn = this;
    var email = document.getElementById("settingsEmailInput").value.trim();
    if (!email) {
      showToast("Enter an email first", "error");
      return;
    }
    btn.disabled = true;
    setText(btn, "Saving...");
    try {
      await apiFetch("/api/settings/email", { method: "POST", body: { email: email } });
      showToast("Email saved: " + email, "success");
      await loadSettings();
    } catch(err) {
      showToast("Failed: " + err.message, "error");
    } finally {
      btn.disabled = false;
      setText(btn, settingsData.email ? "Update Email" : "Save Email");
    }
  });

  onEl("settingsEmailLoginSaveBtn", "click", async function() {
    var btn = this;
    btn.disabled = true;
    setText(btn, "Saving...");
    try {
      await apiFetch("/api/settings/email-login", {
        method: "POST",
        body: {
          enabled: document.getElementById("settingsEmailLoginEnabled").checked,
          email: document.getElementById("settingsEmailLoginAddress").value.trim(),
          url: document.getElementById("settingsEmailDeliveryURL").value.trim(),
          token: document.getElementById("settingsEmailDeliveryToken").value.trim(),
          scope: document.getElementById("settingsEmailDeliveryScope").value.trim(),
          template: document.getElementById("settingsEmailDeliveryTemplate").value.trim(),
          timeout_sec: Number(document.getElementById("settingsEmailDeliveryTimeout").value || "5")
        }
      });
      showToast("Email login settings saved", "success");
      await loadSettings();
    } catch(err) {
      showToast("Failed: " + err.message, "error");
    } finally {
      btn.disabled = false;
      setText(btn, "Save Email Login");
    }
  });

  onEl("settingsEmailLoginTestBtn", "click", async function() {
    var email = document.getElementById("settingsEmailLoginAddress").value.trim();
    if (!email) {
      showToast("Enter the login email first", "error");
      return;
    }
    var btn = this;
    btn.disabled = true;
    setText(btn, "Sending...");
    try {
      await apiFetch("/api/login/email/request-code", { method: "POST", body: { email: email } });
      showToast("If configured, a test login code was sent", "success");
    } catch(err) {
      showToast("Could not send test code", "error");
    } finally {
      btn.disabled = false;
      setText(btn, "Send Test Code");
    }
  });

  // Enable SSL
  onEl("settingsSSLBtn", "click", function() {
    if (!settingsData.domain) return;
    confirmAction("Enable SSL", "Obtain an SSL certificate for " + settingsData.domain + " via Let's Encrypt?", function() {
      runStreamedOperation(
        "/api/settings/ssl-enable",
        {},
        "Enabling SSL for ServerPilot",
        settingsData.domain
      );
    });
  });

  // Block / Unblock insecure traffic (toggle)
  onEl("settingsBlockBtn", "click", function() {
    if (!settingsData.ssl_enabled) return;
    var isBlocked = settingsData.insecure_blocked;
    var title = isBlocked ? "Allow HTTP Traffic" : "Block Insecure Traffic";
    var msg = isBlocked
      ? "This will re-enable HTTP access for " + settingsData.domain + ". HTTPS will still work, but HTTP will no longer redirect. Continue?"
      : "This will redirect ALL HTTP traffic to HTTPS for " + settingsData.domain + " only. Other sites on port 80 are not affected. Continue?";
    confirmAction(title, msg, async function() {
      var btn = document.getElementById("settingsBlockBtn");
      btn.disabled = true;
      setText(btn, isBlocked ? "Unblocking..." : "Blocking...");
      try {
        await apiFetch("/api/settings/block-insecure", { method: "POST", body: {} });
        showToast(isBlocked ? "HTTP access re-enabled for " + settingsData.domain : "HTTP blocked — all traffic redirects to HTTPS.", "success");
        await loadSettings();
        await loadSites();
      } catch(err) {
        showToast("Failed: " + err.message, "error");
        btn.disabled = false;
        renderSettings();
      }
    });
  });

  onEl("settingsHostGuardBtn", "click", function() {
    confirmAction("Install Host Guard", "Install a default nginx guard so unknown domains return a plain 404 instead of reaching ServerPilot?", async function() {
      var btn = document.getElementById("settingsHostGuardBtn");
      btn.disabled = true;
      setText(btn, "Installing...");
      try {
        var resp = await apiFetch("/api/settings/host-guard", { method: "POST", body: {} });
        var data = (resp && resp.data) || {};
        showToast(data.message || "Host guard installed", "success");
        await loadSettings();
        await loadSites();
      } catch(err) {
        showToast("Failed: " + err.message, "error");
        btn.disabled = false;
        renderSettings();
      }
    });
  });

  onEl("settingsMFASetupBtn", "click", async function() {
    var btn = this;
    btn.disabled = true;
    setText(btn, "Generating...");
    try {
      var resp = await apiFetch("/api/security/mfa/setup", { method: "POST", body: {} });
      var data = resp && resp.data ? resp.data : resp;
      pendingMFASecret = data.secret || "";
      document.getElementById("settingsMFASecret").value = pendingMFASecret;
      document.getElementById("settingsMFAURI").value = data.otpauth_uri || "";
      document.getElementById("settingsMFACode").value = "";
      document.getElementById("settingsMFASetupBox").style.display = "block";
      showToast("MFA secret generated", "success");
    } catch(err) {
      showToast("MFA setup failed: " + err.message, "error");
    } finally {
      btn.disabled = false;
      setText(btn, "Set Up MFA");
    }
  });

  onEl("settingsMFAEnableBtn", "click", async function() {
    var code = document.getElementById("settingsMFACode").value.trim();
    if (!pendingMFASecret || code.length !== 6) {
      showToast("Enter the 6-digit MFA code", "error");
      return;
    }
    var btn = this;
    btn.disabled = true;
    setText(btn, "Enabling...");
    try {
      await apiFetch("/api/security/mfa/enable", { method: "POST", body: { secret: pendingMFASecret, code: code } });
      showToast("MFA enabled. Other sessions were revoked.", "success");
      await loadSettings();
    } catch(err) {
      showToast("MFA enable failed: " + err.message, "error");
    } finally {
      btn.disabled = false;
      setText(btn, "Enable MFA");
    }
  });

  onEl("settingsMFADisableBtn", "click", function() {
    confirmAction("Disable MFA", "This removes the second factor from dashboard login and revokes other sessions. Continue?", async function() {
      try {
        await apiFetch("/api/security/mfa/disable", { method: "POST", body: {} });
        showToast("MFA disabled", "success");
        await loadSettings();
      } catch(err) {
        showToast("MFA disable failed: " + err.message, "error");
      }
    });
  });

  onEl("settingsSessionsRefreshBtn", "click", loadSessions);

  onEl("settingsSessionsRevokeOthersBtn", "click", function() {
    confirmAction("Revoke Other Sessions", "This will keep your current browser session and revoke every other active dashboard session.", async function() {
      try {
        var resp = await apiFetch("/api/sessions/revoke-others", { method: "POST", body: {} });
        var data = resp && resp.data ? resp.data : resp;
        showToast("Revoked " + (data.revoked || 0) + " session(s)", "success");
        await loadSessions();
      } catch(err) {
        showToast("Session revoke failed: " + err.message, "error");
      }
    });
  });

  async function loadSessions() {
    var el = document.getElementById("settingsSessionsContent");
    if (!el) return;
    try {
      var resp = await apiFetch("/api/sessions");
      var sessions = (resp && resp.data) ? resp.data : [];
      if (!sessions.length) {
        el.textContent = "No active sessions.";
        return;
      }
      var html = '<div style="overflow:auto;"><table><thead><tr>' +
        '<th>Session</th><th>IP</th><th>Last Seen</th><th>Expires</th><th></th>' +
        '</tr></thead><tbody>';
      sessions.forEach(function(s) {
        var lastSeen = s.last_seen_at ? new Date(s.last_seen_at).toLocaleString() : "";
        var expires = s.expires_at ? new Date(s.expires_at).toLocaleString() : "";
        html += '<tr><td><code>' + escapeHtml(s.id || "") + '</code>' + (s.current ? ' <span class="badge badge-running">Current</span>' : '') +
          '<div style="color:var(--text-muted);font-size:0.72rem;max-width:260px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">' + escapeHtml(s.user_agent || "") + '</div></td>' +
          '<td>' + escapeHtml(s.ip || "") + '</td>' +
          '<td>' + escapeHtml(lastSeen) + '</td>' +
          '<td>' + escapeHtml(expires) + '</td>' +
          '<td><button class="btn btn-sm btn-outline" onclick="revokeSession(&quot;' + escapeHtml(s.id || "") + '&quot;)">Revoke</button></td></tr>';
      });
      html += '</tbody></table></div>';
      el.innerHTML = html;
    } catch(err) {
      el.textContent = "Failed to load sessions: " + err.message;
    }
  }

  window.revokeSession = async function(id) {
    if (!id) return;
    try {
      await apiFetch("/api/sessions/revoke", { method: "POST", body: { id: id } });
      showToast("Session revoked", "success");
      await loadSessions();
    } catch(err) {
      showToast("Session revoke failed: " + err.message, "error");
    }
  };

  // ── Keyboard: Escape closes modals ──
  document.addEventListener("keydown", function(e) {
    if (e.key !== "Escape") return;
    if (assocModal) assocModal.classList.remove("show");
    if (confirmModal) confirmModal.classList.remove("show");
    if (gdappModal) gdappModal.classList.remove("show");
    pendingConfirm = null;
    closeConfigEditor();
    if (typeof closeDockerPruneModal === "function") closeDockerPruneModal();
    if (progressCloseBtn && progressCloseBtn.style.display !== "none") closeProgressModal();
  });

  // ── Resources ──
  var sysData = null;
