/* Associate site + config editor */
"use strict";

  var redirectDelayed = document.getElementById("redirectDelayed");
  var redirectDelayOptions = document.getElementById("redirectDelayOptions");
  function updateRedirectDelayOptions() {
    if (!redirectDelayOptions || !redirectDelayed) return;
    redirectDelayOptions.style.display = redirectDelayed.checked ? "block" : "none";
  }
  onEl("redirectDelayed", "change", updateRedirectDelayOptions);

  function bindNginxDiagConfigActions(root) {
    if (!root) return;
    root.querySelectorAll(".nginx-diag-edit").forEach(function(btn) {
      btn.addEventListener("click", function() {
        var configName = btn.getAttribute("data-config");
        if (configName) openConfigEditor(configName, configName);
      });
    });
    root.querySelectorAll(".nginx-diag-delete").forEach(function(btn) {
      btn.addEventListener("click", async function() {
        var configName = btn.getAttribute("data-config");
        if (!configName) return;
        if (!window.confirm("Delete nginx config " + configName + "? This removes sites-enabled and sites-available entries.")) return;
        try {
          await runStreamedOperation("/api/sites/delete", { domain: configName, config_name: configName }, "Deleting Config", configName);
          await loadSites();
          showToast("Config deleted", "success");
        } catch (err) {
          showToast("Delete failed: " + ((err && err.message) || "error"), "error");
        }
      });
    });
  }

  function renderNginxIssueHtml(issue) {
    var loc = "";
    if (issue.file) {
      loc = issue.file + (issue.line ? ":" + issue.line : "");
    }
    var badge = issue.auto_fixable
      ? "<span class=\"nginx-diag-badge nginx-diag-badge-auto\">Auto-fix</span>"
      : "<span class=\"nginx-diag-badge nginx-diag-badge-manual\">Manual</span>";
    var actions = "";
    if (issue.file) {
      actions = "<div class=\"nginx-diag-actions\">" +
        "<button type=\"button\" class=\"btn btn-sm btn-outline nginx-diag-edit\" data-config=\"" + escapeHtml(issue.file) + "\">Edit config</button>" +
        "<button type=\"button\" class=\"btn btn-sm btn-outline nginx-diag-delete\" data-config=\"" + escapeHtml(issue.file) + "\">Delete config</button>" +
        "</div>";
    }
    return "<div class=\"nginx-diag-issue\">" +
      "<div class=\"nginx-diag-issue-head\">" + (loc ? "<code>" + escapeHtml(loc) + "</code> " : "") + badge + "</div>" +
      "<div class=\"nginx-diag-issue-msg\">" + escapeHtml(issue.message || "") + "</div>" +
      (issue.suggestion ? "<div class=\"nginx-diag-issue-suggestion\">" + escapeHtml(issue.suggestion) + "</div>" : "") +
      actions +
      "</div>";
  }

  function renderNginxDiagnostics(data, options) {
    options = options || {};
    data = data || {};
    var modal = document.getElementById("nginxDiagModal");
    if (!modal) {
      showToast("Nginx diagnostics unavailable — hard-refresh the dashboard (Ctrl+Shift+R)", "error");
      return;
    }

    var status = document.getElementById("nginxDiagStatus");
    var fixedBox = document.getElementById("nginxDiagFixed");
    var issuesBox = document.getElementById("nginxDiagIssues");
    var hiddenBox = document.getElementById("nginxDiagHidden");
    var hiddenList = document.getElementById("nginxDiagHiddenList");
    var detail = document.getElementById("nginxDiagDetail");
    var repairBtn = document.getElementById("nginxDiagRepairBtn");

    if (data.ok) {
      setText(status, data.fixed && data.fixed.length ? "Nginx is valid after repair." : "Nginx configuration is valid.");
    } else {
      setText(status, "Nginx configuration test failed. Review the issues below and take manual action where needed.");
    }

    if (fixedBox) {
      var fixed = data.fixed || [];
      if (fixed.length) {
        fixedBox.style.display = "block";
        fixedBox.innerHTML = "<strong>Fixed automatically:</strong><ul>" + fixed.map(function(item) {
          return "<li>" + escapeHtml(item) + "</li>";
        }).join("") + "</ul>";
      } else {
        fixedBox.style.display = "none";
        fixedBox.innerHTML = "";
      }
    }

    if (issuesBox) {
      var issues = data.issues || [];
      if (!issues.length && !data.ok) {
        issuesBox.innerHTML = "<div class=\"nginx-diag-issue\"><div class=\"nginx-diag-issue-msg\">" +
          escapeHtml(data.remaining_error || "nginx configuration test failed") + "</div></div>";
      } else {
        issuesBox.innerHTML = issues.map(renderNginxIssueHtml).join("");
        bindNginxDiagConfigActions(issuesBox);
      }
    }

    if (hiddenBox && hiddenList) {
      var hidden = data.hidden_configs || [];
      if (hidden.length) {
        hiddenBox.style.display = "block";
        hiddenList.innerHTML = hidden.map(function(name) {
          return "<li class=\"nginx-diag-hidden-item\">" +
            "<code>" + escapeHtml(name) + "</code>" +
            "<span class=\"nginx-diag-actions\">" +
            "<button type=\"button\" class=\"btn btn-sm btn-outline nginx-diag-edit\" data-config=\"" + escapeHtml(name) + "\">Edit</button>" +
            "<button type=\"button\" class=\"btn btn-sm btn-outline nginx-diag-delete\" data-config=\"" + escapeHtml(name) + "\">Delete</button>" +
            "</span></li>";
        }).join("");
        bindNginxDiagConfigActions(hiddenList);
      } else {
        hiddenBox.style.display = "none";
        hiddenList.innerHTML = "";
      }
    }

    if (detail) {
      if (data.detail) {
        detail.textContent = data.detail;
      } else if (data.ok) {
        detail.textContent = "nginx -t currently passes. If site creation just failed, the bad config was already rolled back — create the site again to capture the error here, or check server logs.";
      } else {
        detail.textContent = data.remaining_error || "(no diagnostic output available)";
      }
    }

    if (repairBtn) {
      var hasAutoFixable = (data.issues || []).some(function(issue) { return issue.auto_fixable; });
      repairBtn.style.display = (!data.ok && (hasAutoFixable || options.showRepair)) ? "inline-flex" : "none";
    }

    modal.classList.add("show");
  }

  async function openNginxDiagnostics(fromRepair) {
    try {
      var resp;
      if (fromRepair) {
        if (typeof ensureRecentReauth === "function") {
          await ensureRecentReauth();
        }
        resp = await apiFetch("/api/nginx/repair", { method: "POST" });
      } else {
        resp = await apiFetch("/api/nginx/diagnose");
      }
      var data = (resp && resp.data) || {};
      renderNginxDiagnostics(data, { showRepair: !fromRepair });
      if (fromRepair) {
        if (data.ok) {
          var fixed = data.fixed || [];
          showToast(fixed.length ? ("Nginx repaired: " + fixed.join("; ")) : "Nginx config is valid", "success");
          await loadSites();
        } else {
          showToast("Nginx repair incomplete — review diagnostics for remaining issues", "error");
        }
      }
    } catch (err) {
      showToast("Failed to load nginx diagnostics: " + ((err && err.message) || "error"), "error");
    }
  }

  onEl("nginxDiagCloseBtn", "click", function() {
    var modal = document.getElementById("nginxDiagModal");
    if (modal) modal.classList.remove("show");
  });
  onEl("nginxDiagModal", "click", function(e) {
    var modal = document.getElementById("nginxDiagModal");
    if (e.target === modal) modal.classList.remove("show");
  });
  onEl("nginxDiagRepairBtn", "click", async function() {
    var btn = document.getElementById("nginxDiagRepairBtn");
    if (btn) btn.disabled = true;
    try {
      await openNginxDiagnostics(true);
    } finally {
      if (btn) btn.disabled = false;
    }
  });

  onEl("repairNginxBtn", "click", async function() {
    if (!window.confirm("Scan Nginx, repair known safe issues (including duplicate proxy directives and server name hash size), and reload Nginx?")) return;
    var btn = document.getElementById("repairNginxBtn");
    btn.disabled = true;
    try {
      await openNginxDiagnostics(true);
    } finally {
      btn.disabled = false;
    }
  });
  onEl("createRedirectBtn", "click", function() {
    document.getElementById("redirectDomain").value = "";
    document.getElementById("redirectTarget").value = "";
    document.getElementById("redirectCode").value = "301";
    document.getElementById("redirectIncludeWWW").checked = false;
    if (redirectDelayed) redirectDelayed.checked = false;
    document.getElementById("redirectDelaySeconds").value = "5";
    document.getElementById("redirectMessage").value = "";
    updateRedirectDelayOptions();
    if (redirectModal) redirectModal.classList.add("show");
  });
  onEl("redirectCancelBtn", "click", function() {
    if (redirectModal) redirectModal.classList.remove("show");
  });
  onEl("redirectModal", "click", function(e) {
    var modal = document.getElementById("redirectModal");
    if (e.target === modal) modal.classList.remove("show");
  });
  onEl("redirectForm", "submit", async function(e) {
    e.preventDefault();
    var btn = document.getElementById("redirectSubmitBtn");
    btn.disabled = true;
    setText(btn, "Creating...");
    try {
      var useDelay = document.getElementById("redirectDelayed").checked;
      await apiFetch("/api/sites/redirect", {
        method: "POST",
        body: {
          domain: document.getElementById("redirectDomain").value,
          target: document.getElementById("redirectTarget").value,
          code: parseInt(document.getElementById("redirectCode").value, 10),
          include_www: document.getElementById("redirectIncludeWWW").checked,
          delay_seconds: useDelay ? parseInt(document.getElementById("redirectDelaySeconds").value, 10) : 0,
          message: useDelay ? document.getElementById("redirectMessage").value : ""
        }
      });
      redirectModal.classList.remove("show");
      showToast("Redirect created successfully", "success");
      await loadContainers();
    } catch(err) {
      showToast("Failed to create redirect: " + err.message, "error");
    } finally {
      btn.disabled = false;
      setText(btn, "Create Redirect");
    }
  });

  var assocModal = document.getElementById("associateModal");

  // openAssociateModal + associate form submit: containers-sites.js

  onEl("assocCancelBtn", "click", function() {
    var modal = document.getElementById("associateModal");
    if (modal) modal.classList.remove("show");
  });

  onEl("associateModal", "click", function(e) {
    var modal = document.getElementById("associateModal");
    if (e.target === modal) modal.classList.remove("show");
  });

  // associate form submit handled by containers-sites.js

  // ── Config Editor ──
  function configEditorEls() {
    return {
      modal: document.getElementById("configEditorModal"),
      textarea: document.getElementById("configEditorTextarea"),
      errorBox: document.getElementById("configEditorError"),
      domainSpan: document.getElementById("configEditorDomain")
    };
  }

  var configOriginalContent = "";
  var configCurrentDomain = "";

  async function openConfigEditor(configName, displayDomain) {
    var els = configEditorEls();
    if (!els.modal || !els.textarea || !els.errorBox) {
      showToast("Config editor unavailable — hard-refresh the dashboard (Ctrl+Shift+R)", "error");
      return;
    }
    configCurrentDomain = configName;
    setText(els.domainSpan, displayDomain || configName);
    els.textarea.value = "";
    els.errorBox.style.display = "none";
    setText(els.errorBox, "");
    els.modal.classList.add("show");

    try {
      var resp = await apiFetch("/api/sites/config?domain=" + encodeURIComponent(configName));
      var data = (resp && resp.data) ? resp.data : resp;
      configOriginalContent = data.content || "";
      els.textarea.value = configOriginalContent;
    } catch(err) {
      showToast("Failed to load config: " + err.message, "error");
      els.modal.classList.remove("show");
    }
  }

  function closeConfigEditor() {
    var els = configEditorEls();
    if (!els.modal) return;
    els.modal.classList.remove("show");
    configCurrentDomain = "";
    configOriginalContent = "";
    if (els.textarea) els.textarea.value = "";
    if (els.errorBox) els.errorBox.style.display = "none";
  }

  onEl("configCancelBtn", "click", closeConfigEditor);

  onEl("configEditorModal", "click", function(e) {
    var modal = document.getElementById("configEditorModal");
    if (e.target === modal) closeConfigEditor();
  });

  onEl("configResetBtn", "click", function() {
    var els = configEditorEls();
    if (els.textarea) els.textarea.value = configOriginalContent;
    if (els.errorBox) els.errorBox.style.display = "none";
    showToast("Config reset to original", "success");
  });

  onEl("configSaveBtn", "click", async function() {
    var els = configEditorEls();
    if (!els.textarea || !els.errorBox) return;
    var btn = this;
    btn.disabled = true;
    setText(btn, "Saving...");
    els.errorBox.style.display = "none";
    try {
      var resp = await apiFetch("/api/sites/config/save", {
        method: "POST",
        body: { domain: configCurrentDomain, content: els.textarea.value, reload: false }
      });
      var data = (resp && resp.data) ? resp.data : resp;
      configOriginalContent = els.textarea.value;
      showToast(data.message || "Config saved", "success");
    } catch(err) {
      showToast("Save failed: " + err.message, "error");
    } finally {
      btn.disabled = false;
      setText(btn, "Save");
    }
  });

  onEl("configSaveReloadBtn", "click", async function() {
    var els = configEditorEls();
    if (!els.textarea || !els.errorBox) return;
    var btn = this;
    btn.disabled = true;
    setText(btn, "Validating...");
    els.errorBox.style.display = "none";
    try {
      var resp = await apiFetch("/api/sites/config/save", {
        method: "POST",
        body: { domain: configCurrentDomain, content: els.textarea.value, reload: true }
      });
      if (resp && resp.success === false) {
        var data = resp.data || {};
        var errMsg = resp.error || "Validation failed";
        if (data.test_output) errMsg = data.test_output;
        els.errorBox.style.display = "block";
        setText(els.errorBox, errMsg);
        showToast("Config has errors — not reloaded", "error");
      } else {
        var data2 = (resp && resp.data) ? resp.data : resp;
        configOriginalContent = els.textarea.value;
        showToast(data2.message || "Config saved and nginx reloaded", "success");
        els.errorBox.style.display = "none";
        await loadSites();
      }
    } catch(err) {
      els.errorBox.style.display = "block";
      setText(els.errorBox, err.message);
      showToast("Save & Reload failed: " + err.message, "error");
    } finally {
      btn.disabled = false;
      setText(btn, "Save & Reload");
    }
  });

  // ── Nginx Main Config Editor ──
  function nginxMainEditorEls() {
    return {
      modal: document.getElementById("nginxMainEditorModal"),
      textarea: document.getElementById("nginxMainEditorTextarea"),
      errorBox: document.getElementById("nginxMainEditorError")
    };
  }

  var nginxMainOriginalContent = "";

  async function openNginxMainEditor() {
    var els = nginxMainEditorEls();
    if (!els.modal || !els.textarea || !els.errorBox) {
      showToast("nginx.conf editor unavailable — hard-refresh the dashboard (Ctrl+Shift+R)", "error");
      return;
    }
    els.textarea.value = "";
    els.errorBox.style.display = "none";
    setText(els.errorBox, "");
    els.modal.classList.add("show");
    try {
      var resp = await apiFetch("/api/nginx/main-config");
      var data = (resp && resp.data) ? resp.data : resp;
      nginxMainOriginalContent = data.content || "";
      els.textarea.value = nginxMainOriginalContent;
    } catch (err) {
      showToast("Failed to load nginx.conf: " + err.message, "error");
      els.modal.classList.remove("show");
    }
  }

  function closeNginxMainEditor() {
    var els = nginxMainEditorEls();
    if (!els.modal) return;
    els.modal.classList.remove("show");
    nginxMainOriginalContent = "";
    if (els.textarea) els.textarea.value = "";
    if (els.errorBox) els.errorBox.style.display = "none";
  }

  onEl("nginxMainEditorCancelBtn", "click", closeNginxMainEditor);
  onEl("nginxMainEditorModal", "click", function(e) {
    var modal = document.getElementById("nginxMainEditorModal");
    if (e.target === modal) closeNginxMainEditor();
  });
  onEl("nginxMainEditorResetBtn", "click", function() {
    var els = nginxMainEditorEls();
    if (els.textarea) els.textarea.value = nginxMainOriginalContent;
    if (els.errorBox) els.errorBox.style.display = "none";
    showToast("nginx.conf reset to original", "success");
  });
  onEl("editNginxMainBtn", "click", async function() {
    if (typeof ensureRecentReauth === "function") {
      try { await ensureRecentReauth(); } catch (_) { return; }
    }
    await openNginxMainEditor();
  });
  onEl("nginxDiagEditMainBtn", "click", async function() {
    if (typeof ensureRecentReauth === "function") {
      try { await ensureRecentReauth(); } catch (_) { return; }
    }
    await openNginxMainEditor();
  });

  onEl("nginxMainEditorSaveBtn", "click", async function() {
    var els = nginxMainEditorEls();
    if (!els.textarea || !els.errorBox) return;
    var btn = this;
    btn.disabled = true;
    setText(btn, "Saving...");
    els.errorBox.style.display = "none";
    try {
      if (typeof ensureRecentReauth === "function") {
        await ensureRecentReauth();
      }
      var resp = await apiFetch("/api/nginx/main-config/save", {
        method: "POST",
        body: { content: els.textarea.value, reload: false }
      });
      var data = (resp && resp.data) ? resp.data : resp;
      nginxMainOriginalContent = els.textarea.value;
      showToast(data.message || "nginx.conf saved", "success");
    } catch (err) {
      showToast("Save failed: " + err.message, "error");
    } finally {
      btn.disabled = false;
      setText(btn, "Save");
    }
  });

  onEl("nginxMainEditorSaveReloadBtn", "click", async function() {
    var els = nginxMainEditorEls();
    if (!els.textarea || !els.errorBox) return;
    var btn = this;
    btn.disabled = true;
    setText(btn, "Validating...");
    els.errorBox.style.display = "none";
    try {
      if (typeof ensureRecentReauth === "function") {
        await ensureRecentReauth();
      }
      var resp = await apiFetch("/api/nginx/main-config/save", {
        method: "POST",
        body: { content: els.textarea.value, reload: true }
      });
      if (resp && resp.success === false) {
        var data = resp.data || {};
        var errMsg = resp.error || "Validation failed";
        if (data.test_output) errMsg = data.test_output;
        els.errorBox.style.display = "block";
        setText(els.errorBox, errMsg);
        showToast("nginx.conf has errors — not reloaded", "error");
      } else {
        var data2 = (resp && resp.data) ? resp.data : resp;
        nginxMainOriginalContent = els.textarea.value;
        showToast(data2.message || "nginx.conf saved and reloaded", "success");
        els.errorBox.style.display = "none";
        if (typeof checkAssocNginxDomainReadiness === "function") {
          await checkAssocNginxDomainReadiness();
        }
        await loadSites();
      }
    } catch (err) {
      els.errorBox.style.display = "block";
      setText(els.errorBox, err.message);
      showToast("Save & Reload failed: " + err.message, "error");
    } finally {
      btn.disabled = false;
      setText(btn, "Save & Reload");
    }
  });

  // ── Progress / Log Modal ──
  var progressModal = document.getElementById("progressModal");
