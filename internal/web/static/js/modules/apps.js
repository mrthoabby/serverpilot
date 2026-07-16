/* Installed/managed apps + env modals */
"use strict";

  var appsPendingUninstall = null; // { id, name } of app awaiting confirmation

  var APP_ICONS = {
    docker:  "🐳",
    nodejs:  "⬡",
    nginx:   "🌐",
    certbot: "🔒",
    pm2:     "⚙️",
    golang:  "🔵",
    python3: "🐍",
  };

  var MANAGER_LABELS = {
    apt:    { text: "apt",    color: "var(--accent)"  },
    snap:   { text: "snap",   color: "#f59e0b"        },
    npm:    { text: "npm",    color: "#3fb950"        },
    manual: { text: "manual", color: "var(--text-muted)" },
  };

  async function loadApps() {
    var el = document.getElementById("appsContent");
    if (el) el.innerHTML = '<div class="spinner"><div class="spinner-ring"></div>Detecting installed applications...</div>';
    try {
      var resp = await apiFetch("/api/apps");
      var apps = (resp && resp.data) ? resp.data : (resp || []);
      renderApps(apps);
    } catch(err) {
      if (el) el.innerHTML = '<p style="padding:1rem;color:var(--red);">Error: ' + escapeHtml(err.message) + '</p>';
    }
  }

  async function loadDependencies() {
    var el = document.getElementById("dependenciesContent");
    if (!el) return;
    el.innerHTML = '<div class="spinner"><div class="spinner-ring"></div>Checking dependencies...</div>';
    try {
      var resp = await apiFetch("/api/dependencies");
      var items = (resp && resp.data) ? resp.data : [];
      renderDependencies(items);
    } catch (err) {
      el.innerHTML = '<p style="padding:1rem;color:var(--red);">Error: ' + escapeHtml(err.message || "error") + '</p>';
    }
  }

  function renderDependencies(items) {
    var el = document.getElementById("dependenciesContent");
    if (!el) return;
    if (!items || items.length === 0) {
      el.innerHTML = '<p style="padding:1.25rem;color:var(--text-secondary);">No dependencies to show.</p>';
      return;
    }

    var missing = items.filter(function(d) { return !d.installed; });
    var summary = missing.length === 0
      ? '<p style="padding:0 1.25rem 0.75rem;color:var(--green);font-size:0.8125rem;">All tracked dependencies are installed.</p>'
      : '<p style="padding:0 1.25rem 0.75rem;color:var(--yellow);font-size:0.8125rem;">' +
        missing.length + ' pending ' + (missing.length === 1 ? 'dependency' : 'dependencies') + '.</p>';

    var rows = items.map(function(dep) {
      var status = dep.installed
        ? '<span style="color:var(--green);font-weight:600;">Installed</span>'
        : '<span style="color:var(--yellow);font-weight:600;">Missing</span>';
      var req = dep.required
        ? '<span style="font-size:0.7rem;padding:2px 8px;border-radius:999px;background:rgba(248,81,73,0.15);color:var(--red);margin-left:6px;">required</span>'
        : '<span style="font-size:0.7rem;padding:2px 8px;border-radius:999px;background:var(--bg-secondary);color:var(--text-muted);margin-left:6px;">optional</span>';
      var action = '';
      if (!dep.installed && dep.installable) {
        action = '<button class="btn btn-sm" style="background:var(--accent);color:#fff;border:none;font-size:0.75rem;" ' +
          'onclick="installDependency(' + attrJSON(dep.id) + ', refreshDependenciesAndApps)">Install</button>';
      } else if (!dep.installed && !dep.installable) {
        action = '<span style="color:var(--text-muted);font-size:0.75rem;">manual install</span>';
      } else {
        action = '<span style="color:var(--text-muted);font-size:0.75rem;">—</span>';
      }
      return '<tr style="border-bottom:1px solid var(--border);">' +
        '<td style="padding:0.75rem 1rem;">' +
          '<div style="font-weight:600;color:var(--text-primary);">' + escapeHtml(dep.name) + req + '</div>' +
          '<div style="font-size:0.75rem;color:var(--text-secondary);margin-top:2px;">' + escapeHtml(dep.description || '') + '</div>' +
        '</td>' +
        '<td style="padding:0.75rem 1rem;font-size:0.8125rem;">' + status + '</td>' +
        '<td style="padding:0.75rem 1rem;text-align:right;">' + action + '</td>' +
      '</tr>';
    }).join('');

    el.innerHTML = summary +
      '<table style="width:100%;border-collapse:collapse;">' +
        '<thead><tr style="border-bottom:2px solid var(--border);">' +
          '<th style="padding:0.5rem 1rem;text-align:left;font-size:0.75rem;color:var(--text-muted);">Dependency</th>' +
          '<th style="padding:0.5rem 1rem;text-align:left;font-size:0.75rem;color:var(--text-muted);">Status</th>' +
          '<th style="padding:0.5rem 1rem;text-align:right;font-size:0.75rem;color:var(--text-muted);">Action</th>' +
        '</tr></thead><tbody>' + rows + '</tbody></table>';
  }

  async function refreshDependenciesAndApps() {
    await loadDependencies();
    await loadApps();
  }

  // attrJSON serialises a JS value into a string safe to embed inside an
  // HTML attribute that uses double-quote delimiters (the common case for
  // inline onclick handlers below). Plain JSON.stringify would emit the
  // string with literal `"` characters that collide with the attribute's
  // own delimiter and silently truncate the handler. Using the HTML
  // entity &quot; lets the browser decode it back to `"` when parsing the
  // attribute, restoring the intended JS expression. Side benefit: this
  // also escapes any user-controlled string values defensively (e.g. an
  // app name containing a `"` cannot break out of the attribute or inject
  // additional onclick code — closes a latent XSS path on this row).
  function attrJSON(v) {
    return JSON.stringify(v).replace(/"/g, "&quot;");
  }

  function renderApps(apps) {
    var el = document.getElementById("appsContent");
    if (!el) return;

    if (!apps || apps.length === 0) {
      el.innerHTML = '<p style="padding:1.25rem;color:var(--text-secondary);">No known applications detected on this server.</p>';
      return;
    }

    var rows = apps.map(function(app) {
      var icon     = APP_ICONS[app.id] || "📦";
      var mgr      = MANAGER_LABELS[app.manager] || { text: app.manager || "?", color: "var(--text-muted)" };
      var statusDot= app.running
        ? '<span title="Running" style="display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--green);margin-right:4px;"></span>Running'
        : '<span title="Stopped" style="display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--text-muted);margin-right:4px;"></span>Stopped';
      var sizeStr  = app.size_mb > 0 ? (app.size_mb < 1024
          ? app.size_mb.toFixed(0) + ' MB'
          : (app.size_mb/1024).toFixed(2) + ' GB') : '—';

      return '<tr style="border-bottom:1px solid var(--border);">' +
        '<td style="padding:0.75rem 1rem;font-size:1.25rem;width:2rem;">' + icon + '</td>' +
        '<td style="padding:0.75rem 1rem;">' +
          '<div style="font-weight:600;color:var(--text-primary);">' + escapeHtml(app.name) + '</div>' +
          '<div style="font-size:0.75rem;color:var(--text-secondary);margin-top:2px;">' + escapeHtml(app.description || '') + '</div>' +
        '</td>' +
        '<td style="padding:0.75rem 1rem;font-family:monospace;font-size:0.8125rem;color:var(--text-secondary);">' + escapeHtml(app.version || '—') + '</td>' +
        '<td style="padding:0.75rem 1rem;">' +
          '<span style="font-size:0.75rem;padding:2px 8px;border-radius:999px;background:var(--bg-secondary);color:' + mgr.color + ';font-weight:600;">' + escapeHtml(mgr.text) + '</span>' +
        '</td>' +
        '<td style="padding:0.75rem 1rem;font-size:0.8125rem;color:var(--text-secondary);">' + sizeStr + '</td>' +
        '<td style="padding:0.75rem 1rem;font-size:0.8125rem;">' + statusDot + '</td>' +
        '<td style="padding:0.75rem 1rem;text-align:right;white-space:nowrap;">' +
          (SYSTEM_PERM_APPS[app.id]
            ? '<button class="btn btn-sm btn-outline" style="margin-right:4px;font-size:0.75rem;" ' +
              'onclick="openSystemAppPermsModal(' + attrJSON(app.id) + ',' + attrJSON(app.name) + ')">🔒 Permissions</button>'
            : '') +
          (app.removable
            ? '<button class="btn btn-sm" style="background:var(--red);color:#fff;border:none;" ' +
              'onclick="openAppUninstallModal(' + attrJSON(app.id) + ',' + attrJSON(app.name) + ')">Uninstall</button>'
            : '<span style="color:var(--text-muted);font-size:0.75rem;">protected</span>') +
        '</td>' +
        '</tr>';
    }).join('');

    el.innerHTML =
      '<table style="width:100%;border-collapse:collapse;">' +
        '<thead>' +
          '<tr style="border-bottom:2px solid var(--border);">' +
            '<th style="padding:0.5rem 1rem;text-align:left;font-size:0.75rem;color:var(--text-muted);font-weight:600;"></th>' +
            '<th style="padding:0.5rem 1rem;text-align:left;font-size:0.75rem;color:var(--text-muted);font-weight:600;">Application</th>' +
            '<th style="padding:0.5rem 1rem;text-align:left;font-size:0.75rem;color:var(--text-muted);font-weight:600;">Version</th>' +
            '<th style="padding:0.5rem 1rem;text-align:left;font-size:0.75rem;color:var(--text-muted);font-weight:600;">Manager</th>' +
            '<th style="padding:0.5rem 1rem;text-align:left;font-size:0.75rem;color:var(--text-muted);font-weight:600;">Size</th>' +
            '<th style="padding:0.5rem 1rem;text-align:left;font-size:0.75rem;color:var(--text-muted);font-weight:600;">Status</th>' +
            '<th style="padding:0.5rem 1rem;text-align:right;font-size:0.75rem;color:var(--text-muted);font-weight:600;">Action</th>' +
          '</tr>' +
        '</thead>' +
        '<tbody>' + rows + '</tbody>' +
      '</table>';
  }

  function openAppUninstallModal(appId, appName) {
    appsPendingUninstall = { id: appId, name: appName };
    var desc = document.getElementById("appUninstallDesc");
    if (desc) {
      desc.innerHTML =
        'You are about to <strong>completely remove ' + escapeHtml(appName) + '</strong> from this server.<br><br>' +
        'This will stop any running processes, run the package manager uninstall, ' +
        'and delete all related configuration files and cache directories. ' +
        '<strong style="color:var(--red);">This action cannot be undone.</strong>';
    }
    var modal = document.getElementById("appUninstallModal");
    if (modal) modal.style.display = "flex";
  }

  function closeAppUninstallModal() {
    appsPendingUninstall = null;
    var modal = document.getElementById("appUninstallModal");
    if (modal) modal.style.display = "none";
  }

  async function executeUninstall() {
    if (!appsPendingUninstall) return;
    var btn = document.getElementById("appUninstallConfirmBtn");
    if (btn) { btn.disabled = true; btn.textContent = "Uninstalling…"; }

    try {
      var resp = await apiFetch("/api/apps/uninstall", {
        method: "POST",
        body: { app_id: appsPendingUninstall.id }
      });
      var data = (resp && resp.data) ? resp.data : resp;
      closeAppUninstallModal();
      var msg = escapeHtml(data.app_name || appsPendingUninstall.name) + ' removed — ' +
        data.steps_done + ' step(s) completed';
      if (data.removed_paths && data.removed_paths.length > 0) {
        msg += ', paths deleted: ' + data.removed_paths.map(escapeHtml).join(', ');
      }
      if (data.warnings && data.warnings.length > 0) {
        msg += '. Warnings: ' + data.warnings.map(escapeHtml).join('; ');
        showToast(msg, "warning");
      } else {
        showToast(msg, "success");
      }
      loadApps(); // Refresh the list
    } catch(err) {
      showToast("Uninstall failed: " + escapeHtml(err.message), "error");
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = "Yes, uninstall completely"; }
    }
  }

  // Close modal when clicking the backdrop.
  onEl("appUninstallModal", "click", function(e) {
    if (e.target === this) closeAppUninstallModal();
  });

  // ── Managed Applications ──

  async function loadManagedApps() {
    var el = document.getElementById("managedAppsContent");
    if (!el) return;
    el.innerHTML = '<div class="spinner"><div class="spinner-ring"></div>Loading managed applications...</div>';
    try {
      var resp = await apiFetch("/api/managed-apps");
      var appsList = (resp && resp.data) ? resp.data : [];
      if (!Array.isArray(appsList)) appsList = [];
      renderManagedApps(appsList);
    } catch(err) {
      el.innerHTML = '<p style="padding:1rem;color:var(--red);">Error: ' + escapeHtml(err.message) + '</p>';
    }
  }

  function renderManagedApps(apps) {
    var el = document.getElementById("managedAppsContent");
    if (!el) return;
    if (!Array.isArray(apps)) apps = [];

    if (apps.length === 0) {
      el.innerHTML = '<p style="padding:1.25rem;color:var(--text-secondary);">No managed applications yet. Click <strong>Create Application</strong> to get started.</p>';
      return;
    }

    var cards = apps.map(function(app) {
      var envBadges = (app.env_files || []).map(function(f) {
        return '<span style="display:inline-flex;align-items:center;gap:4px;padding:3px 10px;border-radius:6px;background:var(--bg-primary);border:1px solid var(--border);font-family:monospace;font-size:0.75rem;color:var(--text-secondary);cursor:pointer;" ' +
          'onclick="openEditEnvFile(\'' + escapeHtml(app.name) + '\',\'' + escapeHtml(f) + '\')" title="Click to edit">' +
          '<svg width="12" height="12" viewBox="0 0 16 16" fill="var(--accent)" style="flex-shrink:0;"><path d="M2 4a2 2 0 012-2h4.586a1 1 0 01.707.293l3.414 3.414a1 1 0 01.293.707V12a2 2 0 01-2 2H4a2 2 0 01-2-2V4z"/></svg>' +
          escapeHtml(f) +
          '<button onclick="event.stopPropagation();deleteEnvFile(\'' + escapeHtml(app.name) + '\',\'' + escapeHtml(f) + '\')" ' +
            'style="background:none;border:none;color:var(--text-muted);cursor:pointer;padding:0;margin-left:4px;font-size:0.875rem;line-height:1;" title="Delete file">&times;</button>' +
        '</span>';
      }).join(' ');

      var created = app.created_at ? new Date(app.created_at).toLocaleDateString() : '—';

      return '<div style="padding:1rem 1.25rem;border-bottom:1px solid var(--border);">' +
        '<div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:0.5rem;margin-bottom:0.5rem;">' +
          '<div style="display:flex;align-items:center;gap:0.75rem;">' +
            '<span style="font-size:1.25rem;">📂</span>' +
            '<div>' +
              '<div style="font-weight:600;color:var(--text-primary);">' + escapeHtml(app.name) + '</div>' +
              '<div style="font-family:monospace;font-size:0.6875rem;color:var(--text-muted);">' + escapeHtml(app.path) + '</div>' +
            '</div>' +
          '</div>' +
          '<div style="display:flex;align-items:center;gap:0.5rem;">' +
            '<span style="font-size:0.6875rem;color:var(--text-muted);">Created ' + escapeHtml(created) + '</span>' +
            '<button class="btn btn-sm btn-outline" onclick="openCreateEnvFileModal(\'' + escapeHtml(app.name) + '\')" style="font-size:0.75rem;">+ .env</button>' +
            '<button class="btn btn-sm btn-outline" onclick="openManagedAppPermsModal(\'' + escapeHtml(app.name) + '\')" style="font-size:0.75rem;">🔒 Permissions</button>' +
            '<button class="btn btn-sm" style="background:var(--red);color:#fff;border:none;font-size:0.75rem;" onclick="openDeleteAppModal(\'' + escapeHtml(app.name) + '\')">Delete</button>' +
          '</div>' +
        '</div>' +
        '<div style="display:flex;flex-wrap:wrap;gap:0.5rem;">' +
          (envBadges || '<span style="font-size:0.75rem;color:var(--text-muted);font-style:italic;">No .env files</span>') +
        '</div>' +
      '</div>';
    }).join('');

    el.innerHTML = cards;
  }

  // ── Create App Modal ──
  function openCreateAppModal() {
    document.getElementById("createAppName").value = "";
    if (createAppEnvEditor) {
      createAppEnvEditor.setFromText("");
    }
    document.getElementById("createAppModal").style.display = "flex";
    setTimeout(function() { document.getElementById("createAppName").focus(); }, 100);
  }

  function closeCreateAppModal() {
    document.getElementById("createAppModal").style.display = "none";
    if (createAppEnvEditor) {
      createAppEnvEditor.setFromText("");
    }
  }

  async function submitCreateApp() {
    var name = document.getElementById("createAppName").value.trim().toLowerCase();
    if (!name) { showToast("App name is required", "error"); return; }
    if (createAppEnvEditor) {
      var envErrors = createAppEnvEditor.validate();
      if (envErrors.length) {
        showToast(envErrors[0], "error");
        return;
      }
    }
    var btn = document.getElementById("createAppBtn");
    btn.disabled = true; btn.textContent = "Creating...";
    try {
      await apiFetch("/api/managed-apps/create", { method: "POST", body: { name: name } });
      if (createAppEnvEditor && !createAppEnvEditor.isEmpty()) {
        await apiFetch("/api/managed-apps/env/save", {
          method: "POST",
          body: { app: name, file_name: ".env", content: createAppEnvEditor.getText() }
        });
      }
      closeCreateAppModal();
      showToast("Application '" + name + "' created at /opt/" + name, "success");
      loadManagedApps();
    } catch(err) {
      showToast("Failed: " + err.message, "error");
    } finally {
      btn.disabled = false; btn.textContent = "Create";
    }
  }

  // ── Create Env File Modal ──
  function openCreateEnvFileModal(appName) {
    document.getElementById("createEnvAppName").value = appName;
    document.getElementById("createEnvPrefix").value = "";
    if (createEnvFileEditor) {
      createEnvFileEditor.setFromText("");
    }
    document.getElementById("createEnvModal").style.display = "flex";
    setTimeout(function() { document.getElementById("createEnvPrefix").focus(); }, 100);
  }

  function closeCreateEnvModal() {
    document.getElementById("createEnvModal").style.display = "none";
    if (createEnvFileEditor) {
      createEnvFileEditor.setFromText("");
    }
  }

  async function submitCreateEnvFile() {
    var appName = document.getElementById("createEnvAppName").value;
    var prefix = document.getElementById("createEnvPrefix").value.trim().toLowerCase();
    if (createEnvFileEditor) {
      var envErrors = createEnvFileEditor.validate();
      if (envErrors.length) {
        showToast(envErrors[0], "error");
        return;
      }
    }
    var btn = document.getElementById("createEnvBtn");
    btn.disabled = true; btn.textContent = "Creating...";
    try {
      var resp = await apiFetch("/api/managed-apps/env/create", { method: "POST", body: { app: appName, prefix: prefix } });
      var data = (resp && resp.data) ? resp.data : resp;
      var fileName = data.file_name || (prefix ? prefix + ".env" : ".env");
      if (createEnvFileEditor && !createEnvFileEditor.isEmpty()) {
        await apiFetch("/api/managed-apps/env/save", {
          method: "POST",
          body: { app: appName, file_name: fileName, content: createEnvFileEditor.getText() }
        });
      }
      closeCreateEnvModal();
      showToast("File '" + fileName + "' created in " + appName, "success");
      loadManagedApps();
    } catch(err) {
      showToast("Failed: " + err.message, "error");
    } finally {
      btn.disabled = false; btn.textContent = "Create File";
    }
  }

  // ── Edit Env File Modal ──
  async function openEditEnvFile(appName, fileName) {
    var modal = document.getElementById("editEnvModal");
    modal.style.display = "flex";
    document.getElementById("editEnvTitle").textContent = "Edit " + fileName;
    document.getElementById("editEnvMeta").textContent = "Loading...";
    if (editEnvEditor) {
      editEnvEditor.setFromText("");
      editEnvEditor.setDisabled(true);
    }
    document.getElementById("editEnvApp").value = appName;
    document.getElementById("editEnvFile").value = fileName;

    try {
      // Fetch plaintext for editing (served over authenticated HTTPS channel).
      var resp = await apiFetch("/api/managed-apps/env?app=" + encodeURIComponent(appName) + "&file=" + encodeURIComponent(fileName) + "&plaintext=1");
      var data = (resp && resp.data) ? resp.data : resp;

      document.getElementById("editEnvMeta").textContent =
        appName + " / " + fileName + " — " + data.size_bytes + " bytes" +
        (data.last_modified ? " — modified " + new Date(data.last_modified).toLocaleString() : "");
      if (editEnvEditor) {
        editEnvEditor.setFromText(data.content || "");
        editEnvEditor.setDisabled(false);
      }

    } catch(err) {
      document.getElementById("editEnvMeta").textContent = "Error: " + err.message;
      if (editEnvEditor) {
        editEnvEditor.setFromText("");
      }
    }
  }

  function closeEditEnvModal() {
    document.getElementById("editEnvModal").style.display = "none";
    if (editEnvEditor) {
      editEnvEditor.setFromText(""); // clear sensitive data from DOM
    }
  }

  async function submitSaveEnvFile() {
    var appName = document.getElementById("editEnvApp").value;
    var fileName = document.getElementById("editEnvFile").value;
    if (!editEnvEditor) {
      showToast("Editor not ready", "error");
      return;
    }
    var envErrors = editEnvEditor.validate();
    if (envErrors.length) {
      showToast(envErrors[0], "error");
      return;
    }
    var content = editEnvEditor.getText();
    var btn = document.getElementById("saveEnvBtn");
    btn.disabled = true; btn.textContent = "Encrypting & Saving...";
    try {
      await apiFetch("/api/managed-apps/env/save", {
        method: "POST",
        body: { app: appName, file_name: fileName, content: content }
      });
      closeEditEnvModal();
      showToast(fileName + " saved successfully", "success");
    } catch(err) {
      showToast("Failed to save: " + err.message, "error");
    } finally {
      btn.disabled = false; btn.textContent = "Save Changes";
    }
  }

  // ── Delete Env File ──
  async function deleteEnvFile(appName, fileName) {
    if (!confirm("Delete " + fileName + " from " + appName + "? This cannot be undone.")) return;
    try {
      await apiFetch("/api/managed-apps/env/delete", { method: "POST", body: { app: appName, file_name: fileName } });
      showToast(fileName + " deleted from " + appName, "success");
      loadManagedApps();
    } catch(err) {
      showToast("Failed: " + err.message, "error");
    }
  }

  // ── Delete App Modal ──
  function openDeleteAppModal(appName) {
    document.getElementById("deleteAppName").value = appName;
    document.getElementById("deleteAppDesc").innerHTML =
      'You are about to <strong>delete the application directory</strong> <code>/opt/' + escapeHtml(appName) + '</code> and <strong>all its .env files</strong>.<br><br>' +
      '<strong style="color:var(--red);">This action cannot be undone.</strong>';
    document.getElementById("deleteAppModal").style.display = "flex";
  }

  function closeDeleteAppModal() {
    document.getElementById("deleteAppModal").style.display = "none";
  }

  async function submitDeleteApp() {
    var appName = document.getElementById("deleteAppName").value;
    var btn = document.getElementById("deleteAppConfirmBtn");
    btn.disabled = true; btn.textContent = "Deleting...";
    try {
      await apiFetch("/api/managed-apps/delete", { method: "POST", body: { name: appName } });
      closeDeleteAppModal();
      showToast("Application '" + appName + "' deleted", "success");
      loadManagedApps();
    } catch(err) {
      showToast("Failed: " + err.message, "error");
    } finally {
      btn.disabled = false; btn.textContent = "Yes, delete everything";
    }
  }

  // Close managed app modals on backdrop click.
  ["createAppModal", "createEnvModal", "editEnvModal", "deleteAppModal", "managedAppPermsModal", "systemAppPermsModal", "sshKeysModal"].forEach(function(id) {
    var m = document.getElementById(id);
    if (m) m.addEventListener("click", function(e) { if (e.target === this) this.style.display = "none"; });
  });

  window.loadManagedApps      = loadManagedApps;
  window.openCreateAppModal   = openCreateAppModal;
  window.closeCreateAppModal  = closeCreateAppModal;
  window.submitCreateApp      = submitCreateApp;
  window.openCreateEnvFileModal = openCreateEnvFileModal;
  window.closeCreateEnvModal  = closeCreateEnvModal;
  window.submitCreateEnvFile  = submitCreateEnvFile;
  window.openEditEnvFile      = openEditEnvFile;
  window.closeEditEnvModal    = closeEditEnvModal;
  window.submitSaveEnvFile    = submitSaveEnvFile;
  window.deleteEnvFile        = deleteEnvFile;
  window.openDeleteAppModal   = openDeleteAppModal;
  window.closeDeleteAppModal  = closeDeleteAppModal;
  window.submitDeleteApp      = submitDeleteApp;

  window.loadApps                = loadApps;
  window.loadDependencies        = loadDependencies;
  window.refreshDependenciesAndApps = refreshDependenciesAndApps;
  window.openAppUninstallModal   = openAppUninstallModal;
  window.closeAppUninstallModal  = closeAppUninstallModal;
  window.executeUninstall        = executeUninstall;
