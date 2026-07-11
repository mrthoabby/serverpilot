/* Permissions */
"use strict";

  // Modals for filesystem ACLs (managed apps) and capability toggles
  // (system apps). All state changes go through the dashboard's CSRF +
  // auth middleware. Dangerous capabilities (Docker group, etc.) require
  // a confirm-token round-trip.

  // System apps the dashboard can attach permissions to. Mirrors the
  // hardcoded catalog in internal/permissions/templates.go. Used by
  // renderApps() to decide whether to show the Permissions button.
  var SYSTEM_PERM_APPS = { "docker": true, "nginx": true };

  var _permsCurrentApp = null;
  var _sysPermsCurrentApp = null;

  async function openManagedAppPermsModal(appName) {
    _permsCurrentApp = appName;
    document.getElementById("permsAppLabel").textContent = appName;
    document.getElementById("permsAppPath").textContent = "/opt/" + appName;
    document.getElementById("permsAppContent").innerHTML = '<div class="spinner"><div class="spinner-ring"></div>Loading…</div>';
    document.getElementById("permsAppCaps").textContent = "";
    document.getElementById("managedAppPermsModal").style.display = "flex";
    await refreshManagedAppPerms(appName);
  }
  function closeManagedAppPermsModal() {
    _permsCurrentApp = null;
    document.getElementById("managedAppPermsModal").style.display = "none";
  }

  async function refreshManagedAppPerms(appName) {
    var capsEl = document.getElementById("permsAppCaps");
    var contentEl = document.getElementById("permsAppContent");
    try {
      var capsResp = await apiFetch("/api/permissions/capabilities");
      var caps = (capsResp && capsResp.data) || {};
      if (!caps.acl) {
        // Two distinct cases. Auto-fixable: missing apt package. Manual:
        // filesystem doesn't support ACLs (requires remount or fstab edit,
        // which we deliberately do NOT one-click — too risky to apply
        // unilaterally from a dashboard).
        if (caps.acl_tools_missing) {
          capsEl.innerHTML =
            '<div style="color:var(--accent);font-size:0.78rem;margin-bottom:6px;">⚠ ' +
              escapeHtml(caps.acl_reason || "ACL tools missing") +
            '</div>' +
            '<button type="button" id="installAclBtn" onclick="installACLSupport()" ' +
              'class="btn btn-sm" style="background:var(--accent);color:#fff;font-size:0.75rem;">' +
              'Install ACL support (apt install acl)' +
            '</button>' +
            '<span id="installAclMsg" style="margin-left:8px;font-size:0.72rem;color:var(--text-muted);"></span>';
          contentEl.innerHTML = '<p style="color:var(--text-muted);">After install, the filesystem grants will become available without restarting the dashboard.</p>';
        } else if (caps.acl_fs_unsupported) {
          var target = caps.acl_mount_target || "/opt";
          capsEl.innerHTML = '<span style="color:var(--red);">⚠ ' + escapeHtml(caps.acl_reason || "Filesystem does not support ACLs") + '</span>';
          contentEl.innerHTML =
            '<p style="color:var(--text-muted);font-size:0.82rem;margin-bottom:8px;">' +
              'The <code>acl</code> package is installed but the filesystem under <code>' + escapeHtml(target) + '</code> is not currently mounted with ACL support. The dashboard intentionally does NOT remount filesystems for you — that touches the boot path. Run these commands by hand on the server:' +
            '</p>' +
            '<pre style="background:var(--bg-input);padding:10px 12px;border-radius:6px;font-size:0.74rem;color:var(--text-primary);overflow-x:auto;border:1px solid var(--border);user-select:all;">' +
              '# 1. Verify which mount holds ' + escapeHtml(target) + ':\n' +
              'mount | grep " $(df ' + escapeHtml(target) + ' | awk \'NR==2{print $NF}\') "\n\n' +
              '# 2. Try a non-persistent remount first:\n' +
              'sudo mount -o remount,acl ' + escapeHtml(target) + '\n\n' +
              '# 3. If step 2 worked, verify:\n' +
              'getfacl ' + escapeHtml(target) + '\n\n' +
              '# 4. If you want it to survive reboots, edit /etc/fstab and add\n' +
              '#    ",acl" to the options column for that mountpoint, then test:\n' +
              'sudo mount -fav    # -f = fake (dry-run), -a = all, -v = verbose' +
            '</pre>' +
            '<p style="color:var(--text-muted);font-size:0.72rem;margin-top:6px;">After fixing, click the lock icon on a managed app again to refresh.</p>';
        } else {
          capsEl.innerHTML = '<span style="color:var(--red);">⚠ ' + escapeHtml(caps.acl_reason || "ACLs not supported") + '</span>';
          contentEl.innerHTML = '<p style="color:var(--text-muted);">POSIX ACL support is required to grant per-user folder permissions.</p>';
        }
        return;
      }
      var resp = await apiFetch("/api/permissions/managed-app?app=" + encodeURIComponent(appName));
      var state = (resp && resp.data) || {};
      var users = Object.keys(state).sort();
      if (users.length === 0) {
        contentEl.innerHTML = '<p style="color:var(--text-muted);">No deploy users yet. Create one in the Users tab first.</p>';
        return;
      }
      contentEl.innerHTML = users.map(function(u) {
        var current = state[u] || "none";
        return '<div style="display:flex;align-items:center;justify-content:space-between;padding:0.5rem 0;border-bottom:1px solid var(--border);">' +
          '<div style="font-family:monospace;color:var(--text-primary);">' + escapeHtml(u) + '</div>' +
          '<div style="display:flex;gap:0;border:1px solid var(--border);border-radius:6px;overflow:hidden;">' +
            ['none','read','write'].map(function(level) {
              var active = current === level;
              return '<button type="button" data-user="' + escapeHtml(u) + '" data-level="' + level + '" ' +
                'onclick="setManagedAppLevel(\'' + escapeHtml(u) + '\',\'' + level + '\')" ' +
                'class="btn" style="padding:4px 12px;font-size:0.72rem;border:none;border-radius:0;' +
                (active ? 'background:var(--accent);color:#fff;' : 'background:var(--bg-input);color:var(--text-muted);') + '">' +
                level + '</button>';
            }).join('') +
          '</div>' +
        '</div>';
      }).join('');
    } catch (err) {
      contentEl.innerHTML = '<p style="color:var(--red);">Failed to load: ' + escapeHtml(err.message || "error") + '</p>';
    }
  }

  async function setManagedAppLevel(username, level) {
    if (!_permsCurrentApp) return;
    try {
      await apiFetch("/api/permissions/fs/grant", {
        method: "POST",
        body: { app: _permsCurrentApp, username: username, level: level }
      });
      showToast("Permission updated for " + username, "success");
      await refreshManagedAppPerms(_permsCurrentApp);
    } catch (err) {
      showToast("Failed: " + (err.message || "error"), "error");
    }
  }

  // installDependency runs a one-click apt install for a hardcoded package
  // slug (see knownDependencies in handlers.go). onSuccess is optional.
  async function installDependency(packageSlug, onSuccess) {
    if (!packageSlug) return false;
    showToast("Installing " + packageSlug + "…", "info");
    try {
      var resp = await fetch("/api/dependencies/install", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-SP-Client": "dashboard",
          "X-SP-Build":  "1",
          "X-SP-Source": "ui"
        },
        body: JSON.stringify({ package: packageSlug })
      });
      if (!resp.ok || !resp.body) {
        throw new Error("install request failed (HTTP " + resp.status + ")");
      }
      var reader = resp.body.getReader();
      var decoder = new TextDecoder();
      var buf = "";
      var success = false;
      while (true) {
        var chunk = await reader.read();
        if (chunk.done) break;
        buf += decoder.decode(chunk.value, { stream: true });
        var idx;
        while ((idx = buf.indexOf("\n\n")) !== -1) {
          var event = buf.slice(0, idx);
          buf = buf.slice(idx + 2);
          if (event.indexOf("event: done") !== -1) {
            success = event.indexOf('"success":true') !== -1;
          }
        }
      }
      if (!success) {
        showToast("Install failed for " + packageSlug, "error");
        return false;
      }
      showToast(packageSlug + " installed", "success");
      if (typeof onSuccess === "function") await onSuccess();
      return true;
    } catch (err) {
      showToast("Install failed: " + (err.message || "error"), "error");
      return false;
    }
  }

  // installACLSupport drives the same SSE-streaming dependency-install
  // endpoint that certbot uses, but for the `acl` apt package. The
  // package list is hardcoded server-side (see knownDependencies) so
  // there is no path for the UI to request an arbitrary package.
  //
  // The SSE response is consumed via fetch + ReadableStream so we can
  // disable the button and surface a small status message while apt-get
  // runs. After "done", we re-fetch /api/permissions/capabilities to
  // confirm ACL is now available, then re-render the modal.
  async function installACLSupport() {
    var btn = document.getElementById("installAclBtn");
    var msg = document.getElementById("installAclMsg");
    if (!btn || !msg) return;
    btn.disabled = true;
    msg.style.color = "var(--text-muted)";
    msg.textContent = "Running apt install acl...";

    try {
      var ok = await installDependency("acl", async function() {
        msg.style.color = "var(--green)";
        msg.textContent = "ACL support installed.";
        if (_permsCurrentApp) await refreshManagedAppPerms(_permsCurrentApp);
      });
      if (!ok) {
        msg.style.color = "#f85149";
        msg.textContent = "apt install acl did not complete successfully.";
      }
    } catch (err) {
      msg.style.color = "#f85149";
      msg.textContent = "Install failed.";
    } finally {
      btn.disabled = false;
    }
  }

  async function openSystemAppPermsModal(appId, appName) {
    _sysPermsCurrentApp = appId;
    document.getElementById("sysPermsAppLabel").textContent = appName;
    document.getElementById("sysPermsContent").innerHTML = '<div class="spinner"><div class="spinner-ring"></div>Loading…</div>';
    document.getElementById("systemAppPermsModal").style.display = "flex";
    await refreshSystemAppPerms(appId);
  }
  function closeSystemAppPermsModal() {
    _sysPermsCurrentApp = null;
    document.getElementById("systemAppPermsModal").style.display = "none";
  }

  async function refreshSystemAppPerms(appId) {
    var contentEl = document.getElementById("sysPermsContent");
    try {
      var resp = await apiFetch("/api/permissions/system-app?app=" + encodeURIComponent(appId));
      var state = (resp && resp.data) || {};
      var caps = state.capabilities || [];
      var usersArr = state.users || [];
      if (caps.length === 0) {
        contentEl.innerHTML = '<p style="color:var(--text-muted);">This app has no manageable capabilities.</p>';
        return;
      }
      if (usersArr.length === 0) {
        contentEl.innerHTML = '<p style="color:var(--text-muted);">No deploy users yet. Create one in the Users tab first.</p>';
        return;
      }
      // Render: matrix with users as rows, capabilities as columns.
      var header = '<tr><th style="text-align:left;padding:0.5rem;font-size:0.72rem;color:var(--text-muted);">User</th>' +
        caps.map(function(c) {
          var dangerBadge = c.dangerous
            ? '<span style="color:var(--red);font-size:0.65rem;margin-left:4px;">⚠</span>' : '';
          return '<th style="text-align:center;padding:0.5rem;font-size:0.72rem;color:var(--text-muted);" title="' + escapeHtml(c.detail || '') + '">' +
            escapeHtml(c.description) + dangerBadge + '</th>';
        }).join('') + '</tr>';
      var rows = usersArr.map(function(u) {
        return '<tr style="border-top:1px solid var(--border);">' +
          '<td style="padding:0.5rem;font-family:monospace;color:var(--text-primary);">' + escapeHtml(u.username) + '</td>' +
          caps.map(function(c) {
            var on = !!(u.capabilities && u.capabilities[c.slug]);
            return '<td style="padding:0.5rem;text-align:center;">' +
              '<input type="checkbox" data-user="' + escapeHtml(u.username) + '" data-cap="' + escapeHtml(c.slug) + '" ' +
              (on ? 'checked' : '') +
              ' onclick="toggleSystemCap(this,\'' + escapeHtml(u.username) + '\',\'' + escapeHtml(c.slug) + '\',' + (c.dangerous ? 'true' : 'false') + ')">' +
            '</td>';
          }).join('') +
        '</tr>';
      }).join('');
      var warnings = caps.filter(function(c){return c.dangerous && c.warning;}).map(function(c) {
        return '<div style="font-size:0.72rem;color:var(--red);margin-top:0.25rem;">⚠ ' + escapeHtml(c.warning) + '</div>';
      }).join('');
      contentEl.innerHTML =
        '<table style="width:100%;border-collapse:collapse;">' + header + rows + '</table>' +
        warnings;
    } catch (err) {
      contentEl.innerHTML = '<p style="color:var(--red);">Failed to load: ' + escapeHtml(err.message || "error") + '</p>';
    }
  }

  async function toggleSystemCap(checkbox, username, capability, dangerous) {
    if (!_sysPermsCurrentApp) return;
    var action = checkbox.checked ? "grant" : "revoke";
    var confirmToken = "";

    if (action === "grant" && dangerous) {
      var ok = window.confirm(
        "This is a privileged grant. " +
        "Granting '" + capability + "' to '" + username + "' is effectively equivalent to root access.\n\n" +
        "Are you sure?"
      );
      if (!ok) {
        checkbox.checked = !checkbox.checked;
        return;
      }
      try {
        var tokResp = await apiFetch("/api/permissions/confirm", {
          method: "POST",
          body: {
            action: "system.grant",
            username: username,
            app: _sysPermsCurrentApp,
            capability: capability
          }
        });
        confirmToken = (tokResp && tokResp.data && tokResp.data.token) || "";
        if (!confirmToken) throw new Error("no token returned");
      } catch (err) {
        checkbox.checked = !checkbox.checked;
        showToast("Could not obtain confirmation token: " + (err.message || "error"), "error");
        return;
      }
    }

    try {
      await apiFetch("/api/permissions/system/grant", {
        method: "POST",
        body: {
          app: _sysPermsCurrentApp,
          capability: capability,
          username: username,
          action: action,
          confirm_token: confirmToken
        }
      });
      showToast("Capability " + (action === "grant" ? "granted" : "revoked") + " for " + username, "success");
      // Remind operator that revoking a group does not affect open sessions.
      if (action === "revoke") {
        // showToast only supports "success"/<other>=error; use success so the
        // ✓ icon renders for this advisory note rather than a misleading ✗.
        showToast("Note: open SSH sessions retain their previous permissions until logout.", "success");
      }
      await refreshSystemAppPerms(_sysPermsCurrentApp);
    } catch (err) {
      checkbox.checked = !checkbox.checked;
      showToast("Failed: " + (err.message || "error"), "error");
    }
  }

  // Expose permissions UI functions to the global scope so inline
  // onclick handlers in the HTML (and in the row-render strings above) can
  // resolve them. Without this they fail under module/scope isolation.
  window.openManagedAppPermsModal  = openManagedAppPermsModal;
  window.closeManagedAppPermsModal = closeManagedAppPermsModal;
  window.setManagedAppLevel        = setManagedAppLevel;
  window.installDependency       = installDependency;
  window.installACLSupport         = installACLSupport;
  window.openSystemAppPermsModal   = openSystemAppPermsModal;
  window.closeSystemAppPermsModal  = closeSystemAppPermsModal;
  window.toggleSystemCap           = toggleSystemCap;
  window.SYSTEM_PERM_APPS          = SYSTEM_PERM_APPS;
