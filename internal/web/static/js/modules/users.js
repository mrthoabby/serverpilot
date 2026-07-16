/* Deploy/system users + reset password */
"use strict";

  // Lists all OS users (UID >= 1000) with their groups, plus toggles for
  // each group the dashboard is willing to manage (currently `deploy` and
  // `docker`). All toggles go through /api/users/groups/toggle which
  // re-validates the group against the server-side allowlist; the UI is
  // purely a renderer.

  var _systemUsersManageableGroups = {};

  function loadSystemUsers() {
    var wrap = document.getElementById("systemUsersContent");
    if (!wrap) return;
    wrap.innerHTML = '<div class="spinner"><div class="spinner-ring"></div>Loading…</div>';
    apiFetch("/api/users/system").then(function(resp) {
      if (!resp || !resp.success) {
        wrap.innerHTML = '<div class="empty-state"><p>Error loading system users</p></div>';
        return;
      }
      var data = resp.data || {};
      var list = data.users || [];
      _systemUsersManageableGroups = data.manageable_groups || {};
      renderSystemUsers(list);
    }).catch(function(err) {
      wrap.innerHTML = '<div class="empty-state"><p>Error loading system users: ' + escapeHtml((err && err.message) || "error") + '</p></div>';
    });
  }

  function renderSystemUsers(list) {
    var wrap = document.getElementById("systemUsersContent");
    if (!wrap) return;
    if (!Array.isArray(list) || list.length === 0) {
      wrap.innerHTML = '<div class="empty-state"><p>No regular users found on this host.</p></div>';
      return;
    }
    var groupSlugs = Object.keys(_systemUsersManageableGroups).sort();

    var headerCols = '<th>User</th><th style="width:70px;">UID</th><th>Member of</th>' +
      groupSlugs.map(function(g) {
        var meta = _systemUsersManageableGroups[g] || {};
        var dangerBadge = meta.dangerous ? '<span style="color:var(--red);font-size:0.65rem;margin-left:4px;">⚠</span>' : '';
        return '<th style="text-align:center;width:90px;" title="' + escapeHtml(meta.description || "") + '">' +
          escapeHtml(g) + dangerBadge +
        '</th>';
      }).join('') +
      '<th style="width:60px;">Status</th>';

    var rows = list.map(function(u) {
      var memberChips = (u.groups || []).map(function(g) {
        var isManaged = _systemUsersManageableGroups[g] !== undefined;
        var bg = isManaged ? "var(--accent)" : "var(--bg-input)";
        var fg = isManaged ? "#fff" : "var(--text-muted)";
        return '<span style="display:inline-block;padding:1px 7px;border-radius:999px;background:' + bg + ';color:' + fg + ';font-size:0.66rem;font-family:monospace;margin:1px 2px;">' + escapeHtml(g) + '</span>';
      }).join('');
      var toggles = groupSlugs.map(function(g) {
        var meta = _systemUsersManageableGroups[g] || {};
        var on = (u.groups || []).indexOf(g) !== -1;
        return '<td style="text-align:center;">' +
          '<input type="checkbox" ' + (on ? 'checked' : '') + ' ' +
          'onclick="toggleSystemUserGroup(this,&quot;' + escapeHtml(u.username) + '&quot;,&quot;' + escapeHtml(g) + '&quot;,' + (meta.dangerous ? 'true' : 'false') + ')">' +
        '</td>';
      }).join('');
      var managedBadge = u.managed
        ? '<span style="background:#1a3a2a;color:#3fb950;padding:1px 6px;border-radius:4px;font-size:0.66rem;">managed</span>'
        : '<span style="background:#2a2a2a;color:var(--text-muted);padding:1px 6px;border-radius:4px;font-size:0.66rem;">external</span>';
      return '<tr>' +
        '<td><strong style="font-family:monospace;">' + escapeHtml(u.username) + '</strong></td>' +
        '<td style="font-family:monospace;color:var(--text-muted);font-size:0.78rem;">' + u.uid + '</td>' +
        '<td>' + (memberChips || '<span style="color:var(--text-muted);font-size:0.72rem;">—</span>') + '</td>' +
        toggles +
        '<td>' + managedBadge + '</td>' +
      '</tr>';
    }).join('');

    wrap.innerHTML = '<div class="table-wrap"><table><thead><tr>' + headerCols + '</tr></thead><tbody>' + rows + '</tbody></table></div>';
  }

  // toggleSystemUserGroup is the click handler on each toggle. Mirrors the
  // confirm-token dance from toggleSystemCap: dangerous grants need a
  // round-trip to /api/permissions/confirm before /api/users/groups/toggle.
  async function toggleSystemUserGroup(checkbox, username, group, dangerous) {
    var action = checkbox.checked ? "add" : "remove";
    var confirmToken = "";

    if (action === "add" && dangerous) {
      var ok = window.confirm(
        "Adding '" + username + "' to the '" + group + "' group is a privileged grant " +
        "(effectively root for the docker group).\n\nAre you sure?"
      );
      if (!ok) {
        checkbox.checked = !checkbox.checked;
        return;
      }
      try {
        var tokResp = await apiFetch("/api/permissions/confirm", {
          method: "POST",
          body: { action: "groups.add", username: username, app: "", capability: group }
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
      await apiFetch("/api/users/groups/toggle", {
        method: "POST",
        body: { username: username, group: group, action: action, confirm_token: confirmToken }
      });
      showToast(username + (action === "add" ? " added to " : " removed from ") + group, "success");
      if (action === "remove") {
        showToast("Note: open SSH sessions retain their previous groups until logout.", "success");
      }
      await loadSystemUsers();
    } catch (err) {
      checkbox.checked = !checkbox.checked;
      showToast("Failed: " + (err.message || "error"), "error");
    }
  }

  function loadDeployUsers() {
    var wrap = document.getElementById("usersContent");
    if (!wrap) return;
    var tsEl = document.getElementById("ts-users");
    if (tsEl) tsEl.textContent = new Date().toLocaleTimeString();

    apiFetch("/api/users").then(function(data) {
      if (!data || !data.success) {
        wrap.innerHTML = '<div class="empty-state"><p>Error loading users</p></div>';
        return;
      }
      var userList = data.data || [];
      if (userList.length === 0) {
        wrap.innerHTML = '<div class="empty-state"><p>No deploy users created yet. Use the form above to create one.</p></div>';
        return;
      }

      var html = '<div class="table-wrap"><table><thead><tr>' +
        '<th>Username</th><th>Auth</th><th>Created</th><th>Group</th><th style="width:180px;">Actions</th>' +
        '</tr></thead><tbody>';

      userList.forEach(function(u) {
        var created = u.created_at ? new Date(u.created_at).toLocaleDateString() + " " + new Date(u.created_at).toLocaleTimeString() : "—";
        var authBadge = u.ssh_only
          ? '<span style="background:#1a3a2a;color:#3fb950;padding:2px 8px;border-radius:4px;font-size:0.72rem;white-space:nowrap;">SSH Key</span>'
          : '<span style="background:#2a2a1a;color:#d29922;padding:2px 8px;border-radius:4px;font-size:0.72rem;white-space:nowrap;">Password</span>';
        var resetBtn = u.ssh_only
          ? '<button onclick="openAddKeyModal(\'' + escapeHtml(u.username) + '\')" class="btn btn-secondary" style="padding:3px 10px;font-size:0.75rem;" title="Add SSH key">' +
              '<svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor" style="vertical-align:-1px;margin-right:3px;"><path d="M8 2a.5.5 0 01.5.5v5h5a.5.5 0 010 1h-5v5a.5.5 0 01-1 0v-5h-5a.5.5 0 010-1h5v-5A.5.5 0 018 2z"/></svg>Key' +
            '</button>'
          : '<button onclick="openResetModal(\'' + escapeHtml(u.username) + '\')" class="btn btn-secondary" style="padding:3px 10px;font-size:0.75rem;" title="Reset password">' +
              '<svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor" style="vertical-align:-1px;margin-right:3px;">' +
                '<path d="M11.5 1a.5.5 0 010 1h-1.293l3.147 3.146a.5.5 0 01-.708.708L9.5 2.707V4a.5.5 0 01-1 0V1.5a.5.5 0 01.5-.5h2.5zm-6.354 4.854a.5.5 0 10-.708-.708L1.293 8.293A1 1 0 001 9v2a1 1 0 001 1h2a1 1 0 00.707-.293l3.147-3.147a.5.5 0 10-.708-.708L4 11.001H2V9l3.146-3.146z"/>' +
              '</svg>Reset' +
            '</button>';
        var keysBtn = '<button type="button" onclick="openKeysModalForUser(\'' + escapeHtml(u.username) + '\')" class="btn btn-secondary" style="padding:3px 10px;font-size:0.75rem;" title="Show / generate SSH keys">' +
            '<svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor" style="vertical-align:-1px;margin-right:3px;"><path d="M11 1a4 4 0 100 8 4 4 0 000-8zM6.5 5a4.5 4.5 0 119 0c0 1.1-.4 2.1-1 2.9l4.5 4.5L18 14l-1 1-1-1-1 1-1-1L7.9 6c-.9.6-1.9 1-3 1A.6.6 0 015.4 6.4 4.5 4.5 0 016.5 5z"/></svg>Keys' +
          '</button>';
        html += '<tr>' +
          '<td><strong>' + escapeHtml(u.username) + '</strong></td>' +
          '<td>' + authBadge + '</td>' +
          '<td style="color:var(--text-muted);font-size:0.82rem;">' + created + '</td>' +
          '<td><span class="badge badge-running"><span class="badge-dot"></span> deploy</span></td>' +
          '<td>' +
            '<div style="display:flex;gap:6px;flex-wrap:wrap;">' +
              keysBtn +
              resetBtn +
              '<button type="button" onclick="deleteDeployUser(\'' + escapeHtml(u.username) + '\')" class="btn btn-secondary" style="padding:3px 10px;font-size:0.75rem;border-color:#f8514966;color:#f85149;" title="Delete user">' +
                '<svg width="12" height="12" viewBox="0 0 16 16" fill="none" style="vertical-align:-1px;margin-right:3px;">' +
                  '<path d="M4 4l8 8M12 4l-8 8" stroke="#f85149" stroke-width="1.5" stroke-linecap="round"/>' +
                '</svg>Delete' +
              '</button>' +
            '</div>' +
          '</td></tr>';
      });

      html += '</tbody></table></div>';
      wrap.innerHTML = html;
    }).catch(function() {
      wrap.innerHTML = '<div class="empty-state"><p>Error loading users</p></div>';
    });
  }

  // Default mode is "generate" — the simplest and safest path for CI/CD.
  // The form ships ready to receive just a username and emit a private key.
  var _authMode = "generate"; // "password", "ssh", or "generate"

  function setAuthMode(mode) {
    _authMode = mode;
    var passBtn   = document.getElementById("authModePass");
    var sshBtn    = document.getElementById("authModeSSH");
    var genBtn    = document.getElementById("authModeGen");
    var passFields= document.getElementById("passFields");
    var sshFields = document.getElementById("sshFields");
    var genFields = document.getElementById("genFields");

    var setActive = function(btn, on) {
      if (!btn) return;
      btn.style.background = on ? "var(--accent)" : "var(--bg-input)";
      btn.style.color      = on ? "#fff"          : "var(--text-muted)";
    };
    setActive(passBtn, mode === "password");
    setActive(sshBtn,  mode === "ssh");
    setActive(genBtn,  mode === "generate");
    if (passFields) passFields.style.display = (mode === "password") ? "block" : "none";
    if (sshFields)  sshFields.style.display  = (mode === "ssh")      ? "block" : "none";
    if (genFields)  genFields.style.display  = (mode === "generate") ? "block" : "none";
  }

  function createDeployUser() {
    var nameEl = document.getElementById("newUserName");
    var msgEl = document.getElementById("createUserMsg");
    var btn = document.getElementById("btnCreateUser");
    var username = nameEl.value.trim();

    if (!username) { msgEl.style.color = "#f85149"; msgEl.textContent = "Username required"; return; }

    // Sync hidden username field so the browser can associate the password
    // with the correct account in its password manager.
    var hiddenUser = document.getElementById("newUserPassUsername");
    if (hiddenUser) hiddenUser.value = username;

    if (_authMode === "generate") {
      btn.disabled = true;
      msgEl.style.color = "var(--text-muted)";
      msgEl.textContent = "Generating keypair...";

      // Sane defaults if the operator doesn't expand "Advanced options".
      // Reading from the DOM with fallbacks lets the form work even when
      // the <details> is collapsed (which in some legacy browsers may
      // skip rendering its children) AND keeps the simple flow
      // "username only -> private key" working without surprises.
      var keyTypeEl = document.getElementById("newUserKeyType");
      var commentEl = document.getElementById("newUserKeyComment");
      var storeEl   = document.getElementById("newUserKeyStore");
      var keyType = keyTypeEl ? keyTypeEl.value : "ed25519";
      var comment = commentEl ? commentEl.value.trim() : "";
      var store   = storeEl ? storeEl.checked : true;
      // We need the user to exist before we can generate, but the existing
      // CreateSSHUser path requires a public key. To avoid a server-side
      // refactor we generate first, take the public key, and POST it as
      // the initial key. This keeps the create contract untouched.
      apiFetch("/api/users/ssh-keys/generate", {
        method: "POST",
        body: {
          username: username,
          type: keyType,
          comment: comment,
          store: store,
          create_user: true
        }
      }).then(function(data) {
        btn.disabled = false;
        if (data && data.success) {
          msgEl.style.color = "#3fb950";
          msgEl.textContent = "User '" + username + "' created with generated keypair.";
          nameEl.value = "";
          loadDeployUsers();
          openShowKeysModal(username, data.data || {});
          setTimeout(function() { msgEl.textContent = ""; }, 4000);
        } else {
          msgEl.style.color = "#f85149";
          msgEl.textContent = (data && data.error) || "Failed to generate keypair";
        }
      }).catch(function(err) {
        btn.disabled = false;
        msgEl.style.color = "#f85149";
        msgEl.textContent = "Generation failed: " + ((err && err.message) || "error");
      });
      return;
    }

    var body;
    if (_authMode === "ssh") {
      var keyEl = document.getElementById("newUserSSHKey");
      var sshKey = keyEl.value.trim();
      if (!sshKey) { msgEl.style.color = "#f85149"; msgEl.textContent = "SSH public key required"; return; }
      body = { username: username, ssh_only: true, ssh_key: sshKey };
    } else {
      var passEl = document.getElementById("newUserPass");
      var password = passEl.value;
      if (password.length < 8) { msgEl.style.color = "#f85149"; msgEl.textContent = "Password must be at least 8 chars"; return; }
      body = { username: username, password: password };
    }

    btn.disabled = true;
    msgEl.style.color = "var(--text-muted)";
    msgEl.textContent = "Creating...";

    apiFetch("/api/users/create", {
      method: "POST",
      body: body
    }).then(function(data) {
      btn.disabled = false;
      if (data && data.success) {
        msgEl.style.color = "#3fb950";
        msgEl.textContent = "User '" + username + "' created!";
        nameEl.value = "";
        if (_authMode === "ssh") {
          document.getElementById("newUserSSHKey").value = "";
        } else {
          document.getElementById("newUserPass").value = "";
        }
        loadDeployUsers();
        setTimeout(function() { msgEl.textContent = ""; }, 4000);
      } else {
        msgEl.style.color = "#f85149";
        msgEl.textContent = (data && data.error) || "Failed to create user";
      }
    }).catch(function() {
      btn.disabled = false;
      msgEl.style.color = "#f85149";
      msgEl.textContent = "Connection error";
    });
  }

  // Add SSH Key modal for existing SSH-only users.
  var _addKeyTarget = "";

  function openAddKeyModal(username) {
    _addKeyTarget = username;
    var msg = "Add SSH public key for user '" + username + "':\\n\\n" +
      "Paste the public key (ssh-ed25519, ssh-rsa, etc.):";
    var key = prompt(msg);
    if (!key || !key.trim()) return;

    apiFetch("/api/users/ssh-keys/add", {
      method: "POST",
      body: { username: username, ssh_key: key.trim() }
    }).then(function(data) {
      if (data && data.success) {
        alert("SSH key added for '" + username + "'");
      } else {
        alert("Error: " + ((data && data.error) || "Failed to add key"));
      }
    }).catch(function() { alert("Connection error"); });
  }

  function deleteDeployUser(username) {
    if (!confirm("Delete user '" + username + "'?\n\nThis removes the Linux user and their home directory permanently.")) return;

    apiFetch("/api/users/delete", {
      method: "POST",
      body: { username: username }
    }).then(function(data) {
      if (data && data.success) {
        loadDeployUsers();
      } else {
        alert("Error: " + ((data && data.error) || "Failed to delete user"));
      }
    }).catch(function() { alert("Connection error"); });
  }

  // ── Reset Password Modal ──
  var _resetTarget = "";

  function openResetModal(username) {
    _resetTarget = username;
    document.getElementById("resetPassUser").textContent = username;
    document.getElementById("resetPassInput").value = "";
    document.getElementById("resetPassMsg").textContent = "";
    // Keep the hidden username field in sync so password managers associate
    // the new password with the right account (browser accessibility requirement).
    var hidden = document.getElementById("resetPassUserHidden");
    if (hidden) hidden.value = username;
    var modal = document.getElementById("resetPassModal");
    modal.style.display = "flex";
  }

  function closeResetModal() {
    document.getElementById("resetPassModal").style.display = "none";
    _resetTarget = "";
  }

  function submitResetPassword() {
    var passEl = document.getElementById("resetPassInput");
    var msgEl = document.getElementById("resetPassMsg");
    var btn = document.getElementById("btnResetPass");
    var newPass = passEl.value;

    if (newPass.length < 8) { msgEl.style.color = "#f85149"; msgEl.textContent = "Password must be at least 8 chars"; return; }

    btn.disabled = true;
    msgEl.style.color = "var(--text-muted)";
    msgEl.textContent = "Resetting...";

    apiFetch("/api/users/reset-password", {
      method: "POST",
      body: { username: _resetTarget, password: newPass }
    }).then(function(data) {
      btn.disabled = false;
      if (data && data.success) {
        msgEl.style.color = "#3fb950";
        msgEl.textContent = "Password reset successfully!";
        setTimeout(function() { closeResetModal(); }, 1500);
      } else {
        msgEl.style.color = "#f85149";
        msgEl.textContent = (data && data.error) || "Failed to reset password";
      }
    }).catch(function() {
      btn.disabled = false;
      msgEl.style.color = "#f85149";
      msgEl.textContent = "Connection error";
    });
  }

  // Toggle password visibility for any input by id.
  function passwordToggleIcon(showVisible) {
    if (showVisible) {
      return '<svg width="18" height="18" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 3.5C4.136 3.5 1.04 6.008.152 7.59a.796.796 0 000 .82C1.04 9.992 4.136 12.5 8 12.5s6.96-2.508 7.848-4.09a.796.796 0 000-.82C14.96 6.008 11.864 3.5 8 3.5zM8 11a3 3 0 110-6 3 3 0 010 6z"/><circle cx="8" cy="8" r="1.5"/></svg>';
    }
    return '<svg width="18" height="18" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M13.177 13.177L2.823 2.823M6.47 6.47C6.17 6.77 6 7.17 6 7.6c0 .93.75 1.68 1.68 1.68.43 0 .83-.17 1.13-.47M11.53 11.53C10.62 12.2 9.36 12.6 8 12.6c-3.864 0-6.96-2.508-7.848-4.09a.796.796 0 010-.82C1.04 6.008 4.136 3.5 8 3.5c1.36 0 2.62.4 3.53 1.07M8 5.2A2.4 2.4 0 008 9.8" stroke="currentColor" stroke-width="1.2" fill="none" stroke-linecap="round"/></svg>';
  }

  function togglePasswordVis(inputId, btn) {
    var input = document.getElementById(inputId);
    if (!input) return;
    var show = input.type === "password";
    input.type = show ? "text" : "password";
    if (btn) {
      btn.innerHTML = passwordToggleIcon(show);
      btn.setAttribute("aria-label", show ? "Ocultar contraseña" : "Mostrar contraseña");
      btn.title = show ? "Ocultar contraseña" : "Mostrar contraseña";
    }
  }

  // Close reset modal on backdrop click.
  onEl("resetPassModal", "click", function(e) {
    if (e.target === this) closeResetModal();
  });

  window.setAuthMode             = setAuthMode;
  window.createDeployUser        = createDeployUser;
  window.togglePasswordVis       = togglePasswordVis;
  window.openAddKeyModal         = openAddKeyModal;
  window.openResetModal          = openResetModal;
  window.closeResetModal         = closeResetModal;
  window.submitResetPassword     = submitResetPassword;
  window.deleteDeployUser        = deleteDeployUser;
  window.loadDeployUsers         = loadDeployUsers;
  window.loadSystemUsers         = loadSystemUsers;
  window.toggleSystemUserGroup   = toggleSystemUserGroup;

