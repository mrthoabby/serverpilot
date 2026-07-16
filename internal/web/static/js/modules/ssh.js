/* SSH keys modal */
"use strict";

  // Shows the public key (live from authorized_keys) and on demand the
  // private key (decrypted from the server-side encrypted vault). Every
  // private-key reveal hits /api/users/ssh-keys/private which is audit-
  // logged on the server side. The textarea is also flagged with no-store
  // so the browser does not cache the response.

  var _sshKeysCurrentUser = null;

  async function openKeysModalForUser(username) {
    _sshKeysCurrentUser = username;
    document.getElementById("sshKeysUserLabel").textContent = username;
    document.getElementById("sshKeysPubArea").value = "Loading…";
    document.getElementById("sshKeysPrivArea").value = "";
    document.getElementById("sshKeysPrivStatus").textContent = "";
    document.getElementById("sshKeysGenSection").style.display = "block";
    document.getElementById("sshKeysModal").style.display = "flex";

    try {
      var keysResp = await apiFetch("/api/users/ssh-keys?username=" + encodeURIComponent(username));
      var keys = (keysResp && keysResp.data) || [];
      document.getElementById("sshKeysPubArea").value = keys.length > 0 ? keys.join("\n") : "(no public keys yet)";
    } catch (err) {
      document.getElementById("sshKeysPubArea").value = "(failed to read authorized_keys)";
    }

    var controls = document.getElementById("sshKeysPrivControls");
    var status = document.getElementById("sshKeysPrivStatus");
    var privArea = document.getElementById("sshKeysPrivArea");
    privArea.value = "";
    controls.innerHTML = "";

    var hasStored = false;
    try {
      var statResp = await apiFetch("/api/users/ssh-keys/vault-status");
      var statMap = (statResp && statResp.data) || {};
      hasStored = !!statMap[username];
    } catch (err) { /* ignore — render as no-stored */ }

    if (!hasStored) {
      status.textContent = "No private key in the vault for this user. Generate one above to store an encrypted copy.";
      return;
    }
    var revealBtn = document.createElement("button");
    revealBtn.type = "button";
    revealBtn.className = "btn btn-sm btn-outline";
    revealBtn.style.fontSize = "0.7rem";
    revealBtn.textContent = "Reveal";
    revealBtn.onclick = revealStoredPrivateKey;
    var copyBtn = document.createElement("button");
    copyBtn.type = "button";
    copyBtn.className = "btn btn-sm btn-outline";
    copyBtn.style.fontSize = "0.7rem";
    copyBtn.textContent = "Copy";
    copyBtn.onclick = function() { copyToClipboardField("sshKeysPrivArea"); };
    var deleteBtn = document.createElement("button");
    deleteBtn.type = "button";
    deleteBtn.className = "btn btn-sm";
    deleteBtn.style.cssText = "background:transparent;color:#f85149;border:1px solid #f8514966;font-size:0.7rem;";
    deleteBtn.textContent = "Forget vault entry";
    deleteBtn.onclick = forgetStoredPrivateKey;
    controls.appendChild(revealBtn);
    controls.appendChild(copyBtn);
    controls.appendChild(deleteBtn);
    status.textContent = "A private key is stored in the encrypted vault. Click Reveal to decrypt and display.";
  }

  function closeKeysModal() {
    _sshKeysCurrentUser = null;
    // Wipe any private key from the DOM before closing so it doesn't
    // linger in the textarea's accessibility tree.
    document.getElementById("sshKeysPrivArea").value = "";
    document.getElementById("sshKeysPubArea").value = "";
    document.getElementById("sshKeysModal").style.display = "none";
  }

  async function revealStoredPrivateKey() {
    if (!_sshKeysCurrentUser) return;
    var status = document.getElementById("sshKeysPrivStatus");
    status.textContent = "Decrypting…";
    try {
      var resp = await apiFetch("/api/users/ssh-keys/private?username=" + encodeURIComponent(_sshKeysCurrentUser));
      var d = (resp && resp.data) || {};
      document.getElementById("sshKeysPrivArea").value = d.private_key || "";
      status.textContent = "Decrypted. This reveal was recorded in the audit journal.";
    } catch (err) {
      status.textContent = "Failed to decrypt: " + ((err && err.message) || "error");
    }
  }

  async function forgetStoredPrivateKey() {
    if (!_sshKeysCurrentUser) return;
    if (!window.confirm("Forget the encrypted private key for '" + _sshKeysCurrentUser + "'? The user keeps SSH access via the public key in authorized_keys; only the dashboard's stored copy is removed.")) {
      return;
    }
    try {
      await apiFetch("/api/users/ssh-keys/private/delete", {
        method: "POST",
        body: { username: _sshKeysCurrentUser }
      });
      showToast("Vault entry removed.", "success");
      // Reopen to refresh the controls.
      await openKeysModalForUser(_sshKeysCurrentUser);
    } catch (err) {
      showToast("Failed: " + ((err && err.message) || "error"), "error");
    }
  }

  async function generateNewKeyForCurrentUser() {
    if (!_sshKeysCurrentUser) return;
    var keyType = document.getElementById("sshKeysGenType").value;
    var comment = document.getElementById("sshKeysGenComment").value.trim();
    var store   = document.getElementById("sshKeysGenStore").checked;
    try {
      var resp = await apiFetch("/api/users/ssh-keys/generate", {
        method: "POST",
        body: {
          username: _sshKeysCurrentUser,
          type: keyType,
          comment: comment,
          store: store,
          create_user: false
        }
      });
      var d = (resp && resp.data) || {};
      // Show the freshly-generated keypair right in the modal so the
      // operator can copy it. We deliberately leave the OLD public keys
      // visible too — the new one was appended, not replaced.
      var prevPub = document.getElementById("sshKeysPubArea").value;
      var newPub  = d.public_key || "";
      document.getElementById("sshKeysPubArea").value = (prevPub && !prevPub.startsWith("(no") ? prevPub + "\n" : "") + newPub;
      document.getElementById("sshKeysPrivArea").value = d.private_key || "";
      document.getElementById("sshKeysPrivStatus").textContent =
        "Private key shown ONCE. Copy it now. " +
        (d.stored ? "A copy was also stored in the encrypted vault." : "Storage was disabled — this is your only chance.");
      showToast("Keypair generated for " + _sshKeysCurrentUser, "success");
    } catch (err) {
      showToast("Generation failed: " + ((err && err.message) || "error"), "error");
    }
  }

  // openShowKeysModal is called from createDeployUser's generate-mode
  // success branch. It seeds the modal with the freshly-returned keys
  // (so the user can copy the private one) before kicking off the live
  // refresh.
  function openShowKeysModal(username, gen) {
    _sshKeysCurrentUser = username;
    document.getElementById("sshKeysUserLabel").textContent = username;
    document.getElementById("sshKeysPubArea").value = gen.public_key || "";
    document.getElementById("sshKeysPrivArea").value = gen.private_key || "";
    document.getElementById("sshKeysPrivStatus").textContent =
      "Private key shown ONCE. Copy it now. " +
      (gen.stored ? "A copy was also stored in the encrypted vault." : "Storage was disabled — this is your only chance.");
    document.getElementById("sshKeysGenSection").style.display = "block";
    document.getElementById("sshKeysPrivControls").innerHTML = "";
    var copyBtn = document.createElement("button");
    copyBtn.type = "button";
    copyBtn.className = "btn btn-sm btn-outline";
    copyBtn.style.fontSize = "0.7rem";
    copyBtn.textContent = "Copy";
    copyBtn.onclick = function() { copyToClipboardField("sshKeysPrivArea"); };
    document.getElementById("sshKeysPrivControls").appendChild(copyBtn);
    document.getElementById("sshKeysModal").style.display = "flex";
  }

  function copyToClipboardField(textareaId) {
    var el = document.getElementById(textareaId);
    if (!el || !el.value) return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(el.value).then(function() {
        showToast("Copied to clipboard", "success");
      }, function() {
        // Fallback for older Safari / non-secure context
        el.select();
        try { document.execCommand("copy"); showToast("Copied to clipboard", "success"); }
        catch(e) { showToast("Copy failed", "error"); }
      });
      return;
    }
    el.select();
    try { document.execCommand("copy"); showToast("Copied to clipboard", "success"); }
    catch(e) { showToast("Copy failed", "error"); }
  }

  window.openKeysModalForUser     = openKeysModalForUser;
  window.closeKeysModal            = closeKeysModal;
  window.revealStoredPrivateKey    = revealStoredPrivateKey;
  window.forgetStoredPrivateKey    = forgetStoredPrivateKey;
  window.generateNewKeyForCurrentUser = generateNewKeyForCurrentUser;
  window.openShowKeysModal         = openShowKeysModal;
  window.copyToClipboardField      = copyToClipboardField;

  // ── Database tab ───────────────────────────────────────────────────────
  // Saved connections + SQL query runner. Connections are managed via
