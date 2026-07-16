/* Associate site + config editor */
"use strict";

  var redirectDelayed = document.getElementById("redirectDelayed");
  var redirectDelayOptions = document.getElementById("redirectDelayOptions");
  function updateRedirectDelayOptions() {
    if (!redirectDelayOptions || !redirectDelayed) return;
    redirectDelayOptions.style.display = redirectDelayed.checked ? "block" : "none";
  }
  onEl("redirectDelayed", "change", updateRedirectDelayOptions);
  onEl("repairNginxBtn", "click", async function() {
    if (!window.confirm("Scan nginx configs, remove duplicate proxy directives, and reload nginx?")) return;
    var btn = document.getElementById("repairNginxBtn");
    btn.disabled = true;
    try {
      var resp = await apiFetch("/api/nginx/repair", { method: "POST" });
      var data = (resp && resp.data) ? resp.data : {};
      var fixed = data.fixed || [];
      if (data.ok) {
        showToast(fixed.length ? ("Nginx repaired: " + fixed.join("; ")) : "Nginx config is valid", "success");
      } else {
        showToast("Repair incomplete: " + (data.remaining_error || "nginx test still failing"), "error");
      }
      await loadSites();
    } catch (err) {
      showToast("Repair failed: " + ((err && err.message) || "error"), "error");
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

  // ── Progress / Log Modal ──
  var progressModal = document.getElementById("progressModal");
