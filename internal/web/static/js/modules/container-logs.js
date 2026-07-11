/* Container logs modal */
"use strict";

  var containerLogsBody  = document.getElementById("containerLogsBody");
  var containerLogsTitle = document.getElementById("containerLogsTitle");
  var _logsPendingContainer = null;

  function closeContainerLogsModal() {
    containerLogsModal.classList.remove("show");
    _logsPendingContainer = null;
  }

  async function loadContainerLogs(container) {
    // textContent is XSS-safe; we never inject raw HTML from the log payload.
    containerLogsBody.textContent = "Loading…";
    try {
      // The id field comes from /api/containers (Docker --no-trunc), which is a
      // pure hex sha. The server validates it again with a hex-only regex
      // before handing it to `docker logs` (CWE-78 defence in depth).
      var resp = await apiFetch("/api/containers/logs?id=" + encodeURIComponent(container.id));
      var data = (resp && resp.data) ? resp.data : {};
      var text = data.logs || "";
      containerLogsBody.textContent = text.length ? text : "(no logs)";
    } catch(err) {
      containerLogsBody.textContent = "Failed to load logs: " + err.message;
    }
  }

  function openContainerLogsModal(container) {
    _logsPendingContainer = container;
    setText(containerLogsTitle, container.name);
    containerLogsModal.classList.add("show");
    loadContainerLogs(container);
  }

  async function clearContainerLogs(container) {
    // apiFetch already sets Content-Type and the CSRF-relevant Origin header.
    // The server enforces CSRFMiddleware on every state-changing request, so
    // the POST below is rejected if the Origin/Referer doesn't match.
    try {
      await apiFetch("/api/containers/logs/clear", {
        method: "POST",
        body: { id: container.id }
      });
      showToast("Logs limpiados para " + container.name, "success");
      // Re-fetch to confirm the cleared state in the modal.
      loadContainerLogs(container);
    } catch(err) {
      showToast("No se pudieron limpiar los logs: " + err.message, "error");
    }
  }

  var _reloadEnvApps = [];

  async function reloadContainerEnv(container) {
    if (!container || !container.id) {
      showToast("Container id not available", "error");
      return;
    }
    document.getElementById("reloadEnvContainerId").value = container.id;
    document.getElementById("reloadEnvContainerName").value = container.name || "";
    setText(document.getElementById("reloadEnvModalSub"), "Recreate \"" + (container.name || "container") + "\" with a managed app environment file.");
    await populateReloadEnvApps();
    document.getElementById("reloadEnvModal").classList.add("show");
  }

  async function populateReloadEnvApps() {
    var appSel = document.getElementById("reloadEnvApp");
    var fileSel = document.getElementById("reloadEnvFile");
    var submitBtn = document.getElementById("reloadEnvSubmitBtn");
    appSel.innerHTML = "";
    fileSel.innerHTML = "";
    submitBtn.disabled = true;
    try {
      var resp = await apiFetch("/api/managed-apps");
      _reloadEnvApps = (resp && resp.data) ? resp.data : [];
      if (!Array.isArray(_reloadEnvApps)) _reloadEnvApps = [];
    } catch(err) {
      showToast("Failed to load applications: " + err.message, "error");
      _reloadEnvApps = [];
    }
    _reloadEnvApps = _reloadEnvApps.filter(function(app) {
      return app && app.name && app.env_files && app.env_files.length;
    });
    if (!_reloadEnvApps.length) {
      var opt = document.createElement("option");
      opt.value = "";
      setText(opt, "No apps with .env files");
      appSel.appendChild(opt);
      return;
    }
    submitBtn.disabled = false;
    _reloadEnvApps.forEach(function(app) {
      var opt = document.createElement("option");
      opt.value = app.name;
      setText(opt, app.name);
      appSel.appendChild(opt);
    });
    updateReloadEnvFiles();
  }

  function updateReloadEnvFiles() {
    var appName = document.getElementById("reloadEnvApp").value;
    var fileSel = document.getElementById("reloadEnvFile");
    fileSel.innerHTML = "";
    var app = _reloadEnvApps.find(function(a) { return a.name === appName; });
    ((app && app.env_files) || []).forEach(function(fileName) {
      var opt = document.createElement("option");
      opt.value = fileName;
      setText(opt, fileName);
      fileSel.appendChild(opt);
    });
  }

  onEl("reloadEnvApp", "change", updateReloadEnvFiles);
  onEl("reloadEnvCancelBtn", "click", function() {
    document.getElementById("reloadEnvModal").classList.remove("show");
  });
  onEl("reloadEnvModal", "click", function(e) {
    if (e.target === document.getElementById("reloadEnvModal")) {
      document.getElementById("reloadEnvModal").classList.remove("show");
    }
  });
  onEl("reloadEnvForm", "submit", async function(e) {
    e.preventDefault();
    var id = document.getElementById("reloadEnvContainerId").value;
    var name = document.getElementById("reloadEnvContainerName").value;
    var appName = document.getElementById("reloadEnvApp").value;
    var fileName = document.getElementById("reloadEnvFile").value;
    if (!appName || !fileName) {
      showToast("Choose an application environment", "error");
      return;
    }
    document.getElementById("reloadEnvModal").classList.remove("show");
    confirmAction(
      "Reload environment",
      "This recreates \"" + name + "\" with " + appName + "/" + fileName + ". The container will briefly stop. Continue?",
      async function() {
        try {
          await apiFetch("/api/containers/reload-env", {
            method: "POST",
            body: { id: id, app: appName, file_name: fileName }
          });
          showToast("Container recreated with " + fileName + ": " + name, "success");
          await Promise.all([loadContainers(), loadMappings()]);
        } catch(err) {
          showToast("Failed to reload env: " + err.message, "error");
        }
      }
    );
  });

  onEl("containerLogsCloseBtn", "click", closeContainerLogsModal);
  onEl("containerLogsRefreshBtn", "click", function() {
    if (_logsPendingContainer) loadContainerLogs(_logsPendingContainer);
  });
  onEl("containerLogsClearBtn", "click", function() {
    if (!_logsPendingContainer) return;
    var c = _logsPendingContainer;
    // Destructive: confirm before truncating. Use the existing confirmAction
    // modal so the look-and-feel matches every other destructive flow.
    confirmAction(
      "Limpiar logs",
      "Esto vacía el archivo de logs de \"" + c.name + "\". Los registros previos no se pueden recuperar. ¿Continuar?",
      function() { clearContainerLogs(c); }
    );
  });
  onEl("containerLogsModal", "click", function(e) {
    var modal = document.getElementById("containerLogsModal");
    if (e.target === modal) closeContainerLogsModal();
  });

  // ── Associate Site Modal ──
  var redirectModal = document.getElementById("redirectModal");
