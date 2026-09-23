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
