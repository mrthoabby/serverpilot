/* Progress, confirm, GD-App modals */
"use strict";

  var progressLog = document.getElementById("progressLog");
  var progressSpinner = document.getElementById("progressSpinner");
  var progressStatusText = document.getElementById("progressStatusText");
  var progressCloseBtn = document.getElementById("progressCloseBtn");
  var progressInstallBtn = document.getElementById("progressInstallBtn");
  var progressBackgroundBtn = document.getElementById("progressBackgroundBtn");
  var currentEventSource = null;
  var currentJobId = null;
  var lastStreamedUrl = "";
  var lastStreamedBody = null;
  var lastStreamedTitle = "";
  var lastStreamedSubtitle = "";

  function openProgressModal(title, subtitle) {
    setText(document.getElementById("progressTitle"), title);
    setText(document.getElementById("progressSubtitle"), subtitle || "");
    progressLog.innerHTML = "";
    progressSpinner.style.display = "inline-block";
    setText(progressStatusText, "Working...");
    progressCloseBtn.style.display = "none";
    progressInstallBtn.style.display = "none";
    if (progressBackgroundBtn) progressBackgroundBtn.style.display = "inline-flex";
    currentJobId = null;
    showPruneProgressBar(false);
    progressModal.classList.add("show");
  }

  function showPruneProgressBar(show) {
    var wrap = document.getElementById("progressPruneBarWrap");
    if (wrap) wrap.style.display = show ? "block" : "none";
    if (!show) {
      var fill = document.getElementById("progressPruneBarFill");
      var statsEl = document.getElementById("progressPruneBarStats");
      if (fill) fill.style.width = "0%";
      if (statsEl) statsEl.textContent = "";
    }
  }

  function appendLogLine(text) {
    var line = document.createElement("div");
    // Color-code lines based on content.
    if (text.indexOf("ERROR") !== -1) {
      line.className = "log-error";
    } else if (text.indexOf("WARNING") !== -1) {
      line.className = "log-warning";
    } else if (/^\[Step/.test(text)) {
      line.className = "log-step";
    } else if (text.indexOf("successfully") !== -1 || text.indexOf("enabled") !== -1 || text.indexOf("removed!") !== -1 || text.indexOf("deleted") !== -1) {
      line.className = "log-success";
    }
    setText(line, text);
    progressLog.appendChild(line);
    progressLog.scrollTop = progressLog.scrollHeight;
  }

  function finishProgress(success, message, depMissing) {
    progressSpinner.style.display = "none";
    if (progressBackgroundBtn) progressBackgroundBtn.style.display = "none";
    currentJobId = null;
    if (success) {
      setText(progressStatusText, "Completed successfully");
      progressStatusText.style.color = "var(--green)";
    } else {
      setText(progressStatusText, "Failed: " + (message || "unknown error"));
      progressStatusText.style.color = "var(--red)";
    }
    progressCloseBtn.style.display = "inline-flex";
    // Show "Install & Retry" button when a dependency is missing.
    if (depMissing) {
      progressInstallBtn.style.display = "inline-flex";
      progressInstallBtn.onclick = function() {
        progressInstallBtn.style.display = "none";
        progressCloseBtn.style.display = "none";
        progressSpinner.style.display = "inline-block";
        setText(progressStatusText, "Installing " + depMissing + "...");
        progressStatusText.style.color = "";
        appendLogLine("");
        appendLogLine("--- Installing " + depMissing + " ---");
        // Call the install endpoint.
        fetch("/api/dependencies/install", prepareApiFetchOptions({
          method: "POST",
          body: { "package": depMissing }
        })).then(function(response) {
          var reader = response.body.getReader();
          var decoder = new TextDecoder();
          var buf = "";
          function readChunk() {
            return reader.read().then(function(result) {
              if (result.done) {
                if (buf.trim()) processSSEBuffer(buf);
                return;
              }
              buf += decoder.decode(result.value, { stream: true });
              var parts = buf.split("\n\n");
              buf = parts.pop();
              parts.forEach(function(part) {
                // Parse install events inline (don't trigger finishProgress yet).
                var evt = "message", data = "";
                part.split("\n").forEach(function(line) {
                  if (line.indexOf("event: ") === 0) evt = line.substring(7).trim();
                  else if (line.indexOf("data: ") === 0) data = line.substring(6);
                });
                if (evt === "log" && data) {
                  try { appendLogLine(JSON.parse(data)); } catch(e) { appendLogLine(data); }
                } else if (evt === "done" && data) {
                  try {
                    var res = JSON.parse(data);
                    if (res.success) {
                      appendLogLine("");
                      appendLogLine("--- Retrying original operation ---");
                      appendLogLine("");
                      // Retry the original operation.
                      runStreamedOperation(lastStreamedUrl, lastStreamedBody, lastStreamedTitle, lastStreamedSubtitle);
                    } else {
                      finishProgress(false, "Installation failed: " + (res.error || ""));
                    }
                  } catch(e) {
                    finishProgress(false, "Installation failed");
                  }
                }
              });
              return readChunk();
            });
          }
          return readChunk();
        }).catch(function(err) {
          finishProgress(false, "Install request failed: " + err.message);
        });
      };
    } else {
      progressInstallBtn.style.display = "none";
    }
  }

  function closeProgressModal() {
    progressModal.classList.remove("show");
    progressStatusText.style.color = "";
    if (currentEventSource) {
      currentEventSource.close();
      currentEventSource = null;
    }
  }

  // Send the running operation to the background: hide the modal but keep the
  // server-side operation going. The jobs indicator keeps it visible and the
  // user can reopen it later. Never cancels the operation.
  function sendProgressToBackground() {
    var running = progressSpinner && progressSpinner.style.display !== "none";
    closeProgressModal();
    if (running) {
      if (typeof showToast === "function") {
        showToast("El proceso sigue ejecut\u00e1ndose en segundo plano", "success");
      }
      if (window.SP && SP.jobs && SP.jobs.refresh) SP.jobs.refresh();
    }
  }

  onEl("progressBackgroundBtn", "click", sendProgressToBackground);

  function refreshCoreTabsAfterMutation() {
    if (typeof invalidateDashboardCoreCache === "function") {
      invalidateDashboardCoreCache();
    }
    return Promise.all([
      loadSites({ force: true }),
      loadMappings({ force: true }),
      loadContainers({ force: true }),
      loadSettings()
    ]);
  }

  onEl("progressCloseBtn", "click", function() {
    closeProgressModal();
    refreshCoreTabsAfterMutation();
  });

  onEl("progressModal", "click", function(e) {
    var modal = document.getElementById("progressModal");
    var closeBtn = document.getElementById("progressCloseBtn");
    if (e.target === modal && closeBtn && closeBtn.style.display !== "none") {
      closeProgressModal();
      refreshCoreTabsAfterMutation();
    }
  });

  // Run an SSE-streamed operation via POST, showing logs in the progress modal.
  function runStreamedOperation(url, body, title, subtitle) {
    lastStreamedUrl = url;
    lastStreamedBody = body;
    lastStreamedTitle = title;
    lastStreamedSubtitle = subtitle;
    openProgressModal(title, subtitle);

    runStreamedFetch(url, body, true).catch(function(err) {
      appendLogLine("ERROR: " + err.message);
      finishProgress(false, err.message);
    });
  }

  function parseStreamedError(response, bodyText) {
    if (bodyText && bodyText.trim()) {
      try {
        var errObj = JSON.parse(bodyText);
        return errObj.error || errObj.message || response.statusText || "request failed";
      } catch(e) {
        return response.statusText || bodyText.slice(0, 200);
      }
    }
    return response.statusText || "request failed";
  }

  function runStreamedFetch(url, body, allowReauth) {
    // We use fetch + ReadableStream instead of EventSource because we need POST.
    return fetch(url, prepareApiFetchOptions({
      method: "POST",
      body: body
    })).then(function(response) {
      if (response.status === 401) {
        showLogin();
        finishProgress(false, "Unauthorized");
        return null;
      }
      if (!response.ok) {
        return response.text().then(function(t) {
          var errText = parseStreamedError(response, t);
          if (response.status === 403 && errText === "recent reauthentication required" && allowReauth) {
            appendLogLine("Recent reauthentication required.");
            return promptReauth().then(function() {
              appendLogLine("Reauthenticated. Retrying operation...");
              return runStreamedFetch(url, body, false);
            });
          }
          appendLogLine("ERROR: Server returned " + response.status);
          appendLogLine(errText);
          finishProgress(false, "Server error " + response.status);
        });
      }

      var reader = response.body.getReader();
      var decoder = new TextDecoder();
      var buffer = "";

      function processChunk() {
        return reader.read().then(function(result) {
          if (result.done) {
            // Process any remaining buffer.
            if (buffer.trim()) processSSEBuffer(buffer);
            return;
          }
          buffer += decoder.decode(result.value, { stream: true });
          // Process complete SSE messages.
          var parts = buffer.split("\n\n");
          buffer = parts.pop(); // keep incomplete part
          parts.forEach(function(part) {
            processSSEBuffer(part);
          });
          return processChunk();
        });
      }

      return processChunk();
    });
  }

  function processSSEBuffer(raw) {
    var event = "message";
    var data = "";
    raw.split("\n").forEach(function(line) {
      if (line.indexOf("event: ") === 0) event = line.substring(7).trim();
      else if (line.indexOf("data: ") === 0) data = line.substring(6);
    });
    if (!data) return;

    if (event === "job") {
      // The server announces the tracked job id so we can reconnect/observe it.
      try { currentJobId = JSON.parse(data); } catch(e) { currentJobId = data; }
      if (window.SP && SP.jobs && SP.jobs.refresh) SP.jobs.refresh();
      return;
    }

    if (event === "log") {
      try {
        var text = JSON.parse(data);
        appendLogLine(text);
      } catch(e) {
        appendLogLine(data);
      }
    } else if (event === "done") {
      try {
        var result = JSON.parse(data);
        finishProgress(result.success !== false, result.error || result.message || "", result.dependency_missing || null);
        if (result.success !== false && lastStreamedUrl && (lastStreamedUrl.indexOf("/api/container-replicas/") === 0 || lastStreamedUrl.indexOf("/api/sites/") === 0 || lastStreamedUrl.indexOf("/api/ssl/") === 0 || lastStreamedUrl.indexOf("/api/compose/") === 0 || lastStreamedUrl.indexOf("/api/containers/release") === 0)) {
          refreshCoreTabsAfterMutation();
        }
      } catch(e) {
        finishProgress(true, "");
      }
      if (window.SP && SP.jobs && SP.jobs.refresh) SP.jobs.refresh();
    }
  }

  // ── Release Modal (compose + container) ──
  var releaseModal = document.getElementById("releaseModal");

  function releaseStrategyStorageKey(kind, target) {
    return "sp-release-strategy:" + kind + ":" + target;
  }

  function toggleReleaseAdvancedFields() {
    var strategy = document.getElementById("releaseStrategy");
    var kind = (document.getElementById("releaseKind") || {}).value || "";
    var isBG = strategy && strategy.value === "blue-green";
    var healthGroup = document.getElementById("releaseHealthGroup");
    var timingGroup = document.getElementById("releaseTimingGroup");
    var ensureDepsGroup = document.getElementById("releaseEnsureDepsGroup");
    if (healthGroup) healthGroup.style.display = isBG ? "block" : "none";
    if (timingGroup) timingGroup.style.display = isBG ? "grid" : "none";
    if (ensureDepsGroup) ensureDepsGroup.style.display = kind === "compose" ? "block" : "none";
  }

  function openReleaseModal(opts) {
    if (!releaseModal) return;
    opts = opts || {};
    var kind = opts.kind || "container";
    var target = opts.target || "";
    document.getElementById("releaseKind").value = kind;
    document.getElementById("releaseTarget").value = target;
    document.getElementById("releaseService").value = opts.service || "app";
    document.getElementById("releaseImage").value = opts.image || "";
    var strategyEl = document.getElementById("releaseStrategy");
    var saved = "";
    try { saved = localStorage.getItem(releaseStrategyStorageKey(kind, target)) || ""; } catch (_) {}
    if (strategyEl) strategyEl.value = saved || opts.strategy || "rolling";
    document.getElementById("releaseHealthURL").value = opts.healthURL || "";
    document.getElementById("releaseHealthTimeout").value = opts.healthTimeout || "60s";
    document.getElementById("releaseDrain").value = opts.drain || "10s";
    var skipEnsureDeps = document.getElementById("releaseSkipEnsureDeps");
    if (skipEnsureDeps) skipEnsureDeps.checked = false;
    setText(document.getElementById("releaseModalTitle"), kind === "compose" ? "Compose release" : "Container release");
    setText(document.getElementById("releaseModalSub"),
      kind === "compose"
        ? ("Update image for compose project \"" + target + "\" (service: " + (opts.service || "app") + ").")
        : ("Blue-green or rolling release for container \"" + target + "\"."));
    toggleReleaseAdvancedFields();
    releaseModal.classList.add("show");
  }

  window.openComposeReleaseModal = function(project, service) {
    openReleaseModal({ kind: "compose", target: project, service: service || "app" });
  };

  window.openContainerReleaseModal = function(container) {
    if (!container) return;
    openReleaseModal({ kind: "container", target: container.name || container.id || "", image: container.image || "" });
  };

  onEl("releaseStrategy", "change", toggleReleaseAdvancedFields);

  onEl("releaseCancelBtn", "click", function() {
    if (releaseModal) releaseModal.classList.remove("show");
  });

  onEl("releaseModal", "click", function(e) {
    if (e.target === releaseModal) releaseModal.classList.remove("show");
  });

  onEl("releaseForm", "submit", function(e) {
    e.preventDefault();
    var kind = document.getElementById("releaseKind").value;
    var target = document.getElementById("releaseTarget").value.trim();
    var image = document.getElementById("releaseImage").value.trim();
    var strategy = document.getElementById("releaseStrategy").value;
    var healthURL = document.getElementById("releaseHealthURL").value.trim();
    var healthTimeout = document.getElementById("releaseHealthTimeout").value.trim() || "60s";
    var drain = document.getElementById("releaseDrain").value.trim() || "10s";
    if (!target || !image) {
      showToast("Image and target are required", "error");
      return;
    }
    try { localStorage.setItem(releaseStrategyStorageKey(kind, target), strategy); } catch (_) {}
    releaseModal.classList.remove("show");

    if (kind === "compose") {
      var skipEnsureDepsEl = document.getElementById("releaseSkipEnsureDeps");
      runStreamedOperation(
        "/api/compose/release",
        {
          name: target,
          service: document.getElementById("releaseService").value || "app",
          app_image_ref: image,
          strategy: strategy,
          health_url: healthURL,
          health_timeout: healthTimeout,
          drain: drain,
          skip_ensure_deps: !!(skipEnsureDepsEl && skipEnsureDepsEl.checked)
        },
        "Compose release",
        target + " — " + strategy
      );
      return;
    }

    if (strategy !== "blue-green") {
      showToast("Standalone container release supports blue-green strategy only (use rolling via image pull/recreate).", "warning");
      return;
    }
    runStreamedOperation(
      "/api/containers/release",
      {
        container: target,
        image: image,
        strategy: strategy,
        health_url: healthURL,
        health_timeout: healthTimeout,
        drain: drain
      },
      "Container release",
      target + " — blue-green"
    );
  });

  // ── Confirm Modal ──
  var confirmModal = document.getElementById("confirmModal");
  var pendingConfirm = null;

  function confirmAction(title, text, callback) {
    setText(document.getElementById("confirmTitle"), title);
    setText(document.getElementById("confirmText"), text);
    pendingConfirm = callback;
    confirmModal.classList.add("show");
  }

  onEl("confirmCancelBtn", "click", function() {
    var modal = document.getElementById("confirmModal");
    if (modal) modal.classList.remove("show");
    pendingConfirm = null;
  });

  onEl("confirmModal", "click", function(e) {
    var modal = document.getElementById("confirmModal");
    if (e.target === modal) {
      modal.classList.remove("show");
      pendingConfirm = null;
    }
  });

  onEl("confirmOkBtn", "click", function() {
    var modal = document.getElementById("confirmModal");
    if (modal) modal.classList.remove("show");
    if (pendingConfirm) {
      pendingConfirm();
      pendingConfirm = null;
    }
  });

  // ── GD-App Activate Modal ──
  var gdappModal = document.getElementById("gdappModal");

  function openGDAppActivateModal(container) {
    document.getElementById("gdappContainerName").value = container.name;
    document.getElementById("gdappDomain").value = "";
    var port = "3010"; // default GD-App port
    if (container.ports && container.ports.length) {
      port = String(container.ports[0].container_port || container.ports[0].host_port || "3010");
    }
    document.getElementById("gdappPort").value = port;
    setText(document.getElementById("gdappModalSub"),
      "Set up full nginx for \"" + container.name + "\" with WebSocket, SSE streaming, SSL, and security headers.");
    gdappModal.classList.add("show");
  }

  onEl("gdappCancelBtn", "click", function() {
    var modal = document.getElementById("gdappModal");
    if (modal) modal.classList.remove("show");
  });

  onEl("gdappModal", "click", function(e) {
    var modal = document.getElementById("gdappModal");
    if (e.target === modal) modal.classList.remove("show");
  });

  onEl("gdappForm", "submit", function(e) {
    e.preventDefault();
    var domain = document.getElementById("gdappDomain").value.trim();
    var port = parseInt(document.getElementById("gdappPort").value, 10);
    var containerName = document.getElementById("gdappContainerName").value;

    if (!domain) {
      showToast("Enter a domain", "error");
      return;
    }
    if (!port || port < 1 || port > 65535) {
      showToast("Invalid port number", "error");
      return;
    }

    gdappModal.classList.remove("show");

    runStreamedOperation(
      "/api/gdapp/activate",
      { domain: domain, container_name: containerName, port: port },
      "Activating GD-App",
      domain + " — full setup with SSL, WebSocket, SSE"
    );
  });

  // ── Installed Applications ──────────────────────────────────────────────────

