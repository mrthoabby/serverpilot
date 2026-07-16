/* Background process center: unified view + reconnect.
 *
 * Polls /api/jobs to show running/finished background operations in a navbar
 * dropdown. Lets the operator reopen a job's live log ("Ver") or dismiss a
 * finished one. It NEVER terminates a running operation: privileged multi-step
 * operations (SSL, domain updates, replicas) can leave the server in a
 * half-applied state if interrupted, so running jobs can only be "followed".
 */
"use strict";

(function() {
  window.SP = window.SP || {};

  var POLL_IDLE = 15000;   // ms between polls when nothing is running
  var POLL_ACTIVE = 3000;  // ms between polls while a job runs
  var TAIL_INTERVAL = 1500;

  var pollTimer = null;
  var tailTimer = null;
  var tailJobId = null;
  var tailNextSeq = 0;
  var started = false;
  var lastJobs = [];

  function el(id) { return document.getElementById(id); }

  function fmtElapsed(sec) {
    sec = Math.max(0, parseInt(sec, 10) || 0);
    if (sec < 60) return sec + "s";
    var m = Math.floor(sec / 60), s = sec % 60;
    if (m < 60) return m + "m " + s + "s";
    var h = Math.floor(m / 60);
    return h + "h " + (m % 60) + "m";
  }

  function statusMeta(status) {
    if (status === "running") return { label: "En proceso", cls: "job-running", icon: "\u25CF" };
    if (status === "completed") return { label: "Completado", cls: "job-done", icon: "\u2713" };
    return { label: "Fallido", cls: "job-failed", icon: "\u2717" };
  }

  function runningCount() {
    var n = 0;
    for (var i = 0; i < lastJobs.length; i++) {
      if (lastJobs[i].status === "running") n++;
    }
    return n;
  }

  function schedule() {
    if (pollTimer) clearTimeout(pollTimer);
    if (!started) return;
    var interval = runningCount() > 0 ? POLL_ACTIVE : POLL_IDLE;
    pollTimer = setTimeout(poll, interval);
  }

  async function poll() {
    if (!started) return;
    try {
      var resp = await apiFetch("/api/jobs");
      lastJobs = (resp && resp.data) ? resp.data : [];
    } catch (e) {
      // Silent: 401 already routes to login via apiFetch; transient errors
      // just skip this cycle and the indicator keeps its last known state.
    }
    render();
    schedule();
  }

  function render() {
    var btn = el("jobsIndicatorBtn");
    if (!btn) return;
    var running = runningCount();
    var badge = el("jobsIndicatorCount");
    if (badge) {
      if (running > 0) {
        badge.textContent = String(running);
        badge.style.display = "inline-flex";
      } else {
        badge.style.display = "none";
      }
    }
    if (running > 0) btn.classList.add("has-running");
    else btn.classList.remove("has-running");
    btn.style.display = lastJobs.length > 0 ? "inline-flex" : "none";
    if (lastJobs.length === 0) closePanel();
    renderPanel();
  }

  function renderPanel() {
    var list = el("jobsPanelList");
    if (!list) return;
    if (!lastJobs.length) {
      list.innerHTML = '<div class="jobs-empty">No hay procesos en segundo plano.</div>';
      return;
    }
    list.innerHTML = lastJobs.map(function(j) {
      var m = statusMeta(j.status);
      var meta = m.label + " \u00B7 " + fmtElapsed(j.elapsed_seconds);
      if (j.status === "running" && j.progress_percent) {
        meta += " \u00B7 " + j.progress_percent + "%";
      }
      var actions = '<button type="button" class="btn btn-xs btn-outline" data-job-view="' + esc(j.id) +
        '" data-job-source="' + esc(j.source || "stream") + '">Ver</button>';
      if (j.status === "running") {
        actions += '<span class="jobs-bg-hint" title="Se ejecuta en segundo plano; no se puede interrumpir sin riesgo">segundo plano</span>';
      } else {
        actions += '<button type="button" class="btn btn-xs btn-outline" data-job-dismiss="' + esc(j.id) + '">Descartar</button>';
      }
      return '<div class="jobs-item ' + m.cls + '">' +
        '<div class="jobs-item-main">' +
          '<span class="jobs-item-icon" aria-hidden="true">' + m.icon + '</span>' +
          '<div class="jobs-item-text">' +
            '<div class="jobs-item-title">' + esc(j.title || "Proceso") + '</div>' +
            (j.subtitle ? '<div class="jobs-item-sub">' + esc(j.subtitle) + '</div>' : '') +
            '<div class="jobs-item-meta">' + esc(meta) + (j.error ? ' \u2014 ' + esc(j.error) : '') + '</div>' +
          '</div>' +
        '</div>' +
        '<div class="jobs-item-actions">' + actions + '</div>' +
      '</div>';
    }).join("");
  }

  function openPanel() {
    var panel = el("jobsPanel");
    var btn = el("jobsIndicatorBtn");
    if (!panel) return;
    panel.classList.add("open");
    if (btn) btn.setAttribute("aria-expanded", "true");
    poll();
  }

  function closePanel() {
    var panel = el("jobsPanel");
    var btn = el("jobsIndicatorBtn");
    if (panel) panel.classList.remove("open");
    if (btn) btn.setAttribute("aria-expanded", "false");
  }

  function togglePanel() {
    var panel = el("jobsPanel");
    if (panel && panel.classList.contains("open")) closePanel();
    else openPanel();
  }

  function findJob(id) {
    for (var i = 0; i < lastJobs.length; i++) {
      if (lastJobs[i].id === id) return lastJobs[i];
    }
    return null;
  }

  function onView(id, source) {
    var job = findJob(id);
    closePanel();
    if (source === "docker-prune") {
      // Docker prune has its own progress UI + registry in disk.js.
      if (typeof window.watchDockerPruneJob === "function") {
        window.watchDockerPruneJob(id, { openModal: true });
      } else if (typeof showToast === "function") {
        showToast("Abre la pestaña Resources para ver el prune", "success");
      }
      return;
    }
    reconnectStreamJob(job || { id: id, title: "Proceso", subtitle: "" });
  }

  // reconnectStreamJob reopens the progress modal and tails the buffered log of
  // a streamed operation whose modal was closed. It polls /api/jobs/tail until
  // the job finishes or the user closes the modal.
  function reconnectStreamJob(job) {
    if (typeof openProgressModal !== "function" || typeof appendLogLine !== "function") return;
    openProgressModal(job.title || "Proceso", job.subtitle || "");
    if (typeof appendLogLine === "function") {
      appendLogLine("Reconectando al proceso en segundo plano...");
    }
    tailJobId = job.id;
    tailNextSeq = 0;
    if (tailTimer) clearTimeout(tailTimer);
    pollTail();
  }

  function modalStillOpen() {
    var modal = el("progressModal");
    return modal && modal.classList.contains("show");
  }

  async function pollTail() {
    if (!tailJobId) return;
    if (!modalStillOpen()) { tailJobId = null; return; }
    var data = null;
    try {
      var resp = await apiFetch("/api/jobs/tail?id=" + encodeURIComponent(tailJobId) + "&after=" + tailNextSeq);
      data = resp && resp.data;
    } catch (e) {
      // Keep retrying a bounded number of times via the timer below.
    }
    if (!modalStillOpen()) { tailJobId = null; return; }
    if (data) {
      var logs = data.logs || [];
      for (var i = 0; i < logs.length; i++) {
        if (typeof appendLogLine === "function") appendLogLine(logs[i].line);
        tailNextSeq = logs[i].seq;
      }
      if (data.finished) {
        if (typeof finishProgress === "function") {
          finishProgress(data.status === "completed", data.error || "");
        }
        tailJobId = null;
        poll();
        return;
      }
    }
    tailTimer = setTimeout(pollTail, TAIL_INTERVAL);
  }

  async function onDismiss(id) {
    try {
      await apiFetch("/api/jobs/dismiss", { method: "POST", body: { id: id } });
    } catch (e) {
      if (typeof showToast === "function") showToast("No se pudo descartar: " + e.message, "error");
    }
    poll();
  }

  function bind() {
    var btn = el("jobsIndicatorBtn");
    if (btn) {
      btn.addEventListener("click", function(e) { e.stopPropagation(); togglePanel(); });
    }
    var closeBtn = el("jobsPanelClose");
    if (closeBtn) closeBtn.addEventListener("click", closePanel);

    var panel = el("jobsPanel");
    if (panel) {
      panel.addEventListener("click", function(e) {
        var t = e.target;
        var viewId = t.getAttribute && t.getAttribute("data-job-view");
        if (viewId) { onView(viewId, t.getAttribute("data-job-source")); return; }
        var dismissId = t.getAttribute && t.getAttribute("data-job-dismiss");
        if (dismissId) { onDismiss(dismissId); return; }
      });
    }

    document.addEventListener("click", function(e) {
      var panel = el("jobsPanel");
      var btn = el("jobsIndicatorBtn");
      if (!panel || !panel.classList.contains("open")) return;
      if ((btn && btn.contains(e.target)) || panel.contains(e.target)) return;
      closePanel();
    });
    document.addEventListener("keydown", function(e) {
      if (e.key === "Escape") closePanel();
    });
  }

  var bound = false;

  window.SP.jobs = {
    start: function() {
      if (!bound) { bind(); bound = true; }
      started = true;
      poll();
    },
    stop: function() {
      started = false;
      if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; }
      if (tailTimer) { clearTimeout(tailTimer); tailTimer = null; }
      tailJobId = null;
      lastJobs = [];
      render();
      closePanel();
    },
    refresh: function() { if (started) poll(); }
  };
})();
