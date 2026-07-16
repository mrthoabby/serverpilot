/* Services + memory panels */
"use strict";

  function formatMemDual(mb) {
    if (mb >= 1024) {
      return (mb / 1024).toFixed(2) + " GB (" + mb.toFixed(0) + " MB)";
    }
    return mb.toFixed(1) + " MB";
  }

  function renderSparkline(history) {
    // history is an array of { ts, mem_mb }
    if (!history || history.length < 2) return null;

    var ns = "http://www.w3.org/2000/svg";
    var svg = document.createElementNS(ns, "svg");
    svg.setAttribute("class", "sparkline-svg");
    svg.setAttribute("viewBox", "0 0 80 24");

    var vals = history.map(function(h) { return h.mem_mb; });
    var minV = Math.min.apply(null, vals);
    var maxV = Math.max.apply(null, vals);
    var range = maxV - minV;
    if (range < 0.1) range = 1; // avoid flat line divide-by-zero

    var points = [];
    var w = 80;
    var h = 24;
    var pad = 2;
    for (var i = 0; i < vals.length; i++) {
      var x = pad + (i / (vals.length - 1)) * (w - 2 * pad);
      var y = h - pad - ((vals[i] - minV) / range) * (h - 2 * pad);
      points.push(x.toFixed(1) + "," + y.toFixed(1));
    }

    var polyline = document.createElementNS(ns, "polyline");
    polyline.setAttribute("points", points.join(" "));
    polyline.setAttribute("fill", "none");
    polyline.setAttribute("stroke", "#00b4d8");
    polyline.setAttribute("stroke-width", "1.5");
    polyline.setAttribute("stroke-linecap", "round");
    polyline.setAttribute("stroke-linejoin", "round");
    svg.appendChild(polyline);

    // End dot
    var lastX = parseFloat(points[points.length - 1].split(",")[0]);
    var lastY = parseFloat(points[points.length - 1].split(",")[1]);
    var circle = document.createElementNS(ns, "circle");
    circle.setAttribute("cx", lastX);
    circle.setAttribute("cy", lastY);
    circle.setAttribute("r", "2");
    circle.setAttribute("fill", "#00b4d8");
    svg.appendChild(circle);

    return svg;
  }

  // ── Memory Detail Panel ──

  // Known monitored process names (to flag them in the table) — host
  // services that the dashboard considers part of its own surface even
  // when they're not running inside a docker container.
  var MONITORED_NAMES = { "serverpilot": true, "nginx": true, "docker": true, "dockerd": true, "containerd": true, "postgres": true, "redis-server": true, "node": true };

  // _lastMemTopProcesses caches the last /api/system/memory-detail
  // response so the filter dropdown can re-render without a re-fetch.
  // _knownContainersFromProcs is the set of container names that
  // appeared in the most recent response — used to refresh the per-
  // container filter options dynamically.
  var _lastMemTopProcesses = [];
  var _knownContainersFromProcs = {};

  // procIsMonitored returns the operator-friendly classification for a
  // single process. Three states:
  //   { kind: "container", label: "monitorizado-<container>" }
  //   { kind: "host",      label: "monitoreado" }   (host service in MONITORED_NAMES)
  //   { kind: "none",      label: "no monitoreado" }
  function procIsMonitored(p) {
    if (p.container) {
      return { kind: "container", container: p.container, label: "monitorizado-" + p.container };
    }
    if (MONITORED_NAMES[p.name]) {
      return { kind: "host", label: "monitoreado" };
    }
    return { kind: "none", label: "no monitoreado" };
  }

  // rebuildMemProcContainerFilterOptions populates the filter <select>
  // with one entry per container that currently has at least one process
  // in the top RSS list. Idempotent. Removes stale options that no
  // longer correspond to any process in the cache (e.g. a container
  // that was stopped between refreshes).
  function rebuildMemProcContainerFilterOptions() {
    var sel = document.getElementById("memProcFilter");
    if (!sel) return;
    var prev = sel.value;
    var newSet = {};
    _lastMemTopProcesses.forEach(function(p) {
      if (p.container) newSet[p.container] = true;
    });
    _knownContainersFromProcs = newSet;
    // Drop existing container:* options.
    var keep = [];
    for (var i = 0; i < sel.options.length; i++) {
      var v = sel.options[i].value;
      if (v.indexOf("container:") !== 0) keep.push({ v: v, t: sel.options[i].text });
    }
    sel.innerHTML = "";
    keep.forEach(function(o) {
      var opt = document.createElement("option");
      opt.value = o.v; opt.textContent = o.t;
      sel.appendChild(opt);
    });
    var names = Object.keys(newSet).sort();
    names.forEach(function(n) {
      var opt = document.createElement("option");
      opt.value = "container:" + n;
      opt.textContent = "Solo container — " + n;
      sel.appendChild(opt);
    });
    // Restore the previous selection if still applicable; otherwise reset to All.
    var stillExists = false;
    for (var j = 0; j < sel.options.length; j++) {
      if (sel.options[j].value === prev) { stillExists = true; break; }
    }
    sel.value = stillExists ? prev : "all";
  }

  // rerenderMemProcRows applies the current filter against the cached
  // _lastMemTopProcesses and rebuilds the table. Called when the filter
  // changes AND when a fresh response arrives. The cached list lets us
  // avoid hitting the API just to filter.
  function rerenderMemProcRows() {
    var tbody = document.getElementById("memProcBody");
    var sel = document.getElementById("memProcFilter");
    if (!tbody) return;
    var filter = sel ? sel.value : "all";

    var rows = "";
    var rendered = 0;
    _lastMemTopProcesses.forEach(function(p) {
      var status = procIsMonitored(p);
      // Apply filter.
      var matchesFilter = false;
      if (filter === "all") matchesFilter = true;
      else if (filter === "monitored") matchesFilter = status.kind !== "none";
      else if (filter === "unmonitored") matchesFilter = status.kind === "none";
      else if (filter.indexOf("container:") === 0) {
        matchesFilter = status.kind === "container" && status.container === filter.slice("container:".length);
      }
      if (!matchesFilter) return;

      var typeLabel;
      if (status.kind === "container") {
        // Cyan-on-dark for "this PID belongs to a docker container we know about".
        typeLabel = '<span style="background:#0d3a4a;color:#5db4d4;padding:1px 6px;border-radius:3px;font-size:0.7rem;" title="PID belongs to docker container ' + escapeHtml(status.container) + '">monitorizado-' + escapeHtml(status.container) + '</span>';
      } else if (status.kind === "host") {
        typeLabel = '<span style="background:#1f4822;color:#3fb950;padding:1px 6px;border-radius:3px;font-size:0.7rem;">monitoreado</span>';
      } else {
        typeLabel = '<span style="background:#3b2800;color:#d29922;padding:1px 6px;border-radius:3px;font-size:0.7rem;">no monitoreado</span>';
      }
      var stateColor = p.state === "S" ? "#3fb950" : p.state === "R" ? "#58a6ff" : "#8b949e";
      // Kill button only on "no monitoreado" — never offer to kill a
      // container's PID from this view (operators should manage
      // containers via docker stop), and never offer to kill a host
      // service like nginx or postgres.
      var killBtn = (status.kind === "none") ?
        '<button onclick="killProcess(' + p.pid + ', \'' + escapeHtml(p.name) + '\', this)" ' +
        'style="background:none;border:1px solid #f8514966;color:#f85149;border-radius:4px;padding:2px 7px;font-size:0.72rem;cursor:pointer;transition:all 0.15s;" ' +
        'onmouseenter="this.style.background=\'#f8514922\'" onmouseleave="this.style.background=\'none\'" ' +
        'title="Enviar SIGTERM al proceso">' +
        '<svg width="12" height="12" viewBox="0 0 16 16" fill="none" style="vertical-align:-1px;margin-right:2px;">' +
        '<path d="M4 4l8 8M12 4l-8 8" stroke="#f85149" stroke-width="1.5" stroke-linecap="round"/>' +
        '</svg>Kill</button>' : '';
      rows += '<tr style="border-bottom:1px solid var(--border);">' +
        '<td style="padding:5px 8px;color:var(--text-muted);font-family:monospace;">' + p.pid + '</td>' +
        '<td style="padding:5px 8px;font-weight:500;">' + escapeHtml(p.name) + '</td>' +
        '<td style="padding:5px 8px;">' +
          '<div style="display:flex;align-items:center;gap:6px;">' +
            '<div style="width:80px;height:6px;background:var(--border);border-radius:3px;overflow:hidden;">' +
              '<div style="height:100%;background:#f85149;border-radius:3px;width:' + Math.min(100, p.rss_mb / 5) + '%;"></div>' +
            '</div>' +
            p.rss_mb.toFixed(1) +
          '</div>' +
        '</td>' +
        '<td style="padding:5px 8px;color:' + stateColor + ';font-family:monospace;">' + escapeHtml(p.state || "?") + '</td>' +
        '<td style="padding:5px 8px;">' + typeLabel + '</td>' +
        '<td style="padding:5px 8px;text-align:center;">' + killBtn + '</td>' +
        '</tr>';
      rendered++;
    });
    if (rendered === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="padding:10px;color:var(--text-muted);">Sin procesos que coincidan con el filtro.</td></tr>';
    } else {
      tbody.innerHTML = rows;
    }
  }
  window.rerenderMemProcRows = rerenderMemProcRows;

  window.closeMemDetail = function() {
    var panel = document.getElementById("memDetailPanel");
    if (panel) panel.style.display = "none";
  };

  // Kill a non-monitored process by PID (sends SIGTERM via backend).
  window.killProcess = function(pid, name, btn) {
    if (!confirm("Terminar proceso " + name + " (PID " + pid + ")?\nSe enviará SIGTERM.")) return;
    var origHTML = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<span style="font-size:0.7rem;">...</span>';
    apiFetch("/api/system/kill-process", {
      method: "POST",
      body: { pid: pid }
    }).then(function(data) {
      if (data && data.success) {
        btn.style.borderColor = "#3fb95066";
        btn.style.color = "#3fb950";
        btn.innerHTML = '<svg width="12" height="12" viewBox="0 0 16 16" fill="none" style="vertical-align:-1px;"><path d="M3 8l4 4 6-7" stroke="#3fb950" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg> OK';
        // Refresh the process table after a brief delay to show updated list.
        setTimeout(function() { window.openMemDetail(window._lastMemData); }, 1500);
      } else {
        btn.innerHTML = origHTML;
        btn.disabled = false;
        alert("Error: " + (data && data.error ? data.error : "no se pudo terminar el proceso"));
      }
    }).catch(function() {
      btn.innerHTML = origHTML;
      btn.disabled = false;
      alert("Error de conexión al intentar terminar el proceso");
    });
  };

  // Update only the stat cards in the memory detail panel (no re-fetch of processes).
  // Called on auto-refresh to keep stats in sync with the pie chart.
  function updateMemDetailStats(memData) {
    var cacheRows = document.getElementById("memCacheRows");
    if (!cacheRows || !memData) return;
    var totalMB = memData.total_mb || 0;
    var availMB = memData.available_mb || 0;
    var usedMB  = memData.used_mb    || 0;
    var freeMB  = memData.free_mb    || 0;

    function makeStat(label, value, hint, color) {
      var div = document.createElement("div");
      div.style.cssText = "background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:10px 16px;min-width:0;flex:1 1 120px;";
      div.innerHTML = '<div style="font-size:0.72rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;">' + label + '</div>' +
        '<div style="font-size:1.15rem;font-weight:700;color:' + color + ';margin:2px 0;">' + value + ' MB</div>' +
        '<div style="font-size:0.7rem;color:var(--text-muted);">' + hint + '</div>';
      return div;
    }

    cacheRows.innerHTML = "";
    cacheRows.appendChild(makeStat("MemAvailable", availMB, "real RAM disponible", "#3fb950"));
    cacheRows.appendChild(makeStat("MemFree", freeMB, "completamente libre", "#58a6ff"));
    cacheRows.appendChild(makeStat("MemUsed", usedMB, "total ocupada", "#f85149"));
    cacheRows.appendChild(makeStat("MemTotal", totalMB, "capacidad total", "#8b949e"));
  }

  window.openMemDetail = function(memData) {
    window._lastMemData = memData;
    var panel = document.getElementById("memDetailPanel");
    if (!panel) return;
    panel.style.display = "block";
    panel.scrollIntoView({ behavior: "smooth", block: "start" });

    // ── Cache rows ──
    var cacheRows = document.getElementById("memCacheRows");
    if (cacheRows && memData) {
      var totalMB = memData.total_mb || 0;
      var availMB = memData.available_mb || 0;
      var usedMB  = memData.used_mb    || 0;
      var freeMB  = memData.free_mb    || 0;

      function makeStat(label, value, hint, color) {
        var div = document.createElement("div");
        div.style.cssText = "background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:10px 16px;min-width:0;flex:1 1 120px;";
        div.innerHTML = '<div style="font-size:0.72rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;">' + label + '</div>' +
          '<div style="font-size:1.15rem;font-weight:700;color:' + color + ';margin:2px 0;">' + value + ' MB</div>' +
          '<div style="font-size:0.7rem;color:var(--text-muted);">' + hint + '</div>';
        return div;
      }

      cacheRows.innerHTML = "";
      cacheRows.appendChild(makeStat("MemAvailable", availMB, "real RAM disponible", "#3fb950"));
      cacheRows.appendChild(makeStat("MemFree", freeMB, "completamente libre", "#58a6ff"));
      cacheRows.appendChild(makeStat("MemUsed", usedMB, "total ocupada", "#f85149"));
      cacheRows.appendChild(makeStat("MemTotal", totalMB, "capacidad total", "#8b949e"));
    }

    // ── Top processes ──
    var loadMsg = document.getElementById("memProcLoadingMsg");
    var tbody   = document.getElementById("memProcBody");
    if (loadMsg) loadMsg.textContent = "Cargando...";
    if (tbody)   tbody.innerHTML = "";

    apiFetch("/api/system/memory-detail")
      .then(function(data) {
        if (loadMsg) loadMsg.textContent = "";
        if (!data || !data.success || !data.data) return;
        var detail = data.data;

        // Update cache stats with fresh buffers/cached from backend.
        if (cacheRows && detail.cached_mb != null && detail.buffers_mb != null) {
          var cachedDiv = document.createElement("div");
          cachedDiv.style.cssText = "background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:10px 16px;min-width:0;flex:1 1 120px;";
          cachedDiv.innerHTML = '<div style="font-size:0.72rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;">Page Cache</div>' +
            '<div style="font-size:1.15rem;font-weight:700;color:#d29922;margin:2px 0;">' + detail.cached_mb + ' MB</div>' +
            '<div style="font-size:0.7rem;color:var(--text-muted);">caché de disco liberable</div>';
          var bufDiv = document.createElement("div");
          bufDiv.style.cssText = "background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:10px 16px;min-width:0;flex:1 1 120px;";
          bufDiv.innerHTML = '<div style="font-size:0.72rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;">Buffers</div>' +
            '<div style="font-size:1.15rem;font-weight:700;color:#db6d28;margin:2px 0;">' + detail.buffers_mb + ' MB</div>' +
            '<div style="font-size:0.7rem;color:var(--text-muted);">I/O buffers del kernel</div>';
          cacheRows.appendChild(cachedDiv);
          cacheRows.appendChild(bufDiv);
        }

        if (!detail.top_processes || detail.top_processes.length === 0) {
          if (tbody) tbody.innerHTML = '<tr><td colspan="6" style="padding:10px;color:var(--text-muted);">Sin datos de procesos</td></tr>';
          return;
        }

        // Cache the response so the filter dropdown can re-render
        // without re-fetching, and refresh the per-container option list
        // based on which containers actually show in the top RSS list.
        _lastMemTopProcesses = detail.top_processes.slice();
        rebuildMemProcContainerFilterOptions();
        rerenderMemProcRows();
      })
      .catch(function() {
        if (loadMsg) loadMsg.textContent = "Error al cargar procesos";
      });
  };

  // ── Disk Breakdown Pie + Table ──
  // ── Disk Usage Explorer ──
