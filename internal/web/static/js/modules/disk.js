/* Disk explorer */
"use strict";

  var DISK_COLORS = ["#00b4d8", "#3fb950", "#f85149", "#d29922", "#db6d28", "#8b5cf6", "#ec4899", "#6366f1", "#14b8a6", "#f97316", "#a855f7", "#ef4444"];
  var TYPE_ICONS = { dir: "\uD83D\uDCC1", file: "\uD83D\uDCC4", image: "\uD83D\uDDBC\uFE0F", log: "\uD83D\uDCDC", archive: "\uD83D\uDCE6", other: "\uD83D\uDCC4" };
  var diskCurrentPath = null;
  var diskCurrentEntries = [];
  var diskCurrentFilter = "all";
  var diskSelectedPaths = {};
  var diskTotalSizeMB = 0; // total disk capacity for % calculation

  function renderDiskBreakdown(d) {
    var loadingEl = document.getElementById("diskBreakdownLoading");
    if (loadingEl) loadingEl.style.display = "none";
    var entries = d.disk_breakdown;
    if (!entries || entries.length === 0) return;

    var items = entries.map(function(e) {
      return {
        path: e.path,
        name: e.label + (e.partial ? " ⚠ (timeout)" : ""),
        size_mb: e.size_mb,
        size_gb: e.size_gb,
        is_dir: true,
        type: e.partial ? "other" : "dir",
        partial: e.partial || false
      };
    });

    var rootDiskAvailMB = 0, rootDiskUsedMB = 0, rootDiskSizeMB = 0;
    if (d.disk && d.disk.length > 0) {
      rootDiskAvailMB = d.disk[0].avail_mb;
      rootDiskUsedMB = d.disk[0].used_mb;
      rootDiskSizeMB = d.disk[0].size_mb;
    }
    diskTotalSizeMB = rootDiskSizeMB || (rootDiskUsedMB + rootDiskAvailMB);

    // ── Docker disk breakdown from docker system df ──
    // Shown as a separate group — more accurate than du /var/lib/docker.
    var dockerTotalMB = 0;
    if (d.docker_disk && d.docker_disk.length > 0) {
      d.docker_disk.forEach(function(dk) {
        dockerTotalMB += dk.size_mb;
        items.push({
          path: "(docker:" + dk.type + ")",
          name: "Docker " + dk.type + " (" + dk.total + " items, " + dk.active + " active)",
          size_mb: dk.size_mb,
          size_gb: Math.round(dk.size_mb / 1024 * 100) / 100,
          is_dir: false,
          type: "docker",
          docker: true,
          dockerType: dk.type,
          reclaimMB: dk.reclaim_mb
        });
      });
    }

    // Calculate scanned total. du rows already EXCLUDE Docker (/var/lib is scanned
    // with --exclude=/var/lib/docker and /var/lib/docker itself is not du-scanned),
    // so Docker is counted exactly once via docker system df (dockerTotalMB below).
    var scannedMB = 0;
    items.forEach(function(e) { if (!e.docker) scannedMB += e.size_mb; });

    // "Other / System" = used space not accounted for by du or docker system df.
    // This includes: kernel metadata, journal, filesystem overhead, deleted-but-open files.
    var accountedMB = scannedMB + dockerTotalMB;
    var otherMB = rootDiskUsedMB - accountedMB;

    // Show discrepancy warning when scanned significantly exceeds df used.
    // This happens when du counts files that df doesn't (e.g. sparse file holes counted differently).
    var discrepancyEl = document.getElementById("diskDiscrepancy");
    if (discrepancyEl) {
      if (accountedMB > rootDiskUsedMB * 1.05) {
        var excess = ((accountedMB - rootDiskUsedMB) / 1024).toFixed(2);
        discrepancyEl.style.display = "block";
        discrepancyEl.innerHTML = '⚠ El escaneo suma <strong>' + (accountedMB/1024).toFixed(2) + ' GB</strong> pero <code>df</code> reporta solo <strong>' + (rootDiskUsedMB/1024).toFixed(2) + ' GB</strong> usado (diferencia: ' + excess + ' GB). Esto ocurre cuando hay bind mounts o archivos contados en múltiples directorios.';
      } else {
        discrepancyEl.style.display = "none";
      }
    }

    if (otherMB > 100) {
      var unaccountedName = "No escaneado / Sistema";
      if (dockerTotalMB < 1 && otherMB > 5000) {
        unaccountedName = "No escaneado / Sistema (probablemente Docker — clic para ver)";
      } else if (dockerTotalMB < 1) {
        unaccountedName = "No escaneado / Sistema (clic para desglosar)";
      } else {
        unaccountedName = "No escaneado / Sistema (resto — clic para desglosar)";
      }
      items.push({
        path: "(other)",
        diagnostic: "unaccounted",
        name: unaccountedName,
        size_mb: otherMB,
        size_gb: Math.round(otherMB / 1024 * 100) / 100,
        is_dir: false,
        type: "other",
        synthetic: true,
        protected_reason: "synthetic disk accounting row"
      });
    }

    // Re-sort by size descending.
    items.sort(function(a, b) { return b.size_mb - a.size_mb; });

    var diskTitle = document.getElementById("diskBreakdownTitle");
    if (diskTitle) {
      var freeGB = (rootDiskAvailMB / 1024).toFixed(2);
      var usedGB = (rootDiskUsedMB / 1024).toFixed(2);
      var totalGB = (diskTotalSizeMB / 1024).toFixed(2);
      diskTitle.innerHTML = 'Disk Usage Explorer (' + totalGB + ' GB total — ' + usedGB + ' GB used) — <span style="color:var(--green);font-weight:700;">Free: ' + freeGB + ' GB</span>';
    }

    diskCurrentPath = null;
    diskCurrentEntries = items;
    diskCurrentFilter = "all";
    renderDiskPie(items, rootDiskAvailMB, rootDiskUsedMB, diskTotalSizeMB);
    renderDiskTable(items);
    renderDiskBreadcrumb(null);
    showDiskActionBar();
    loadTopFiles();
  }

  function renderDiskPie(items, freeMB, usedMB, totalDiskMB) {
    var svg = document.getElementById("diskPieChart");
    if (!svg) return;
    svg.innerHTML = "";
    var slices = [];
    // items already include "No escaneado / Sistema" and Docker entries —
    // do NOT add a second "Other" here (that was a bug that caused double-counting).
    items.forEach(function(e) { slices.push({ label: e.name, sizeMB: e.size_mb }); });
    if (freeMB > 0) slices.push({ label: "Free", sizeMB: freeMB });

    // Normalize: if slices sum > totalDiskMB, scale them down so the pie
    // represents actual disk proportions and doesn't overflow 360°.
    var rawTotal = 0;
    slices.forEach(function(s) { rawTotal += s.sizeMB; });
    var diskRef = totalDiskMB > 0 ? totalDiskMB : rawTotal;
    // Use rawTotal as pie denominator (normalizes the visual), but keep actual MB labels.
    var pieTotalMB = rawTotal > 0 ? rawTotal : 1;

    var cx = 140, cy = 130, r = 100, startAngle = -Math.PI / 2;
    var ns = "http://www.w3.org/2000/svg";
    slices.forEach(function(slice, i) {
      if (slice.sizeMB <= 0) return;
      var pct = slice.sizeMB / pieTotalMB;
      var angle = pct * 2 * Math.PI;
      if (angle < 0.005) return;
      var endAngle = startAngle + angle;
      var largeArc = angle > Math.PI ? 1 : 0;
      var x1 = cx + r * Math.cos(startAngle), y1 = cy + r * Math.sin(startAngle);
      var x2 = cx + r * Math.cos(endAngle), y2 = cy + r * Math.sin(endAngle);
      var pathD = pct >= 0.999
        ? "M " + (cx-r) + " " + cy + " A " + r + " " + r + " 0 1 1 " + (cx+r) + " " + cy + " A " + r + " " + r + " 0 1 1 " + (cx-r) + " " + cy + " Z"
        : "M " + cx + " " + cy + " L " + x1 + " " + y1 + " A " + r + " " + r + " 0 " + largeArc + " 1 " + x2 + " " + y2 + " Z";
      var path = document.createElementNS(ns, "path");
      path.setAttribute("d", pathD);
      path.setAttribute("fill", DISK_COLORS[i % DISK_COLORS.length]);
      path.setAttribute("stroke", "#0d1117");
      path.setAttribute("stroke-width", "2");
      svg.appendChild(path);
      startAngle = endAngle;
    });
    var ly = 250;
    slices.forEach(function(slice, i) {
      if (slice.sizeMB <= 0) return;
      var col = i % 2, row = Math.floor(i / 2);
      var lx = 5 + col * 170, yy = ly + row * 16;
      var rect = document.createElementNS(ns, "rect");
      rect.setAttribute("x", lx); rect.setAttribute("y", yy - 7);
      rect.setAttribute("width", 8); rect.setAttribute("height", 8); rect.setAttribute("rx", 2);
      rect.setAttribute("fill", DISK_COLORS[i % DISK_COLORS.length]);
      svg.appendChild(rect);
      var txt = document.createElementNS(ns, "text");
      txt.setAttribute("x", lx + 12); txt.setAttribute("y", yy);
      txt.setAttribute("fill", "#8b949e"); txt.setAttribute("font-size", "10");
      txt.setAttribute("font-family", "-apple-system, sans-serif");
      // Show actual GB and % of total disk (not % of pie, so user sees real proportions).
      var realPct = diskRef > 0 ? (slice.sizeMB / diskRef * 100).toFixed(1) : "0";
      txt.textContent = (slice.sizeMB / 1024).toFixed(2) + " GB (" + realPct + "%) \u2014 " + slice.label;
      svg.appendChild(txt);
    });
    var rows = Math.ceil(slices.filter(function(s) { return s.sizeMB > 0; }).length / 2);
    var h = ly + rows * 16 + 10;
    if (h > 340) svg.setAttribute("viewBox", "0 0 340 " + h);
  }

  function renderDiskTable(items) {
    var tbody = document.getElementById("diskDetailBody");
    if (!tbody) return;
    tbody.innerHTML = "";
    var filtered = diskCurrentFilter === "all" ? items : items.filter(function(e) { return e.type === diskCurrentFilter; });
    // Use total disk capacity as reference for bars and %, NOT the max entry
    var refMB = diskTotalSizeMB > 0 ? diskTotalSizeMB : 1;
    if (filtered.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" style="padding:1rem;color:var(--text-muted);text-align:center;">No items match this filter</td></tr>';
      return;
    }
    filtered.forEach(function(entry, i) {
      var pct = refMB > 0 ? (entry.size_mb / refMB * 100) : 0;
      // Bar: use % of total disk, but ensure minimum visible width for small items.
      var barW = pct > 100 ? 100 : pct;
      if (entry.size_mb > 0 && barW < 1.5) barW = 1.5; // minimum visible bar
      var color = DISK_COLORS[i % DISK_COLORS.length];
      var isChecked = diskSelectedPaths[entry.path] ? "checked" : "";
      var safePath = entry.path.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
      var browseTarget = entry.browse_path || entry.path;
      var safeBrowseTarget = browseTarget.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
      var nameHtml;
      if (entry.diagnostic === "unaccounted") {
        nameHtml = '<a href="#" onclick="openDiskUnaccounted();return false;" style="color:var(--accent);text-decoration:underline;font-weight:500;cursor:pointer;">' + escapeHtml(entry.name) + '</a> <span style="font-size:0.68rem;color:var(--text-muted);">(clic para desglosar)</span>';
      } else if (entry.docker) {
        var reclaimGb = Number(entry.reclaimMB || 0) / 1024;
        var pruneHint = "";
        if (entry.dockerType === "Build Cache") {
          pruneHint = ' · <a href="#" onclick="scrollToDockerPrune(\'builder\');return false;" style="color:var(--accent);font-size:0.72rem;">Limpiar build cache ↓</a>';
        } else if (reclaimGb > 0) {
          pruneHint = ' · <a href="#" onclick="scrollToDockerPrune();return false;" style="color:var(--accent);font-size:0.72rem;">Ver prune ↓</a>';
        }
        nameHtml = '<span style="color:var(--text-primary);font-weight:500;">' + escapeHtml(entry.name) + '</span>' +
          (reclaimGb > 0 ? ' <span style="font-size:0.72rem;color:var(--green);">(' + reclaimGb.toFixed(2) + ' GB recuperables)</span>' : '') +
          pruneHint +
          ' <span style="font-size:0.68rem;color:var(--text-muted);">(medido por docker system df — no es una carpeta)</span>';
      } else if (entry.is_dir || entry.type === "dir" || entry.browse_path) {
        nameHtml = '<a href="#" onclick="diskDrillInto(\'' + safeBrowseTarget + '\');return false;" style="color:var(--accent);text-decoration:none;font-weight:500;">' + escapeHtml(entry.name) + '</a>';
      } else {
        nameHtml = '<span style="color:var(--text-primary);">' + escapeHtml(entry.name) + '</span>';
      }
      var checkboxHtml = entry.synthetic
        ? '<input type="checkbox" disabled title="' + escapeHtml(entry.protected_reason || "not a real path") + '" style="cursor:not-allowed;opacity:0.45;">'
        : '<input type="checkbox" ' + isChecked + ' onchange="diskToggleSelect(\'' + safePath + '\', this.checked)" style="cursor:pointer;">';
      // Color dot matching the pie chart slice color.
      var colorDot = '<span style="display:inline-block;width:10px;height:10px;border-radius:3px;background:' + color + ';"></span>';
      var tr = document.createElement("tr");
      tr.innerHTML =
        '<td style="padding:4px;border-bottom:1px solid var(--border);text-align:center;">' + checkboxHtml + '</td>' +
        '<td style="padding:4px 8px;border-bottom:1px solid var(--border);">' + nameHtml + '<br><span style="font-size:0.7rem;color:var(--text-muted);">' + escapeHtml(entry.path) + '</span></td>' +
        '<td style="padding:4px;border-bottom:1px solid var(--border);text-align:center;">' + colorDot + '</td>' +
        '<td style="padding:4px 8px;border-bottom:1px solid var(--border);text-align:right;font-variant-numeric:tabular-nums;font-weight:600;">' + entry.size_gb.toFixed(2) + '</td>' +
        '<td style="padding:4px 8px;border-bottom:1px solid var(--border);text-align:right;font-variant-numeric:tabular-nums;color:var(--text-secondary);">' + Math.round(entry.size_mb) + '</td>' +
        '<td style="padding:4px 8px;border-bottom:1px solid var(--border);text-align:right;font-variant-numeric:tabular-nums;color:var(--text-secondary);">' + pct.toFixed(1) + '%</td>' +
        '<td style="padding:4px 8px;border-bottom:1px solid var(--border);"><div style="background:var(--bg-input);border-radius:4px;height:12px;overflow:hidden;"><div style="width:' + barW.toFixed(1) + '%;height:100%;background:' + color + ';border-radius:4px;"></div></div></td>';
      tbody.appendChild(tr);
    });
    // Total row — only in overview mode (diskCurrentPath is null).
    if (!diskCurrentPath && diskTotalSizeMB > 0) {
      var totalUsedMB = 0;
      filtered.forEach(function(e) { totalUsedMB += e.size_mb; });
      var totalUsedGB = totalUsedMB / 1024;
      var totalPct = totalUsedMB / refMB * 100;
      var totalTr = document.createElement("tr");
      totalTr.innerHTML =
        '<td style="padding:6px 4px;border-top:2px solid var(--accent);"></td>' +
        '<td style="padding:6px 8px;border-top:2px solid var(--accent);font-weight:700;color:var(--accent);">Total Used</td>' +
        '<td style="padding:6px 4px;border-top:2px solid var(--accent);"></td>' +
        '<td style="padding:6px 8px;border-top:2px solid var(--accent);text-align:right;font-variant-numeric:tabular-nums;font-weight:700;color:var(--accent);">' + totalUsedGB.toFixed(2) + '</td>' +
        '<td style="padding:6px 8px;border-top:2px solid var(--accent);text-align:right;font-variant-numeric:tabular-nums;font-weight:700;color:var(--accent);">' + Math.round(totalUsedMB) + '</td>' +
        '<td style="padding:6px 8px;border-top:2px solid var(--accent);text-align:right;font-variant-numeric:tabular-nums;font-weight:700;color:var(--accent);">' + totalPct.toFixed(1) + '%</td>' +
        '<td style="padding:6px 8px;border-top:2px solid var(--accent);"><div style="background:var(--bg-input);border-radius:4px;height:12px;overflow:hidden;"><div style="width:' + (totalPct > 100 ? 100 : totalPct).toFixed(1) + '%;height:100%;background:var(--accent);border-radius:4px;"></div></div></td>';
      tbody.appendChild(totalTr);
    }
  }

  function renderDiskBreadcrumb(path) {
    var bc = document.getElementById("diskBreadcrumb");
    if (!bc) return;
    if (!path) { bc.innerHTML = '<span style="color:var(--accent);font-weight:600;">/ Overview</span>'; return; }
    var parts = path.split("/").filter(function(p) { return p !== ""; });
    var html = '<a href="#" onclick="diskGoToOverview();return false;" style="color:var(--accent);text-decoration:none;">Overview</a>';
    var accumulated = "";
    parts.forEach(function(part, i) {
      accumulated += "/" + part;
      html += ' <span style="color:var(--text-muted);">/</span> ';
      if (i === parts.length - 1) {
        html += '<span style="color:var(--text-primary);font-weight:600;">' + escapeHtml(part) + '</span>';
      } else {
        var p = accumulated.replace(/'/g, "\\'");
        html += '<a href="#" onclick="diskDrillInto(\'' + p + '\');return false;" style="color:var(--accent);text-decoration:none;">' + escapeHtml(part) + '</a>';
      }
    });
    bc.innerHTML = html;
  }

  function showDiskActionBar() {
    var bar = document.getElementById("diskActionBar");
    var count = Object.keys(diskSelectedPaths).length;
    if (bar) {
      bar.style.display = count > 0 ? "flex" : "none";
      var countEl = document.getElementById("diskSelectedCount");
      if (countEl) countEl.textContent = count + " selected";
    }
  }

  window.diskFilterBy = function(type) {
    diskCurrentFilter = type;
    ["All","Dir","File","Image","Log","Archive"].forEach(function(t) {
      var btn = document.getElementById("diskFilter" + t);
      if (btn) {
        if (t.toLowerCase() === type) {
          btn.style.background = "var(--accent)"; btn.style.color = "#fff"; btn.style.border = "none";
        } else {
          btn.style.background = "var(--bg-input)"; btn.style.color = "var(--text-secondary)"; btn.style.border = "1px solid var(--border)";
        }
      }
    });
    renderDiskTable(diskCurrentEntries);
  };

  window.diskDrillInto = async function(path) {
    // User-initiated navigation: show loading state since they clicked.
    var tbody = document.getElementById("diskDetailBody");
    if (tbody) tbody.innerHTML = '<tr><td colspan="7" style="padding:1rem;color:var(--text-muted);text-align:center;">Loading ' + escapeHtml(path) + ' ...</td></tr>';
    diskSelectedPaths = {};
    showDiskActionBar();
    try {
      var resp = await apiFetch("/api/system/disk-detail?path=" + encodeURIComponent(path));
      var items = resp.data || resp || [];
      diskCurrentPath = path;
      diskCurrentEntries = items;
      diskCurrentFilter = "all";
      renderDiskBreadcrumb(path);
      renderDiskTable(items);
      diskFilterBy("all");
    } catch(err) {
      if (tbody) tbody.innerHTML = '<tr><td colspan="7" style="padding:1rem;color:var(--red);">Error: ' + escapeHtml(err.message) + '</td></tr>';
    }
  };

  // Silent variant for auto-refresh: fetches data in background, swaps DOM when ready.
  // No "Loading..." message, no flicker — the user's view stays intact until new data arrives.
  async function diskDrillIntoSilent(path) {
    try {
      var resp = await apiFetch("/api/system/disk-detail?path=" + encodeURIComponent(path));
      var items = resp.data || resp || [];
      // Only update if the user is still on the same directory (they may have navigated away).
      if (diskCurrentPath === path) {
        diskCurrentEntries = items;
        renderDiskTable(items);
      }
    } catch(err) {
      // Silent fail — the user still sees the previous data, no disruption.
    }
  }

  window.diskGoToOverview = function() {
    diskSelectedPaths = {};
    showDiskActionBar();
    if (sysData && sysData.disk_breakdown) renderDiskBreakdown(sysData);
  };

  window.openDiskUnaccounted = async function() {
    var panel = document.getElementById("diskUnaccountedPanel");
    var content = document.getElementById("diskUnaccountedContent");
    if (!panel || !content) return;
    panel.style.display = "block";
    panel.scrollIntoView({ behavior: "smooth", block: "start" });
    _diskRootScanEntries = [];
    _diskRootScanPending = {};
    _diskRootScanDone = false;
    _diskUnaccountedData = null;
    renderDiskUnaccountedShell();
    if (typeof showToast === "function") showToast("Escaneando espacio no contabilizado...", "info");

    apiFetch("/api/system/disk-unaccounted?limit=50").then(function(resp) {
      _diskUnaccountedData = resp.data || resp || {};
      renderDiskUnaccountedDeletedSection();
    }).catch(function() {
      _diskUnaccountedData = { deleted_open_files: [], notes: [] };
      renderDiskUnaccountedDeletedSection();
    });

    // Docker is the usual explanation for "No escaneado" — fetch it first.
    Promise.all([
      apiFetch("/api/system/disk-breakdown").catch(function() { return null; }),
      apiFetch("/api/system/docker-container-disk").catch(function() { return null; })
    ]).then(function(results) {
      var diskResp = results[0];
      var containerResp = results[1];
      var payload = diskResp ? (diskResp.data || diskResp) : {};
      var dockerDisk = Array.isArray(payload) ? [] : (payload.docker_disk || []);
      var containers = containerResp ? (containerResp.data || containerResp || []) : [];
      if (sysData && dockerDisk.length) sysData.docker_disk = dockerDisk;
      renderDiskUnaccountedDockerSection(dockerDisk, containers);
      if (!diskCurrentPath && sysData && dockerDisk.length) renderDiskBreakdown(sysData);
    });

    streamDiskRootScan().catch(function(err) {
      var statusEl = document.getElementById("diskRootScanStatus");
      if (statusEl) statusEl.innerHTML = '<span style="color:var(--red);">Error: ' + escapeHtml(err.message) + '</span>';
    });
  };

  var _diskRootScanEntries = [];
  var _diskRootScanPending = {};
  var _diskRootScanDone = false;
  var _diskUnaccountedData = null;

  function streamDiskRootScan() {
    return fetch("/api/system/disk-root-scan?stream=1", prepareApiFetchOptions({ method: "GET" })).then(function(response) {
      if (response.status === 401) {
        showLogin();
        throw new Error("Unauthorized");
      }
      if (!response.ok) {
        return response.text().then(function(t) {
          throw new Error(parseStreamedError(response, t));
        });
      }
      var reader = response.body.getReader();
      var decoder = new TextDecoder();
      var buffer = "";
      function readChunk() {
        return reader.read().then(function(result) {
          if (result.done) {
            if (buffer.trim()) processDiskRootScanSSE(buffer);
            return;
          }
          buffer += decoder.decode(result.value, { stream: true });
          var parts = buffer.split("\n\n");
          buffer = parts.pop();
          parts.forEach(processDiskRootScanSSE);
          return readChunk();
        });
      }
      return readChunk();
    });
  }

  function processDiskRootScanSSE(raw) {
    var event = "message";
    var data = "";
    raw.split("\n").forEach(function(line) {
      if (line.indexOf("event: ") === 0) event = line.substring(7).trim();
      else if (line.indexOf("data: ") === 0) data = line.substring(6);
    });
    if (!data) return;

    if (event === "paths") {
      var paths = JSON.parse(data);
      paths.forEach(function(p) { _diskRootScanPending[p] = true; });
      updateDiskRootScanTable();
      return;
    }
    if (event === "entry") {
      var entry = JSON.parse(data);
      delete _diskRootScanPending[entry.path];
      var replaced = false;
      for (var i = 0; i < _diskRootScanEntries.length; i++) {
        if (_diskRootScanEntries[i].path === entry.path) {
          _diskRootScanEntries[i] = entry;
          replaced = true;
          break;
        }
      }
      if (!replaced) _diskRootScanEntries.push(entry);
      _diskRootScanEntries.sort(function(a, b) { return (b.size_mb || 0) - (a.size_mb || 0); });
      updateDiskRootScanTable();
      return;
    }
    if (event === "done") {
      _diskRootScanDone = true;
      // Any directory that never reported is effectively empty (well under 1 MB),
      // not a timeout — show it as a real 0, never as "no escaneado".
      Object.keys(_diskRootScanPending).forEach(function(p) {
        _diskRootScanEntries.push({ path: p, size_mb: 0, size_gb: 0, partial: false, scanning: false });
        delete _diskRootScanPending[p];
      });
      // Force every remaining row to its final (non-scanning) state.
      _diskRootScanEntries.forEach(function(e) { e.scanning = false; });
      _diskRootScanEntries.sort(function(a, b) { return (b.size_mb || 0) - (a.size_mb || 0); });
      updateDiskRootScanTable();
    }
  }

  function renderDiskUnaccountedShell() {
    var content = document.getElementById("diskUnaccountedContent");
    if (!content) return;
    content.innerHTML =
      '<div id="diskUnaccountedDockerSection" style="margin-bottom:1.25rem;padding-bottom:1rem;border-bottom:1px solid var(--border);">' +
        '<h3 style="margin:0 0 0.5rem;font-size:0.9rem;color:var(--text-primary);">Docker — uso real de disco</h3>' +
        '<div style="font-size:0.78rem;color:var(--text-muted);margin-bottom:0.65rem;line-height:1.45;">' +
          'El bloque <strong>No escaneado / Sistema</strong> casi siempre es Docker en <code>/var/lib/docker</code>. ' +
          '<code>du</code> no puede medir overlay2 correctamente; <code>docker system df</code> sí.' +
        '</div>' +
        '<div id="diskUnaccountedDockerBody" style="color:var(--text-muted);font-size:0.82rem;">Consultando Docker…</div>' +
      '</div>' +
      '<h3 style="margin:0 0 0.5rem;font-size:0.9rem;color:var(--text-primary);">Directorios de nivel superior en / (du)</h3>' +
      '<div style="font-size:0.72rem;color:var(--text-muted);margin-bottom:0.35rem;">Complemento — no incluye datos overlay2 de Docker.</div>' +
      '<div id="diskRootScanStatus" style="margin-bottom:0.35rem;font-size:0.75rem;color:var(--text-muted);">Iniciando escaneo...</div>' +
      '<div style="overflow-x:auto;margin-bottom:1rem;"><table style="width:100%;border-collapse:collapse;font-size:0.82rem;">' +
      '<thead><tr style="color:var(--text-muted);text-align:left;border-bottom:1px solid var(--border);">' +
      '<th style="padding:6px 8px;">Path</th><th style="padding:6px 8px;text-align:right;">GB</th><th style="padding:6px 8px;text-align:right;">MB</th><th style="padding:6px 8px;min-width:100px;">Bar</th>' +
      '</tr></thead><tbody id="diskRootScanBody"></tbody></table></div>' +
      '<div id="diskUnaccountedDeletedSection"><div style="color:var(--text-muted);font-size:0.82rem;">Cargando archivos borrados abiertos...</div></div>';
    updateDiskRootScanTable();
  }

  function renderDiskUnaccountedDockerSection(dockerDisk, containerEntries) {
    var el = document.getElementById("diskUnaccountedDockerBody");
    if (!el) return;

    if (!dockerDisk || !dockerDisk.length) {
      el.innerHTML =
        '<div style="padding:0.75rem;border:1px solid var(--orange);border-radius:6px;background:rgba(255,165,0,0.08);color:var(--text-secondary);line-height:1.45;">' +
          '<strong style="color:var(--orange);">Docker no respondió.</strong> ' +
          'Verifica que el daemon esté corriendo (<code>systemctl status docker</code>). ' +
          'Si el espacio desaparecido es ~80 GB, casi seguro está en imágenes/capas Docker y aparecerá aquí cuando el daemon responda.' +
        '</div>';
      return;
    }

    var totalMB = 0, reclaimMB = 0;
    dockerDisk.forEach(function(d) {
      totalMB += d.size_mb || 0;
      reclaimMB += d.reclaim_mb || 0;
    });

    var html =
      '<div style="display:flex;gap:0.75rem;flex-wrap:wrap;margin-bottom:0.75rem;">' +
        '<div style="padding:10px 14px;border:1px solid var(--accent);border-radius:8px;background:rgba(88,166,255,0.08);">' +
          '<strong style="color:var(--accent);font-size:1.15rem;">' + (totalMB / 1024).toFixed(2) + ' GB</strong><br>' +
          '<span style="font-size:0.72rem;color:var(--text-muted);">total Docker (imágenes + contenedores + volúmenes + cache)</span>' +
        '</div>' +
        '<div style="padding:10px 14px;border:1px solid var(--green);border-radius:8px;">' +
          '<strong style="color:var(--green);font-size:1.05rem;">' + (reclaimMB / 1024).toFixed(2) + ' GB</strong><br>' +
          '<span style="font-size:0.72rem;color:var(--text-muted);">recuperable con prune (sin tocar lo activo)</span>' +
        '</div>' +
      '</div>' +
      '<div style="overflow-x:auto;"><table style="width:100%;border-collapse:collapse;font-size:0.82rem;">' +
      '<thead><tr style="color:var(--text-muted);text-align:left;border-bottom:1px solid var(--border);">' +
      '<th style="padding:6px 8px;">Tipo</th><th style="padding:6px 8px;text-align:right;">GB</th>' +
      '<th style="padding:6px 8px;text-align:right;">Recuperable</th><th style="padding:6px 8px;">Items</th>' +
      '</tr></thead><tbody>';

    dockerDisk.forEach(function(d) {
      html += '<tr>' +
        '<td style="padding:5px 8px;border-bottom:1px solid var(--border);font-weight:500;color:var(--text-primary);">' + escapeHtml(d.type || "") + '</td>' +
        '<td style="padding:5px 8px;border-bottom:1px solid var(--border);text-align:right;font-weight:600;font-variant-numeric:tabular-nums;">' +
          ((d.size_mb || 0) / 1024).toFixed(2) + '</td>' +
        '<td style="padding:5px 8px;border-bottom:1px solid var(--border);text-align:right;color:var(--green);font-variant-numeric:tabular-nums;">' +
          ((d.reclaim_mb || 0) / 1024).toFixed(2) + ' GB</td>' +
        '<td style="padding:5px 8px;border-bottom:1px solid var(--border);color:var(--text-secondary);">' +
          (d.active || 0) + ' activos / ' + (d.total || 0) + ' total</td>' +
        '</tr>';
    });
    html += '</tbody></table></div>';

    if (containerEntries && containerEntries.length) {
      html += '<div style="margin-top:0.65rem;font-size:0.75rem;color:var(--text-muted);">' +
        'Detalle por contenedor: tarjeta <strong>Docker disk by container</strong> (más abajo). ' +
        'Para liberar espacio: tarjeta <strong>Limpieza Docker (prune)</strong>.</div>';
    }

    el.innerHTML = html;
  }

  function updateDiskRootScanTable() {
    var tbody = document.getElementById("diskRootScanBody");
    var statusEl = document.getElementById("diskRootScanStatus");
    if (!tbody) return;

    var pendingPaths = Object.keys(_diskRootScanPending);
    var scanningEntries = _diskRootScanEntries.filter(function(e) { return e.scanning; }).length;
    var workingCount = pendingPaths.length + scanningEntries;
    var finishedCount = _diskRootScanEntries.filter(function(e) { return !e.scanning; }).length;
    var partialCount = _diskRootScanEntries.filter(function(e) { return e.partial && !e.scanning; }).length;

    if (statusEl) {
      if (!_diskRootScanDone && workingCount > 0) {
        statusEl.innerHTML = 'Escaneo en curso: <strong>' + workingCount + '</strong> directorio(s) midiéndose, ' +
          finishedCount + ' completo(s). Esperamos a que todos terminen — /var y /usr se dividen en subdirectorios en paralelo.';
      } else if (_diskRootScanDone && partialCount > 0) {
        statusEl.innerHTML = 'Escaneo completo. <span style="color:var(--orange);">' + partialCount + ' directorio(s) tienen subcarpetas que no se pudieron medir (parcial).</span> Clic en un path para explorar.';
      } else if (_diskRootScanDone) {
        statusEl.innerHTML = 'Escaneo completo (' + _diskRootScanEntries.length + ' directorios). Clic en un path para explorar subdirectorios.';
      }
    }

    var rows = _diskRootScanEntries.slice();
    pendingPaths.sort().forEach(function(p) {
      rows.push({ path: p, size_mb: null, size_gb: null, pending: true });
    });

    if (rows.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" style="padding:0.75rem;color:var(--text-muted);text-align:center;">Esperando lista de directorios...</td></tr>';
      return;
    }

    // Scanning rows first (so the user watches active work), then by size.
    rows.sort(function(a, b) {
      var aw = (a.pending || a.scanning) ? 1 : 0;
      var bw = (b.pending || b.scanning) ? 1 : 0;
      if (aw !== bw) return bw - aw;
      return (b.size_mb || 0) - (a.size_mb || 0);
    });

    var maxMB = Math.max.apply(null, rows.map(function(e) { return e.size_mb || 0; }).concat([1]));
    var html = "";
    rows.forEach(function(e) {
      var safePath = escapeHtml(e.path);
      var pathLink = '<a href="#" onclick="diskDrillFromUnaccounted(\'' + e.path.replace(/\\/g, "\\\\").replace(/'/g, "\\'") + '\');return false;" style="color:var(--accent);text-decoration:none;font-family:monospace;font-weight:500;">' + safePath + '</a>';

      // Still waiting for the very first measurement.
      if (e.pending) {
        html += '<tr style="opacity:0.75;">' +
          '<td style="padding:5px 8px;border-bottom:1px solid var(--border);font-family:monospace;color:var(--text-muted);">' + safePath + ' <span style="font-size:0.7rem;color:var(--accent);">⟳ escaneando...</span></td>' +
          '<td style="padding:5px 8px;border-bottom:1px solid var(--border);text-align:right;color:var(--text-muted);">—</td>' +
          '<td style="padding:5px 8px;border-bottom:1px solid var(--border);text-align:right;color:var(--text-muted);">—</td>' +
          '<td style="padding:5px 8px;border-bottom:1px solid var(--border);"><div style="height:8px;background:var(--bg-input);border-radius:4px;overflow:hidden;"><div style="height:100%;width:30%;background:var(--accent);border-radius:4px;opacity:0.5;"></div></div></td>' +
          '</tr>';
        return;
      }

      var barPct = Math.min(100, ((e.size_mb || 0) / maxMB) * 100);
      var stateTag = "";
      if (e.scanning) {
        // In progress: value is a partial running total that keeps growing.
        stateTag = ' <span style="font-size:0.7rem;color:var(--accent);">⟳ escaneando ' + (e.size_mb > 0 ? '(parcial)' : '') + '</span>';
      } else if (e.partial) {
        stateTag = ' <span style="color:var(--orange);font-size:0.7rem;">⚠ parcial</span>';
      }
      var barColor = e.scanning ? "var(--accent)" : (e.partial ? "var(--orange)" : "var(--accent)");
      var rowStyle = e.scanning ? "opacity:0.9;" : "";

      html += '<tr style="' + rowStyle + '">' +
        '<td style="padding:5px 8px;border-bottom:1px solid var(--border);color:var(--text-primary);">' + pathLink + stateTag + '</td>' +
        '<td style="padding:5px 8px;border-bottom:1px solid var(--border);text-align:right;font-weight:600;font-variant-numeric:tabular-nums;">' + Number(e.size_gb || 0).toFixed(2) + '</td>' +
        '<td style="padding:5px 8px;border-bottom:1px solid var(--border);text-align:right;font-variant-numeric:tabular-nums;">' + Math.round(e.size_mb || 0).toLocaleString() + '</td>' +
        '<td style="padding:5px 8px;border-bottom:1px solid var(--border);"><div style="height:8px;background:var(--bg-input);border-radius:4px;overflow:hidden;"><div style="height:100%;width:' + barPct.toFixed(1) + '%;background:' + barColor + ';border-radius:4px;"></div></div></td>' +
        '</tr>';
    });
    tbody.innerHTML = html;
  }

  function renderDiskUnaccountedDeletedSection() {
    var section = document.getElementById("diskUnaccountedDeletedSection");
    if (!section) return;
    var data = _diskUnaccountedData || { deleted_open_files: [], notes: [] };
    var files = data.deleted_open_files || [];
    var totalGB = Number(data.deleted_open_files_total_gb || 0);
    var html = '<h3 style="margin:0.75rem 0 0.5rem;font-size:0.9rem;color:var(--text-primary);">Archivos borrados pero aún abiertos</h3>';
    html += '<div style="display:flex;gap:0.75rem;flex-wrap:wrap;margin-bottom:0.75rem;">' +
      '<div style="padding:8px 10px;border:1px solid var(--border);border-radius:6px;background:var(--bg-input);"><strong style="color:var(--text-primary);">' + totalGB.toFixed(2) + ' GB</strong><br><span style="font-size:0.72rem;color:var(--text-muted);">deleted open files</span></div>' +
      '</div>';
    if (data.notes && data.notes.length) {
      html += '<div style="margin-bottom:0.75rem;color:var(--text-muted);line-height:1.45;">';
      data.notes.forEach(function(n) { html += '<div>• ' + escapeHtml(n) + '</div>'; });
      html += '</div>';
    }
    if (!files.length) {
      html += '<div style="padding:0.75rem;border:1px solid var(--border);border-radius:6px;color:var(--text-muted);">No deleted open files found. El espacio restante puede ser metadata del filesystem, bloques reservados o datos ocultos bajo mount points.</div>';
      section.innerHTML = html;
      return;
    }
    html += '<div style="overflow-x:auto;"><table style="width:100%;border-collapse:collapse;font-size:0.82rem;">' +
      '<thead><tr style="color:var(--text-muted);text-align:left;border-bottom:1px solid var(--border);">' +
      '<th style="padding:6px 8px;">Process</th><th style="padding:6px 8px;">PID</th><th style="padding:6px 8px;">FD</th><th style="padding:6px 8px;text-align:right;">GB</th><th style="padding:6px 8px;">Deleted file path</th>' +
      '</tr></thead><tbody>';
    files.forEach(function(f) {
      html += '<tr>' +
        '<td style="padding:5px 8px;border-bottom:1px solid var(--border);color:var(--text-primary);">' + escapeHtml(f.process || "-") + '</td>' +
        '<td style="padding:5px 8px;border-bottom:1px solid var(--border);font-variant-numeric:tabular-nums;">' + escapeHtml(String(f.pid || "")) + '</td>' +
        '<td style="padding:5px 8px;border-bottom:1px solid var(--border);font-variant-numeric:tabular-nums;">' + escapeHtml(String(f.fd || "")) + '</td>' +
        '<td style="padding:5px 8px;border-bottom:1px solid var(--border);text-align:right;font-weight:600;color:var(--text-primary);font-variant-numeric:tabular-nums;">' + Number(f.size_gb || 0).toFixed(2) + '</td>' +
        '<td style="padding:5px 8px;border-bottom:1px solid var(--border);font-family:monospace;font-size:0.74rem;color:var(--text-secondary);">' + escapeHtml(f.path || "") + '</td>' +
        '</tr>';
    });
    html += '</tbody></table></div>';
    section.innerHTML = html;
  }

  window.closeDiskUnaccounted = function() {
    var panel = document.getElementById("diskUnaccountedPanel");
    if (panel) panel.style.display = "none";
  };

  window.diskDrillFromUnaccounted = function(path) {
    closeDiskUnaccounted();
    diskDrillInto(path);
    var explorer = document.getElementById("diskBreakdownTitle");
    if (explorer) explorer.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  var STANDARD_ROOT_DIRS = {
    "/var": true, "/usr": true, "/home": true, "/tmp": true, "/opt": true,
    "/etc": true, "/root": true, "/srv": true, "/snap": true
  };

  window.toggleDockerVolumes = function(idx) {
    var el = document.getElementById("dockerVolDetail" + idx);
    if (el) el.style.display = el.style.display === "none" ? "block" : "none";
  };

  function renderDockerContainerDisk(entries) {
    var el = document.getElementById("dockerContainerDiskContent");
    var loading = document.getElementById("dockerContainerDiskLoading");
    if (loading) loading.textContent = "";
    if (!el) return;
    if (!entries || !entries.length) {
      el.innerHTML = '<div style="color:var(--text-muted);">No containers found or Docker is unavailable.</div>';
      return;
    }
    var maxTotal = entries[0].total_mb || 1;
    var html = '<div style="overflow-x:auto;"><table style="width:100%;border-collapse:collapse;">' +
      '<thead><tr style="color:var(--text-muted);text-align:left;border-bottom:1px solid var(--border);">' +
      '<th style="padding:6px 8px;">Container</th>' +
      '<th style="padding:6px 8px;">Image</th>' +
      '<th style="padding:6px 8px;">Status</th>' +
      '<th style="padding:6px 8px;">Age</th>' +
      '<th style="padding:6px 8px;text-align:right;">Writable</th>' +
      '<th style="padding:6px 8px;text-align:right;">Volumes</th>' +
      '<th style="padding:6px 8px;text-align:right;">Total</th>' +
      '<th style="padding:6px 8px;min-width:80px;">Bar</th>' +
      '</tr></thead><tbody>';
    entries.forEach(function(c, idx) {
      var statusLower = (c.status || "").toLowerCase();
      var statusColor = statusLower.indexOf("up") >= 0 ? "var(--green)" : "var(--text-muted)";
      var volDetail = "";
      if (c.volumes && c.volumes.length) {
        volDetail = '<div style="margin-top:4px;"><span style="cursor:pointer;color:var(--accent);font-size:0.72rem;" onclick="toggleDockerVolumes(' + idx + ')">▼ volumes</span>' +
          '<div id="dockerVolDetail' + idx + '" style="display:none;margin-top:4px;font-size:0.72rem;color:var(--text-secondary);">';
        c.volumes.forEach(function(v) {
          volDetail += '<div>' + escapeHtml(v.name) + ': ' + Number(v.size_gb || 0).toFixed(2) + ' GB</div>';
        });
        volDetail += '</div></div>';
      }
      var barPct = Math.min(100, (c.total_mb / maxTotal) * 100);
      html += '<tr>' +
        '<td style="padding:5px 8px;border-bottom:1px solid var(--border);font-weight:500;color:var(--text-primary);">' + escapeHtml(c.name || c.id) + '</td>' +
        '<td style="padding:5px 8px;border-bottom:1px solid var(--border);color:var(--text-secondary);max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + escapeHtml(c.image || "") + '">' + escapeHtml(c.image || "-") + '</td>' +
        '<td style="padding:5px 8px;border-bottom:1px solid var(--border);color:' + statusColor + ';">' + escapeHtml(c.status || "-") + '</td>' +
        '<td style="padding:5px 8px;border-bottom:1px solid var(--border);color:var(--text-secondary);white-space:nowrap;">' + escapeHtml(c.created_at || "-") + '</td>' +
        '<td style="padding:5px 8px;border-bottom:1px solid var(--border);text-align:right;font-variant-numeric:tabular-nums;">' + Number(c.writable_gb || 0).toFixed(2) + ' GB</td>' +
        '<td style="padding:5px 8px;border-bottom:1px solid var(--border);text-align:right;font-variant-numeric:tabular-nums;">' + Number(c.volumes_gb || 0).toFixed(2) + ' GB' + volDetail + '</td>' +
        '<td style="padding:5px 8px;border-bottom:1px solid var(--border);text-align:right;font-weight:600;font-variant-numeric:tabular-nums;">' + Number(c.total_gb || 0).toFixed(2) + ' GB</td>' +
        '<td style="padding:5px 8px;border-bottom:1px solid var(--border);"><div style="height:8px;background:var(--bg-input);border-radius:4px;overflow:hidden;"><div style="height:100%;width:' + barPct.toFixed(1) + '%;background:var(--accent);border-radius:4px;"></div></div></td>' +
        '</tr>';
    });
    html += '</tbody></table></div>';
    el.innerHTML = html;
  }

  var _dockerPruneModes = [];
  var _dockerPrunePending = null;
  var _dockerPruneActiveJob = null;
  var _dockerPrunePollJobId = null;
  var DOCKER_PRUNE_JOB_KEY = "sp_docker_prune_job_id";
  var dockerPruneChannel = (typeof BroadcastChannel !== "undefined") ? new BroadcastChannel("sp-docker-prune") : null;

  function rememberDockerPruneJob(jobId) {
    if (!jobId) return;
    try { localStorage.setItem(DOCKER_PRUNE_JOB_KEY, jobId); } catch (e) {}
  }

  function getRememberedDockerPruneJob() {
    try { return localStorage.getItem(DOCKER_PRUNE_JOB_KEY) || ""; } catch (e) { return ""; }
  }

  function clearRememberedDockerPruneJob() {
    try { localStorage.removeItem(DOCKER_PRUNE_JOB_KEY); } catch (e) {}
    _dockerPruneActiveJob = null;
  }

  function broadcastDockerPruneEvent(type) {
    if (dockerPruneChannel) {
      try { dockerPruneChannel.postMessage(type); } catch (e) {}
    }
  }

  async function fetchPruneJobStatus(jobId) {
    var url = "/api/system/docker-prune/status" + (jobId ? ("?job=" + encodeURIComponent(jobId)) : "");
    try {
      var resp = await fetch(url, { credentials: "same-origin", headers: { "Accept": "application/json" } });
      if (resp.status === 401) return { unauthorized: true };
      if (!resp.ok) {
        var errText = resp.statusText || "request failed";
        try {
          var body = await resp.text();
          if (body) {
            var parsed = JSON.parse(body);
            errText = parsed.error || parsed.message || errText;
          }
        } catch (e) {}
        return { error: errText };
      }
      var json = await resp.json();
      var job = (json && json.data !== undefined) ? json.data : json;
      return { job: job };
    } catch (e) {
      return { networkError: true };
    }
  }

  function updatePruneProgressUI(job) {
    if (!job) return;
    _dockerPruneActiveJob = job;
    var pct = Number(job.progress_percent || 0);
    var freedGB = Number(job.freed_gb || 0);
    var elapsed = Number(job.elapsed_seconds || 0);
    var statsText = freedGB > 0
      ? ("~" + freedGB.toFixed(2) + " GB liberados · " + pct.toFixed(1) + "% · " + elapsed + "s")
      : (pct > 0 ? (pct.toFixed(1) + "% · " + elapsed + "s") : (elapsed + "s en curso"));

    showPruneProgressBar(true);
    var fill = document.getElementById("progressPruneBarFill");
    var statsEl = document.getElementById("progressPruneBarStats");
    if (fill) fill.style.width = Math.max(pct > 0 ? 2 : 0, Math.min(100, pct)) + "%";
    if (statsEl) statsEl.textContent = statsText;
    setText(progressStatusText, "Prune en el servidor… " + statsText);

    var banner = document.getElementById("dockerPruneActiveBanner");
    var detail = document.getElementById("dockerPruneActiveDetail");
    var bar = document.getElementById("dockerPruneActiveBar");
    var title = document.getElementById("dockerPruneActiveTitle");
    if (banner) banner.style.display = "block";
    if (title) title.textContent = "Prune Docker en curso (" + (job.mode || "job") + ")";
    if (detail) detail.textContent = statsText + " — el job sigue aunque abras otra pestaña o recargues.";
    if (bar) bar.style.width = Math.max(pct > 0 ? 2 : 0, Math.min(100, pct)) + "%";
  }

  function hideDockerPruneActiveBanner() {
    var banner = document.getElementById("dockerPruneActiveBanner");
    if (banner) banner.style.display = "none";
    _dockerPruneActiveJob = null;
  }

  async function resumeDockerPruneWatch(options) {
    options = options || {};
    var status = await fetchPruneJobStatus("");
    var job = status && status.job;
    if ((!job || job.status !== "running") && !status.unauthorized) {
      var remembered = getRememberedDockerPruneJob();
      if (remembered) {
        var rememberedStatus = await fetchPruneJobStatus(remembered);
        if (rememberedStatus && rememberedStatus.job) job = rememberedStatus.job;
        if (rememberedStatus && rememberedStatus.unauthorized) status = rememberedStatus;
      }
    }
    if (status && status.unauthorized) {
      if (getRememberedDockerPruneJob()) {
        var banner = document.getElementById("dockerPruneActiveBanner");
        var detail = document.getElementById("dockerPruneActiveDetail");
        if (banner) banner.style.display = "block";
        if (detail) detail.textContent = "Hay un prune reciente en este navegador. Inicia sesión de nuevo para ver el progreso en vivo.";
      }
      return;
    }
    if (job && job.status === "running") {
      rememberDockerPruneJob(job.id);
      updatePruneProgressUI(job);
      if (options.openModal) watchDockerPruneJob(job.id, { openModal: true, quiet: true });
      return;
    }
    if (job && (job.status === "completed" || job.status === "failed")) {
      clearRememberedDockerPruneJob();
      hideDockerPruneActiveBanner();
      return;
    }
    if (!getRememberedDockerPruneJob()) hideDockerPruneActiveBanner();
  }

  async function watchDockerPruneJob(jobId, opts) {
    opts = opts || {};
    if (_dockerPrunePollJobId === jobId) return;
    _dockerPrunePollJobId = jobId;
    rememberDockerPruneJob(jobId);
    if (opts.openModal) {
      openProgressModal("Limpieza Docker", "Prune en curso en el servidor — puedes cambiar de pestaña; el job sigue.");
      if (!opts.quiet) appendLogLine("Siguiendo job " + jobId + "…");
      showPruneProgressBar(true);
    }
    try {
      await pollDockerPruneJob(jobId);
    } finally {
      if (_dockerPrunePollJobId === jobId) _dockerPrunePollJobId = null;
    }
  }

  // Mirror of docker.ReclaimSnapshot + EstimatePruneReclaim — fills estimates when the
  // prune/modes API ran before docker system df data was ready.
  function mergePruneModesWithDockerDisk(modes, dockerDisk) {
    if (!modes || !modes.length || !dockerDisk || !dockerDisk.length) return modes || [];
    var snap = { images: 0, containers: 0, volumes: 0, buildCache: 0 };
    dockerDisk.forEach(function(d) {
      var r = Number(d.reclaim_mb || 0);
      if (d.type === "Images") snap.images = r;
      else if (d.type === "Containers") snap.containers = r;
      else if (d.type === "Local Volumes") snap.volumes = r;
      else if (d.type === "Build Cache") snap.buildCache = r;
    });
    function estimate(mode) {
      var parts = [], total = 0;
      function add(label, mb) {
        if (mb <= 0) return;
        total += mb;
        parts.push({ label: label, gb: Math.round(mb / 1024 * 100) / 100 });
      }
      var note = "";
      if (mode === "safe") {
        add("Contenedores parados", snap.containers);
        add("Build cache", snap.buildCache);
        note = "No incluye imágenes sin usar completas (usa «Todas las imágenes sin usar»).";
      } else if (mode === "builder") {
        add("Build cache", snap.buildCache);
      } else if (mode === "images") {
        add("Imágenes sin usar", snap.images);
        add("Contenedores parados", snap.containers);
        add("Build cache", snap.buildCache);
      } else if (mode === "volumes") {
        add("Volúmenes huérfanos", snap.volumes);
      } else if (mode === "aggressive") {
        add("Imágenes sin usar", snap.images);
        add("Contenedores parados", snap.containers);
        add("Volúmenes huérfanos", snap.volumes);
        add("Build cache", snap.buildCache);
      }
      return { totalMB: Math.round(total * 100) / 100, parts: parts, note: note };
    }
    return modes.map(function(m) {
      if (m.estimate_available) return m;
      var est = estimate(m.mode);
      return Object.assign({}, m, {
        estimate_available: true,
        estimated_reclaim_mb: est.totalMB,
        estimated_reclaim_gb: Math.round(est.totalMB / 1024 * 100) / 100,
        estimate_parts: est.parts,
        estimate_note: est.note || m.estimate_note || ""
      });
    });
  }

  window.scrollToDockerPrune = function(highlightMode) {
    var card = document.getElementById("dockerPruneCard");
    if (card) {
      card.scrollIntoView({ behavior: "smooth", block: "start" });
      card.style.outline = "2px solid var(--accent)";
      setTimeout(function() { card.style.outline = ""; }, 2500);
    }
    if (highlightMode && _dockerPruneModes.length) {
      renderDockerPruneModes(_dockerPruneModes);
    }
  };

  function dockerPruneRiskStyle(risk) {
    if (risk === "high") return { color: "var(--red)", label: "Riesgo alto" };
    if (risk === "medium") return { color: "var(--orange)", label: "Riesgo medio" };
    return { color: "var(--green)", label: "Riesgo bajo" };
  }

  function formatPruneReclaimLabel(m) {
    if (!m.estimate_available) {
      return '<span style="font-size:0.78rem;color:var(--text-muted);">Estimado: — (Docker no disponible)</span>';
    }
    var gb = Number(m.estimated_reclaim_gb || 0);
    if (gb <= 0) {
      return '<span style="font-size:0.85rem;color:var(--text-muted);">Liberaría: <strong>0 GB</strong> <span style="font-size:0.72rem;">(nada recuperable ahora)</span></span>';
    }
    var html = '<div style="margin:0.35rem 0 0.15rem;">' +
      '<span style="font-size:0.95rem;font-weight:700;color:var(--green);">Liberaría ~' + gb.toFixed(2) + ' GB</span></div>';
    if (m.estimate_parts && m.estimate_parts.length) {
      html += '<div style="font-size:0.72rem;color:var(--text-muted);line-height:1.35;">';
      m.estimate_parts.forEach(function(p) {
        html += escapeHtml(p.label) + ': ' + Number(p.gb || 0).toFixed(2) + ' GB · ';
      });
      html = html.replace(/ · $/, '') + '</div>';
    }
    if (m.estimate_note) {
      html += '<div style="font-size:0.68rem;color:var(--text-muted);margin-top:0.2rem;line-height:1.35;">' + escapeHtml(m.estimate_note) + '</div>';
    }
    return html;
  }

  function renderDockerPruneModes(modes) {
    _dockerPruneModes = modes || [];
    var el = document.getElementById("dockerPruneModesList");
    if (!el) return;
    if (!_dockerPruneModes.length) {
      el.innerHTML = '<div style="color:var(--text-muted);">Docker no disponible o sin opciones de limpieza.</div>';
      return;
    }
    var html = '<div style="display:flex;flex-direction:column;gap:0.65rem;">';
    var pruneBusy = _dockerPruneActiveJob && _dockerPruneActiveJob.status === "running";
    _dockerPruneModes.forEach(function(m) {
      var risk = dockerPruneRiskStyle(m.risk);
      var reclaimHtml = formatPruneReclaimLabel(m);
      var btnDisabled = pruneBusy || (m.estimate_available && Number(m.estimated_reclaim_gb || 0) <= 0);
      var busyTitle = pruneBusy ? ' title="Hay un prune en curso — espera o pulsa Ver progreso"' : (btnDisabled ? ' title="Nada que liberar con esta opción ahora"' : "");
      html += '<div style="border:1px solid var(--border);border-radius:8px;padding:0.75rem;background:var(--bg-input);">' +
        '<div style="display:flex;align-items:flex-start;justify-content:space-between;gap:0.75rem;flex-wrap:wrap;">' +
          '<div style="flex:1;min-width:0;">' +
            '<div style="font-weight:600;color:var(--text-primary);margin-bottom:0.25rem;">' + escapeHtml(m.title || m.mode) +
              ' <span style="font-size:0.7rem;color:' + risk.color + ';">● ' + risk.label + '</span></div>' +
            reclaimHtml +
            '<div style="font-size:0.78rem;color:var(--text-secondary);line-height:1.4;margin-top:0.35rem;">' + escapeHtml(m.description || "") + '</div>' +
          '</div>' +
          '<button type="button" onclick="openDockerPruneModal(' + attrJSON(m.mode) + ')" ' +
            (btnDisabled ? 'disabled' + busyTitle : '') +
            ' style="background:' + (btnDisabled ? "var(--bg-secondary)" : (m.risk === "high" ? "var(--red)" : (m.risk === "medium" ? "var(--orange)" : "var(--accent)"))) +
            ';color:' + (btnDisabled ? "var(--text-muted)" : "#fff") +
            ';border:none;padding:6px 14px;border-radius:6px;font-size:0.78rem;cursor:' + (btnDisabled ? "not-allowed" : "pointer") + ';white-space:nowrap;">Ejecutar</button>' +
        '</div></div>';
    });
    html += '</div>';
    el.innerHTML = html;
  }

  window.openDockerPruneModal = function(mode) {
    var info = null;
    for (var i = 0; i < _dockerPruneModes.length; i++) {
      if (_dockerPruneModes[i].mode === mode) { info = _dockerPruneModes[i]; break; }
    }
    if (!info) return;
    _dockerPrunePending = info;

    var risk = dockerPruneRiskStyle(info.risk);
    document.getElementById("dockerPruneModalTitle").textContent = info.title || "Confirmar limpieza Docker";
    document.getElementById("dockerPruneModalRisk").innerHTML = '<span style="color:' + risk.color + ';">' + risk.label + '</span>';
    document.getElementById("dockerPruneModalDesc").textContent = info.description || "";

    var reclaimBanner = document.getElementById("dockerPruneModalReclaim");
    if (reclaimBanner) {
      if (info.estimate_available && Number(info.estimated_reclaim_gb || 0) > 0) {
        var partsText = "";
        if (info.estimate_parts && info.estimate_parts.length) {
          partsText = info.estimate_parts.map(function(p) {
            return p.label + ": " + Number(p.gb || 0).toFixed(2) + " GB";
          }).join(" · ");
        }
        reclaimBanner.style.display = "block";
        reclaimBanner.innerHTML =
          '<strong style="color:var(--green);font-size:1rem;">Espacio estimado a liberar: ~' +
          Number(info.estimated_reclaim_gb || 0).toFixed(2) + ' GB</strong>' +
          (partsText ? '<div style="font-size:0.75rem;color:var(--text-muted);margin-top:0.25rem;">' + escapeHtml(partsText) + '</div>' : '') +
          (info.estimate_note ? '<div style="font-size:0.72rem;color:var(--text-muted);margin-top:0.25rem;">' + escapeHtml(info.estimate_note) + '</div>' : '');
      } else if (info.estimate_available) {
        reclaimBanner.style.display = "block";
        reclaimBanner.innerHTML = '<span style="color:var(--text-muted);">No hay espacio recuperable con esta opción en este momento.</span>';
      } else {
        reclaimBanner.style.display = "none";
        reclaimBanner.innerHTML = "";
      }
    }

    var removesEl = document.getElementById("dockerPruneModalRemoves");
    var keepsEl = document.getElementById("dockerPruneModalKeeps");
    removesEl.innerHTML = '<strong style="color:var(--text-primary);">Elimina:</strong><ul style="margin:0.35rem 0 0 1.1rem;padding:0;">' +
      (info.removes || []).map(function(x) { return '<li>' + escapeHtml(x) + '</li>'; }).join("") + '</ul>';
    keepsEl.innerHTML = '<strong style="color:var(--text-primary);">No toca:</strong><ul style="margin:0.35rem 0 0 1.1rem;padding:0;">' +
      (info.keeps || []).map(function(x) { return '<li>' + escapeHtml(x) + '</li>'; }).join("") + '</ul>';

    var typeWrap = document.getElementById("dockerPruneTypeConfirmWrap");
    var typeInput = document.getElementById("dockerPruneTypeConfirmInput");
    var typeLabel = document.getElementById("dockerPruneTypeConfirmLabel");
    if (info.requires_type_confirm) {
      typeWrap.style.display = "block";
      typeLabel.textContent = info.mode;
      typeInput.value = "";
      setTimeout(function() { typeInput.focus(); }, 50);
    } else {
      typeWrap.style.display = "none";
      typeInput.value = "";
    }

    document.getElementById("dockerPruneModalOutput").style.display = "none";
    document.getElementById("dockerPruneModalOutput").textContent = "";
    document.getElementById("dockerPruneExecuteBtn").disabled = false;
    document.getElementById("dockerPruneExecuteBtn").textContent = "Ejecutar prune";
    document.getElementById("dockerPruneModal").classList.add("show");
  };

  window.closeDockerPruneModal = function() {
    _dockerPrunePending = null;
    document.getElementById("dockerPruneModal").classList.remove("show");
  };

  async function pollDockerPruneJob(jobId) {
    var started = Date.now();
    var maxWaitMs = 35 * 60 * 1000;
    var lastLineAt = 0;
    var authWarned = false;
    while (Date.now() - started < maxWaitMs) {
      var status = await fetchPruneJobStatus(jobId);
      if (status && status.unauthorized) {
        if (!authWarned) {
          authWarned = true;
          appendLogLine("Sesión expirada en esta pestaña. El prune sigue en el servidor — recarga o inicia sesión y pulsa «Ver progreso».");
          showToast("Sesión expirada aquí, pero el prune sigue en el servidor", "warning");
        }
        return;
      }
      if (status && status.networkError) {
        await new Promise(function(resolve) { setTimeout(resolve, 5000); });
        continue;
      }
      if (status && status.error) throw new Error(status.error);

      var job = status && status.job;
      if (!job) throw new Error("estado del job no disponible");

      updatePruneProgressUI(job);
      if (dockerPruneChannel) {
        try { dockerPruneChannel.postMessage({ type: "progress", job: job }); } catch (e) {}
      }

      if (Date.now() - lastLineAt > 15000) {
        var line = "[" + (job.elapsed_seconds || 0) + "s]";
        if (Number(job.freed_gb || 0) > 0) line += " ~" + Number(job.freed_gb).toFixed(2) + " GB liberados";
        if (Number(job.progress_percent || 0) > 0) line += " (" + Number(job.progress_percent).toFixed(1) + "%)";
        appendLogLine(line);
        lastLineAt = Date.now();
      }

      if (job.status === "completed") {
        if (job.output) {
          job.output.split("\n").forEach(function(line) {
            if (line.trim()) appendLogLine(line);
          });
        }
        clearRememberedDockerPruneJob();
        hideDockerPruneActiveBanner();
        broadcastDockerPruneEvent("completed");
        finishProgress(true, "Limpieza Docker completada");
        showToast("Limpieza Docker completada", "success");
        setTimeout(function() { loadResources(); }, 800);
        return;
      }
      if (job.status === "failed") {
        clearRememberedDockerPruneJob();
        hideDockerPruneActiveBanner();
        broadcastDockerPruneEvent("failed");
        throw new Error(job.error || "docker prune failed");
      }
      await new Promise(function(resolve) { setTimeout(resolve, 3000); });
    }
    appendLogLine("Timeout de UI — el prune puede seguir en el servidor. Pulsa «Ver progreso» o recarga Resources.");
    showToast("Timeout de UI — revisa el progreso en unos minutos", "warning");
  }

  async function executeDockerPrune() {
    if (!_dockerPrunePending) return;
    var info = _dockerPrunePending;
    var btn = document.getElementById("dockerPruneExecuteBtn");
    var confirmVal = "";
    if (info.requires_type_confirm) {
      confirmVal = (document.getElementById("dockerPruneTypeConfirmInput").value || "").trim();
      if (confirmVal !== info.mode) {
        showToast('Escribe "' + info.mode + '" para confirmar', "warning");
        return;
      }
    }

    if (btn) { btn.disabled = true; btn.textContent = "Ejecutando…"; }

    try {
      closeDockerPruneModal();
      openProgressModal("Limpieza Docker", (info.title || info.mode) + " — corre en el servidor; puedes abrir otra pestaña.");
      showPruneProgressBar(true);
      appendLogLine("Iniciando " + (info.title || info.mode) + "…");

      var resp = await apiFetch("/api/system/docker-prune", {
        method: "POST",
        body: { mode: info.mode, confirm: confirmVal || info.mode }
      });

      var job = (resp && resp.data) ? resp.data : resp;
      if (!job || !job.id) throw new Error("no se recibió job id del servidor");
      appendLogLine("Job " + job.id + " en el servidor.");
      updatePruneProgressUI(job);
      await watchDockerPruneJob(job.id, { quiet: true });
    } catch (err) {
      finishProgress(false, err.message || "error");
      showToast("Prune falló: " + (err.message || "error"), "error");
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = "Ejecutar prune"; }
    }
  }

  (function initDockerPruneModal() {
    var modal = document.getElementById("dockerPruneModal");
    var cancelBtn = document.getElementById("dockerPruneCancelBtn");
    var execBtn = document.getElementById("dockerPruneExecuteBtn");
    var watchBtn = document.getElementById("dockerPruneWatchBtn");
    if (cancelBtn) cancelBtn.addEventListener("click", closeDockerPruneModal);
    if (execBtn) execBtn.addEventListener("click", executeDockerPrune);
    if (watchBtn) watchBtn.addEventListener("click", function() {
      var jobId = (_dockerPruneActiveJob && _dockerPruneActiveJob.id) || getRememberedDockerPruneJob();
      if (jobId) watchDockerPruneJob(jobId, { openModal: true });
      else resumeDockerPruneWatch({ openModal: true });
    });
    if (modal) {
      modal.addEventListener("click", function(e) {
        if (e.target === modal) closeDockerPruneModal();
      });
    }
    if (dockerPruneChannel) {
      dockerPruneChannel.onmessage = function(ev) {
        var data = ev.data;
        if (data && data.type === "progress" && data.job) {
          updatePruneProgressUI(data.job);
          return;
        }
        if (data === "completed") {
          clearRememberedDockerPruneJob();
          hideDockerPruneActiveBanner();
          loadResources();
        } else if (data === "failed") {
          clearRememberedDockerPruneJob();
          hideDockerPruneActiveBanner();
        }
      };
    }
  })();

  window.diskToggleSelect = function(path, checked) {
    if (checked) diskSelectedPaths[path] = true;
    else delete diskSelectedPaths[path];
    showDiskActionBar();
  };

  window.diskSelectAll = function() {
    var filtered = diskCurrentFilter === "all" ? diskCurrentEntries : diskCurrentEntries.filter(function(e) { return e.type === diskCurrentFilter; });
    filtered.forEach(function(e) { diskSelectedPaths[e.path] = true; });
    renderDiskTable(diskCurrentEntries);
    showDiskActionBar();
  };

  window.diskDeselectAll = function() {
    diskSelectedPaths = {};
    renderDiskTable(diskCurrentEntries);
    showDiskActionBar();
  };

  window.diskDeleteSelected = async function() {
    var paths = Object.keys(diskSelectedPaths);
    if (paths.length === 0) return;
    if (!confirm("Delete " + paths.length + " item(s)? This cannot be undone.")) return;
    var btn = document.getElementById("diskDeleteSelectedBtn");
    if (btn) { btn.disabled = true; btn.textContent = "Deleting..."; }
    try {
      var resp = await apiFetch("/api/system/disk-clean", { method: "POST", body: { paths: paths } });
      var data = resp.data || resp;
      diskSelectedPaths = {};
      showToast("Deleted " + (data.deleted || 0) + " item(s)" + (data.failed > 0 ? ", " + data.failed + " failed" : ""), data.failed > 0 ? "warning" : "success");
      if (diskCurrentPath) { diskDrillInto(diskCurrentPath); } else { loadResources(); }
    } catch(err) {
      showToast("Delete failed: " + err.message, "error");
    }
    if (btn) { btn.disabled = false; btn.textContent = "Delete Selected"; }
  };

  // --- Top Files: tabs, hidden, selection ---
  var topFilesCurrentTab = "main"; // "main" or "hidden"
  var topFilesSelectedPaths = {};
  var topFilesData = []; // cached main top files
  var hiddenFilesData = []; // cached hidden file entries

  async function loadTopFiles() {
    var topLoading = document.getElementById("topFilesLoading");
    var tbody = document.getElementById("topFilesBody");
    try {
      var resp = await apiFetch("/api/system/disk-top-files?path=/&limit=10");
      if (topLoading) topLoading.style.display = "none";
      topFilesData = resp.data || resp || [];
      renderTopFilesTable(topFilesData);
    } catch(err) {
      if (topLoading) topLoading.textContent = "(error)";
      if (tbody) {
        tbody.innerHTML = '<tr><td colspan="7" style="padding:1rem;color:var(--red);">Failed to load largest files: ' + escapeHtml(err.message) + '</td></tr>';
      }
    }
    // Also load hidden files count.
    loadHiddenFiles();
  }

  async function loadHiddenFiles() {
    try {
      var resp = await apiFetch("/api/system/disk-hidden-files");
      var paths = resp.data || resp || [];
      hiddenFilesData = paths;
      var countEl = document.getElementById("hiddenFilesCount");
      if (countEl) countEl.textContent = paths.length;
    } catch(err) {
      hiddenFilesData = [];
    }
  }

  function renderTopFilesTable(files) {
    var tbody = document.getElementById("topFilesBody");
    if (!tbody) return;
    tbody.innerHTML = "";
    if (files.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" style="padding:1rem;color:var(--text-muted);text-align:center;">No large files found</td></tr>';
      return;
    }
    var refMB = diskTotalSizeMB > 0 ? diskTotalSizeMB : 1;
    files.forEach(function(f, i) {
      var pct = refMB > 0 ? (f.size_mb / refMB * 100) : 0;
      var barW = pct > 100 ? 100 : pct;
      if (barW > 0 && barW < 1.5) barW = 1.5;
      var color = DISK_COLORS[i % DISK_COLORS.length];
      var icon = TYPE_ICONS[f.type] || TYPE_ICONS.other;
      var safePath = f.path.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
      var isChecked = topFilesSelectedPaths[f.path] ? "checked" : "";
      var cleanable = f.cleanable !== false;
      var cleanTitle = cleanable ? "Select for deletion" : ("Not deletable from dashboard: " + (f.clean_block_reason || "not in cleanable allowlist"));
      var checkboxHtml = cleanable
        ? '<input type="checkbox" ' + isChecked + ' title="' + escapeHtml(cleanTitle) + '" onchange="topFilesToggleSelect(\'' + safePath + '\', this.checked)" style="cursor:pointer;">'
        : '<input type="checkbox" disabled title="' + escapeHtml(cleanTitle) + '" style="cursor:not-allowed;opacity:0.45;">';
      var cleanBadge = cleanable
        ? ''
        : '<span style="display:inline-block;margin-left:6px;padding:1px 6px;border-radius:8px;background:rgba(210,153,34,0.12);color:var(--yellow);font-size:0.65rem;">protected</span>';
      var tr = document.createElement("tr");
      tr.innerHTML =
        '<td style="padding:4px;border-bottom:1px solid var(--border);text-align:center;">' + checkboxHtml + '</td>' +
        '<td style="padding:4px 8px;border-bottom:1px solid var(--border);"><span style="color:var(--text-primary);font-weight:500;">' + escapeHtml(f.name) + '</span>' + cleanBadge + '<br><span style="font-size:0.7rem;color:var(--text-muted);">' + escapeHtml(f.path) + '</span></td>' +
        '<td style="padding:4px;border-bottom:1px solid var(--border);text-align:center;">' + icon + '</td>' +
        '<td style="padding:4px 8px;border-bottom:1px solid var(--border);text-align:right;font-variant-numeric:tabular-nums;font-weight:600;">' + f.size_gb.toFixed(2) + '</td>' +
        '<td style="padding:4px 8px;border-bottom:1px solid var(--border);text-align:right;font-variant-numeric:tabular-nums;color:var(--text-secondary);">' + f.size_mb.toFixed(1) + '</td>' +
        '<td style="padding:4px 8px;border-bottom:1px solid var(--border);text-align:right;font-variant-numeric:tabular-nums;color:var(--text-secondary);">' + pct.toFixed(1) + '%</td>' +
        '<td style="padding:4px 8px;border-bottom:1px solid var(--border);"><div style="background:var(--bg-input);border-radius:4px;height:12px;overflow:hidden;"><div style="width:' + barW.toFixed(1) + '%;height:100%;background:' + color + ';border-radius:4px;"></div></div></td>';
      tbody.appendChild(tr);
    });
  }

  async function renderHiddenFilesTable() {
    var tbody = document.getElementById("hiddenFilesBody");
    if (!tbody) return;
    tbody.innerHTML = '<tr><td colspan="7" style="padding:1rem;color:var(--text-muted);text-align:center;">Loading hidden files...</td></tr>';

    try {
      var resp = await apiFetch("/api/system/disk-hidden-files");
      var paths = resp.data || resp || [];
      hiddenFilesData = paths;
      var countEl = document.getElementById("hiddenFilesCount");
      if (countEl) countEl.textContent = paths.length;

      tbody.innerHTML = "";
      if (paths.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="padding:1rem;color:var(--text-muted);text-align:center;">No hidden files. Hide files from the Top 10 tab to skip them.</td></tr>';
        return;
      }

      paths.forEach(function(p, i) {
        var name = p.split("/").pop() || p;
        var safePath = p.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
        var isChecked = topFilesSelectedPaths[p] ? "checked" : "";
        var color = DISK_COLORS[i % DISK_COLORS.length];
        var tr = document.createElement("tr");
        tr.innerHTML =
          '<td style="padding:4px;border-bottom:1px solid var(--border);text-align:center;"><input type="checkbox" ' + isChecked + ' onchange="topFilesToggleSelect(\'' + safePath + '\', this.checked)" style="cursor:pointer;"></td>' +
          '<td style="padding:4px 8px;border-bottom:1px solid var(--border);"><span style="color:var(--text-primary);font-weight:500;">' + escapeHtml(name) + '</span><br><span style="font-size:0.7rem;color:var(--text-muted);">' + escapeHtml(p) + '</span></td>' +
          '<td style="padding:4px;border-bottom:1px solid var(--border);text-align:center;color:var(--text-muted);">-</td>' +
          '<td style="padding:4px 8px;border-bottom:1px solid var(--border);text-align:right;color:var(--text-muted);">-</td>' +
          '<td style="padding:4px 8px;border-bottom:1px solid var(--border);text-align:right;color:var(--text-muted);">-</td>' +
          '<td style="padding:4px 8px;border-bottom:1px solid var(--border);text-align:right;color:var(--text-muted);">-</td>' +
          '<td style="padding:4px 8px;border-bottom:1px solid var(--border);color:var(--text-muted);font-size:0.75rem;font-style:italic;">hidden</td>';
        tbody.appendChild(tr);
      });
    } catch(err) {
      tbody.innerHTML = '<tr><td colspan="7" style="padding:1rem;color:var(--red);">Error loading hidden files</td></tr>';
    }
  }

  window.topFilesSwitchTab = function(tab) {
    topFilesCurrentTab = tab;
    topFilesSelectedPaths = {};
    showTopFilesActionBar();

    var tabMain = document.getElementById("topFilesTabMain");
    var tabHidden = document.getElementById("topFilesTabHidden");
    var panelMain = document.getElementById("topFilesPanelMain");
    var panelHidden = document.getElementById("topFilesPanelHidden");

    if (tab === "main") {
      tabMain.style.borderBottomColor = "var(--accent)";
      tabMain.style.color = "var(--accent)";
      tabMain.style.fontWeight = "600";
      tabHidden.style.borderBottomColor = "transparent";
      tabHidden.style.color = "var(--text-muted)";
      tabHidden.style.fontWeight = "500";
      panelMain.style.display = "block";
      panelHidden.style.display = "none";
    } else {
      tabMain.style.borderBottomColor = "transparent";
      tabMain.style.color = "var(--text-muted)";
      tabMain.style.fontWeight = "500";
      tabHidden.style.borderBottomColor = "var(--accent)";
      tabHidden.style.color = "var(--accent)";
      tabHidden.style.fontWeight = "600";
      panelMain.style.display = "none";
      panelHidden.style.display = "block";
      renderHiddenFilesTable();
    }
  };

  window.topFilesToggleSelect = function(path, checked) {
    if (checked) topFilesSelectedPaths[path] = true;
    else delete topFilesSelectedPaths[path];
    showTopFilesActionBar();
  };

  window.topFilesSelectAll = function() {
    if (topFilesCurrentTab === "main") {
      topFilesData.forEach(function(f) { if (f.cleanable !== false) topFilesSelectedPaths[f.path] = true; });
      renderTopFilesTable(topFilesData);
    } else {
      hiddenFilesData.forEach(function(p) { topFilesSelectedPaths[p] = true; });
      renderHiddenFilesTable();
    }
    showTopFilesActionBar();
  };

  window.topFilesDeselectAll = function() {
    topFilesSelectedPaths = {};
    if (topFilesCurrentTab === "main") {
      renderTopFilesTable(topFilesData);
    } else {
      renderHiddenFilesTable();
    }
    showTopFilesActionBar();
  };

  function showTopFilesActionBar() {
    var bar = document.getElementById("topFilesActionBar");
    var count = Object.keys(topFilesSelectedPaths).length;
    var hideBtn = document.getElementById("topFilesHideBtn");
    var unhideBtn = document.getElementById("topFilesUnhideBtn");

    if (bar) {
      bar.style.display = count > 0 ? "flex" : "none";
      var countEl = document.getElementById("topFilesSelectedCount");
      if (countEl) countEl.textContent = count + " selected";
    }
    // Show appropriate button based on active tab.
    if (hideBtn) hideBtn.style.display = topFilesCurrentTab === "main" ? "inline-block" : "none";
    if (unhideBtn) unhideBtn.style.display = topFilesCurrentTab === "hidden" ? "inline-block" : "none";
  }

  window.topFilesHideSelected = async function() {
    var paths = Object.keys(topFilesSelectedPaths);
    if (paths.length === 0) return;
    var btn = document.getElementById("topFilesHideBtn");
    if (btn) { btn.disabled = true; btn.textContent = "Hiding..."; }
    try {
      await apiFetch("/api/system/disk-hidden-files/add", { method: "POST", body: { paths: paths } });
      topFilesSelectedPaths = {};
      showTopFilesActionBar();
      showToast(paths.length + " file(s) hidden from Top 10", "success");
      // Reload top files (they'll be filtered out by backend).
      loadTopFiles();
    } catch(err) {
      showToast("Failed to hide files: " + err.message, "error");
    }
    if (btn) { btn.disabled = false; btn.textContent = "Hide Selected"; }
  };

  window.topFilesUnhideSelected = async function() {
    var paths = Object.keys(topFilesSelectedPaths);
    if (paths.length === 0) return;
    var btn = document.getElementById("topFilesUnhideBtn");
    if (btn) { btn.disabled = true; btn.textContent = "Unhiding..."; }
    try {
      await apiFetch("/api/system/disk-hidden-files/remove", { method: "POST", body: { paths: paths } });
      topFilesSelectedPaths = {};
      showTopFilesActionBar();
      showToast(paths.length + " file(s) restored to Top 10", "success");
      // Reload hidden tab and refresh main data.
      renderHiddenFilesTable();
      loadTopFiles();
    } catch(err) {
      showToast("Failed to unhide files: " + err.message, "error");
    }
    if (btn) { btn.disabled = false; btn.textContent = "Unhide Selected"; }
  };

  function renderServicesTable(d) {
    var wrap = document.getElementById("servicesContent");
    if (!wrap) return;
    wrap.innerHTML = "";

    var svcs = d.services || [];
    if (!svcs.length) {
      var em = document.createElement("div");
      em.className = "empty-state";
      var p = document.createElement("p");
      setText(p, "No services detected");
      em.appendChild(p);
      wrap.appendChild(em);
      return;
    }

    var tw = document.createElement("div");
    tw.className = "table-wrap";
    var table = document.createElement("table");

    var thead = document.createElement("thead");
    var trh = document.createElement("tr");
    ["Service", "Status", "Memory Live", "Memory Last 1h"].forEach(function(h) {
      var th = document.createElement("th");
      setText(th, h);
      trh.appendChild(th);
    });
    thead.appendChild(trh);
    table.appendChild(thead);

    var tbody = document.createElement("tbody");
    svcs.forEach(function(svc) {
      var tr = document.createElement("tr");

      var tdName = document.createElement("td");
      var nameStr = document.createElement("strong");
      setText(nameStr, svc.name);
      tdName.appendChild(nameStr);
      tr.appendChild(tdName);

      var tdStatus = document.createElement("td");
      var badge = document.createElement("span");
      badge.className = "badge " + (svc.active ? "badge-running" : "badge-stopped");
      var dot = document.createElement("span");
      dot.className = "badge-dot";
      badge.appendChild(dot);
      badge.appendChild(document.createTextNode(" " + svc.status));
      tdStatus.appendChild(badge);
      tr.appendChild(tdStatus);

      // Memory Live (with pulsing dot)
      var tdMemLive = document.createElement("td");
      if (svc.mem_mb > 0) {
        var liveDot = document.createElement("span");
        liveDot.className = "live-dot";
        liveDot.title = "Real-time";
        tdMemLive.appendChild(liveDot);
        tdMemLive.appendChild(document.createTextNode(formatMemDual(svc.mem_mb)));
      } else {
        tdMemLive.style.color = "var(--text-muted)";
        setText(tdMemLive, "-");
      }
      tr.appendChild(tdMemLive);

      // Memory Last 1h (sparkline)
      var tdMemHist = document.createElement("td");
      var history = svc.mem_history;
      if (history && history.length >= 2) {
        var sparkSvg = renderSparkline(history);
        if (sparkSvg) {
          tdMemHist.appendChild(sparkSvg);
          // Show min/max range
          var vals = history.map(function(h) { return h.mem_mb; });
          var minV = Math.min.apply(null, vals).toFixed(0);
          var maxV = Math.max.apply(null, vals).toFixed(0);
          var rangeSpan = document.createElement("span");
          rangeSpan.style.fontSize = "0.7rem";
          rangeSpan.style.color = "var(--text-muted)";
          rangeSpan.style.marginLeft = "6px";
          setText(rangeSpan, minV + "-" + maxV + " MB");
          tdMemHist.appendChild(rangeSpan);
        }
      } else {
        tdMemHist.style.color = "var(--text-muted)";
        tdMemHist.style.fontSize = "0.8rem";
        setText(tdMemHist, history && history.length === 1 ? "Collecting..." : "No data yet");
      }
      tr.appendChild(tdMemHist);

      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    tw.appendChild(table);
    wrap.appendChild(tw);
  }

  // ── Container Stats Table ──
  function renderContainerStats(d) {
