/* Resources tab */
"use strict";


  var resourcesFirstLoad = true; // first load shows spinners, subsequent refreshes are silent
  var _resourcesInflight = null;

  async function loadResources(opts) {
    opts = opts || {};
    if (_resourcesInflight && !opts.force) {
      return _resourcesInflight;
    }
    _resourcesInflight = loadResourcesBody(opts).finally(function() {
      _resourcesInflight = null;
    });
    return _resourcesInflight;
  }

  async function loadResourcesBody(opts) {
    opts = opts || {};
    // Fire both requests in parallel — main system data is fast,
    // disk breakdown is slow (runs du on multiple directories).
    var sysPromise = apiFetch("/api/system").catch(function() { return null; });
    var diskPromise = apiFetch("/api/system/disk-breakdown").catch(function() { return null; });
    var dockerDiskPromise = apiFetch("/api/system/docker-container-disk").catch(function() { return null; });
    var dockerPrunePromise = apiFetch("/api/system/docker-prune/modes").catch(function() { return null; });

    // Render main data as soon as it arrives (don't wait for disk breakdown).
    var resp = await sysPromise;
    if (resp && resp.data) sysData = resp.data;
    else if (resp && !resp.data) sysData = resp;
    renderResources();

    // When disk breakdown arrives, merge it in.
    var diskResp = await diskPromise;
    if (diskResp) {
      var payload = diskResp.data || diskResp;
      var breakdown = Array.isArray(payload) ? payload : (payload.breakdown || []);
      var dockerFromBreakdown = Array.isArray(payload) ? null : payload.docker_disk;
      if (sysData) {
        sysData.disk_breakdown = breakdown;
        if (dockerFromBreakdown && dockerFromBreakdown.length) {
          sysData.docker_disk = dockerFromBreakdown;
        }
      }

      if (diskCurrentPath) {
        diskDrillIntoSilent(diskCurrentPath);
        loadTopFiles();
      } else {
        renderDiskBreakdown(sysData || { disk_breakdown: breakdown, docker_disk: dockerFromBreakdown || [] });
      }
    }

    var dockerDiskResp = await dockerDiskPromise;
    if (dockerDiskResp) {
      renderDockerContainerDisk(dockerDiskResp.data || dockerDiskResp || []);
    } else {
      renderDockerContainerDisk([]);
    }

    var dockerPruneResp = await dockerPrunePromise;
    var pruneModes = dockerPruneResp ? (dockerPruneResp.data || dockerPruneResp || []) : [];
    renderDockerPruneModes(mergePruneModesWithDockerDisk(pruneModes, sysData && sysData.docker_disk));
    resumeDockerPruneWatch();

    resourcesFirstLoad = false;
  }

  function renderResources() {
    if (!sysData) return;
    var d = sysData;

    // Update timestamp
    updateTabTimestamp("resources");

    // Summary cards
    if (d.load_avg) {
      setText(document.getElementById("resCpuLoad"), d.load_avg.load1.toFixed(2));
      setText(document.getElementById("resCpuSub"), d.num_cpu + " cores | 5m: " + d.load_avg.load5.toFixed(2) + " | 15m: " + d.load_avg.load15.toFixed(2));
    }

    if (d.memory) {
      var memPct = d.memory.used_percent.toFixed(1) + "%";
      setText(document.getElementById("resMemValue"), memPct);
      var usedGB = (d.memory.used_mb / 1024).toFixed(2);
      var totalGB = (d.memory.total_mb / 1024).toFixed(2);
      setText(document.getElementById("resMemSub"), usedGB + " / " + totalGB + " GB (" + d.memory.used_mb + " / " + d.memory.total_mb + " MB)");
    }

    if (d.disk && d.disk.length > 0) {
      var rootDisk = d.disk[0];
      setText(document.getElementById("resDiskValue"), rootDisk.used_percent.toFixed(1) + "%");
      var sizeGB = (rootDisk.size_mb / 1024).toFixed(2);
      var usedGB = (rootDisk.used_mb / 1024).toFixed(2);
      var availGB = (rootDisk.avail_mb / 1024).toFixed(2);
      setText(document.getElementById("resDiskSub"), usedGB + " / " + sizeGB + " GB (used/total)");
      setText(document.getElementById("resDiskSubMB"), rootDisk.used_mb + " / " + rootDisk.size_mb + " MB (used/total)");
      setText(document.getElementById("resDiskAvail"), "Available: " + availGB + " GB (" + rootDisk.avail_mb + " MB)");
    }

    setText(document.getElementById("resUptime"), d.uptime || "--");
    setText(document.getElementById("resHostname"), d.hostname || "--");
    setText(document.getElementById("resPublicIP"), "Public IP: " + (d.public_ip || "unavailable"));

    // Memory Pie Chart
    renderMemoryPie(d);

    // If the memory breakdown panel is open, refresh its stats in-place
    // so they stay in sync with the freshly re-rendered pie chart.
    var memPanel = document.getElementById("memDetailPanel");
    if (memPanel && memPanel.style.display !== "none" && d.memory) {
      updateMemDetailStats(d.memory);
    }

    // CPU Bar Chart
    renderCpuBars(d);

    // Services Table
    renderServicesTable(d);

    // Container Stats Table
    renderContainerStats(d);

    // Disk Breakdown is loaded lazily via /api/system/disk-breakdown.
    // Only render if data is already available (e.g., from a previous load).
    if (d.disk_breakdown && d.disk_breakdown.length > 0) {
      renderDiskBreakdown(d);
    }
  }
