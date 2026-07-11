/* SVG charts */
"use strict";


  function renderMemoryPie(d) {
    var svg = document.getElementById("memPieChart");
    if (!svg) return;
    svg.innerHTML = "";

    var slices = [];
    var totalMem = d.memory ? d.memory.total_mb : 0;
    if (totalMem <= 0) return;

    // ServerPilot memory — prefer systemctl cgroup value (matches Services table),
    // fall back to self_process VmRSS if the service isn't listed.
    var spMem = 0;
    if (d.services) {
      d.services.forEach(function(s) {
        if (s.name === "serverpilot" && s.mem_mb > 0) spMem = s.mem_mb;
      });
    }
    if (spMem <= 0 && d.self_process) spMem = d.self_process.mem_mb || 0;
    if (spMem > 0) slices.push({ label: "ServerPilot", value: spMem });

    // Docker containers
    var containerMem = 0;
    if (d.containers) {
      d.containers.forEach(function(c) { containerMem += c.mem_mb; });
    }
    if (containerMem > 0) slices.push({ label: "Containers", value: containerMem });

    // Nginx (from services)
    var nginxMem = 0;
    if (d.services) {
      d.services.forEach(function(s) {
        if (s.name === "nginx" && s.mem_mb > 0) nginxMem = s.mem_mb;
      });
    }
    if (nginxMem > 0) slices.push({ label: "Nginx", value: nginxMem });

    // Docker daemon (from services)
    var dockerMem = 0;
    if (d.services) {
      d.services.forEach(function(s) {
        if (s.name === "docker" && s.mem_mb > 0) dockerMem = s.mem_mb;
      });
    }
    if (dockerMem > 0) slices.push({ label: "Docker Engine", value: dockerMem });

    // System / Other
    var accounted = spMem + containerMem + nginxMem + dockerMem;
    var usedMem = d.memory ? d.memory.used_mb : 0;
    var otherMem = usedMem - accounted;
    if (otherMem > 0) slices.push({ label: "System / Other ▾", value: otherMem, clickable: true, memData: d.memory });

    // Free memory
    var freeMem = totalMem - usedMem;
    if (freeMem > 0) slices.push({ label: "Free", value: freeMem });

    // Highlight "Free" in the chart title
    var memTitle = document.getElementById("memPieTitle");
    if (memTitle && freeMem > 0) {
      var freeGB = (freeMem / 1024).toFixed(2);
      var freeIdx = slices.length - 1; // "Free" is always last
      var freeColor = PIE_COLORS[freeIdx % PIE_COLORS.length];
      memTitle.innerHTML = 'Memory Distribution — <span style="color:' + freeColor + ';font-weight:700;">Free: ' + freeGB + ' GB (' + freeMem + ' MB)</span>';
    }

    if (slices.length === 0) return;

    var total = 0;
    slices.forEach(function(s) { total += s.value; });

    var cx = 130, cy = 120, r = 90;
    var startAngle = -Math.PI / 2;
    var ns = "http://www.w3.org/2000/svg";

    slices.forEach(function(slice, i) {
      var pct = slice.value / total;
      var angle = pct * 2 * Math.PI;
      var endAngle = startAngle + angle;
      var largeArc = angle > Math.PI ? 1 : 0;

      var x1 = cx + r * Math.cos(startAngle);
      var y1 = cy + r * Math.sin(startAngle);
      var x2 = cx + r * Math.cos(endAngle);
      var y2 = cy + r * Math.sin(endAngle);

      var pathD;
      if (pct >= 0.999) {
        // Full circle
        pathD = "M " + (cx - r) + " " + cy +
                " A " + r + " " + r + " 0 1 1 " + (cx + r) + " " + cy +
                " A " + r + " " + r + " 0 1 1 " + (cx - r) + " " + cy + " Z";
      } else {
        pathD = "M " + cx + " " + cy +
                " L " + x1 + " " + y1 +
                " A " + r + " " + r + " 0 " + largeArc + " 1 " + x2 + " " + y2 + " Z";
      }

      var path = document.createElementNS(ns, "path");
      path.setAttribute("d", pathD);
      path.setAttribute("fill", PIE_COLORS[i % PIE_COLORS.length]);
      path.setAttribute("stroke", "#0d1117");
      path.setAttribute("stroke-width", "2");
      if (slice.clickable) {
        path.style.cursor = "pointer";
        path.setAttribute("opacity", "0.92");
        (function(s) {
          path.addEventListener("mouseenter", function() { path.setAttribute("opacity", "1"); path.setAttribute("stroke-width", "3"); });
          path.addEventListener("mouseleave", function() { path.setAttribute("opacity", "0.92"); path.setAttribute("stroke-width", "2"); });
          path.addEventListener("click", function() { openMemDetail(s.memData); });
        })(slice);
      }
      svg.appendChild(path);

      startAngle = endAngle;
    });

    // Legend
    var legendY = 250;
    var legendX = 10;
    var colWidth = 160;
    slices.forEach(function(slice, i) {
      var col = i % 2;
      var row = Math.floor(i / 2);
      var lx = legendX + col * colWidth;
      var ly = legendY + row * 18;

      var rect = document.createElementNS(ns, "rect");
      rect.setAttribute("x", lx);
      rect.setAttribute("y", ly - 8);
      rect.setAttribute("width", 10);
      rect.setAttribute("height", 10);
      rect.setAttribute("rx", 2);
      rect.setAttribute("fill", PIE_COLORS[i % PIE_COLORS.length]);
      svg.appendChild(rect);

      var txt = document.createElementNS(ns, "text");
      txt.setAttribute("x", lx + 14);
      txt.setAttribute("y", ly);
      txt.setAttribute("fill", slice.clickable ? "#58a6ff" : "#8b949e");
      txt.setAttribute("font-size", "11");
      txt.setAttribute("font-family", "-apple-system, sans-serif");
      if (slice.clickable) {
        txt.style.cursor = "pointer";
        txt.style.textDecoration = "underline";
        (function(s) { txt.addEventListener("click", function() { openMemDetail(s.memData); }); })(slice);
      }
      var pctVal = (slice.value / total * 100).toFixed(1);
      var mbVal = slice.value.toFixed(0);
      txt.textContent = slice.label + " " + mbVal + "MB (" + pctVal + "%)";
      svg.appendChild(txt);
    });

    // Adjust viewBox based on legend rows
    var totalRows = Math.ceil(slices.length / 2);
    var newHeight = 260 + totalRows * 18;
    svg.setAttribute("viewBox", "0 0 320 " + newHeight);
  }

  // ── SVG Bar Chart ──
  function renderCpuBars(d) {
    var svg = document.getElementById("cpuBarChart");
    if (!svg) return;
    svg.innerHTML = "";

    var items = [];
    if (d.containers) {
      d.containers.forEach(function(c) {
        items.push({ label: c.name, cpu: c.cpu_perc, mem: c.mem_mb });
      });
    }

    if (items.length === 0) {
      var ns = "http://www.w3.org/2000/svg";
      var t = document.createElementNS(ns, "text");
      t.setAttribute("x", 200);
      t.setAttribute("y", 140);
      t.setAttribute("text-anchor", "middle");
      t.setAttribute("fill", "#6e7681");
      t.setAttribute("font-size", "14");
      t.setAttribute("font-family", "-apple-system, sans-serif");
      t.textContent = "No running containers";
      svg.appendChild(t);
      return;
    }

    // Sort by CPU descending, limit to 10
    items.sort(function(a, b) { return b.cpu - a.cpu; });
    if (items.length > 10) items = items.slice(0, 10);

    var ns = "http://www.w3.org/2000/svg";
    var barH = 22;
    var gap = 6;
    var leftPad = 120;
    var rightPad = 60;
    var chartW = 400 - leftPad - rightPad;
    var topPad = 10;

    var maxCpu = 0;
    items.forEach(function(it) { if (it.cpu > maxCpu) maxCpu = it.cpu; });
    if (maxCpu < 1) maxCpu = 1;

    var totalH = topPad + items.length * (barH + gap) + 10;
    svg.setAttribute("viewBox", "0 0 400 " + totalH);

    items.forEach(function(it, i) {
      var y = topPad + i * (barH + gap);
      var barW = (it.cpu / maxCpu) * chartW;
      if (barW < 2) barW = 2;

      // Label
      var label = document.createElementNS(ns, "text");
      label.setAttribute("x", leftPad - 8);
      label.setAttribute("y", y + barH / 2 + 4);
      label.setAttribute("text-anchor", "end");
      label.setAttribute("fill", "#e6edf3");
      label.setAttribute("font-size", "11");
      label.setAttribute("font-family", "-apple-system, sans-serif");
      var name = it.label.length > 16 ? it.label.substring(0, 15) + "\u2026" : it.label;
      label.textContent = name;
      svg.appendChild(label);

      // Background bar
      var bgBar = document.createElementNS(ns, "rect");
      bgBar.setAttribute("x", leftPad);
      bgBar.setAttribute("y", y);
      bgBar.setAttribute("width", chartW);
      bgBar.setAttribute("height", barH);
      bgBar.setAttribute("rx", 4);
      bgBar.setAttribute("fill", "#21262d");
      svg.appendChild(bgBar);

      // Filled bar
      var bar = document.createElementNS(ns, "rect");
      bar.setAttribute("x", leftPad);
      bar.setAttribute("y", y);
      bar.setAttribute("width", barW);
      bar.setAttribute("height", barH);
      bar.setAttribute("rx", 4);
      var color = it.cpu > 80 ? "#f85149" : it.cpu > 50 ? "#d29922" : "#00b4d8";
      bar.setAttribute("fill", color);
      bar.setAttribute("opacity", "0.85");
      svg.appendChild(bar);

      // Value
      var val = document.createElementNS(ns, "text");
      val.setAttribute("x", leftPad + chartW + 6);
      val.setAttribute("y", y + barH / 2 + 4);
      val.setAttribute("fill", "#8b949e");
      val.setAttribute("font-size", "11");
      val.setAttribute("font-family", "-apple-system, sans-serif");
      val.textContent = it.cpu.toFixed(1) + "%";
      svg.appendChild(val);
    });
  }

  // ── Services Table ──
  function formatMemDual(mb) {
