/* Container stats table */
"use strict";

    var wrap = document.getElementById("containerStatsContent");
    if (!wrap) return;
    wrap.innerHTML = "";

    var cts = d.containers || [];
    if (!cts.length) {
      var em = document.createElement("div");
      em.className = "empty-state";
      var p = document.createElement("p");
      setText(p, "No running containers");
      em.appendChild(p);
      wrap.appendChild(em);
      return;
    }

    var tw = document.createElement("div");
    tw.className = "table-wrap";
    var table = document.createElement("table");

    var thead = document.createElement("thead");
    var trh = document.createElement("tr");
    ["Container", "CPU %", "Memory", "Mem %", "Network I/O", "Block I/O", "PIDs"].forEach(function(h) {
      var th = document.createElement("th");
      setText(th, h);
      trh.appendChild(th);
    });
    thead.appendChild(trh);
    table.appendChild(thead);

    var tbody = document.createElement("tbody");
    cts.forEach(function(c) {
      var tr = document.createElement("tr");

      var tdName = document.createElement("td");
      var nameStr = document.createElement("strong");
      setText(nameStr, c.name);
      tdName.appendChild(nameStr);
      tr.appendChild(tdName);

      var tdCpu = document.createElement("td");
      var cpuBadge = document.createElement("span");
      var cpuClass = c.cpu_perc > 80 ? "badge-stopped" : c.cpu_perc > 50 ? "badge-warning" : "badge-running";
      cpuBadge.className = "badge " + cpuClass;
      setText(cpuBadge, c.cpu_perc.toFixed(1) + "%");
      tdCpu.appendChild(cpuBadge);
      tr.appendChild(tdCpu);

      var tdMem = document.createElement("td");
      setText(tdMem, formatMemDual(c.mem_mb));
      tdMem.style.fontFamily = '"SF Mono","Fira Code",monospace';
      tdMem.style.fontSize = "0.8125rem";
      tr.appendChild(tdMem);

      var tdMemPct = document.createElement("td");
      var memBadge = document.createElement("span");
      var memClass = c.mem_perc > 80 ? "badge-stopped" : c.mem_perc > 50 ? "badge-warning" : "badge-running";
      memBadge.className = "badge " + memClass;
      setText(memBadge, c.mem_perc.toFixed(1) + "%");
      tdMemPct.appendChild(memBadge);
      tr.appendChild(tdMemPct);

      var tdNet = document.createElement("td");
      tdNet.style.fontSize = "0.8125rem";
      tdNet.style.color = "var(--text-secondary)";
      setText(tdNet, c.net_io || "-");
      tr.appendChild(tdNet);

      var tdBlock = document.createElement("td");
      tdBlock.style.fontSize = "0.8125rem";
      tdBlock.style.color = "var(--text-secondary)";
      setText(tdBlock, c.block_io || "-");
      tr.appendChild(tdBlock);

      var tdPids = document.createElement("td");
      setText(tdPids, String(c.pids));
      tr.appendChild(tdPids);

      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    tw.appendChild(table);
    wrap.appendChild(tw);
  }

  // ── Initial: try loading dashboard (if session cookie exists) ──
  (async function init() {
