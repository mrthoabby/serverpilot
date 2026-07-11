/* Mappings tab */
"use strict";

    var wrap = document.getElementById("mappingsContent");
    try {
      var resp = await apiFetch("/api/mappings");
      var data = (resp && resp.data) ? resp.data : resp;
      mappings = {
        mapped: (data && data.mapped) || [],
        unmappedContainers: (data && data.unmappedContainers) || [],
        orphanedSites: (data && data.orphanedSites) || [],
        dashboardSites: (data && data.dashboardSites) || []
      };
      var total = mappings.mapped.length + mappings.unmappedContainers.length + mappings.orphanedSites.length + mappings.dashboardSites.length;
      setText(document.getElementById("mappingCount"), String(total));
      renderMappings(wrap);
      updateTabTimestamp("mappings");
      // Mappings load in parallel with containers — if containers finished
      // first they rendered with an empty mappings.mapped (race condition)
      // and showed "Associate" instead of "Asociado". Re-render now that we
      // know the real state. textContent / DOM-API rendering paths used by
      // renderContainers keep this XSS-safe.
      if (containers && containers.length) {
        var cWrap = document.getElementById("containersContent");
        if (cWrap) renderContainers(cWrap);
      }
    } catch(err) {
      wrap.innerHTML = "";
      var em = document.createElement("div");
      em.className = "empty-state";
      var p = document.createElement("p");
      setText(p, "Failed to load mappings: " + err.message);
      em.appendChild(p);
      wrap.appendChild(em);
    }
  }

  function renderMappings(wrap) {
    wrap.innerHTML = "";
    var allEmpty = (!mappings.mapped || !mappings.mapped.length) &&
                   (!mappings.unmappedContainers || !mappings.unmappedContainers.length) &&
                   (!mappings.orphanedSites || !mappings.orphanedSites.length) &&
                   (!mappings.dashboardSites || !mappings.dashboardSites.length);
    if (allEmpty) {
      var em = document.createElement("div");
      em.className = "empty-state";
      var p = document.createElement("p");
      setText(p, "No mappings found");
      em.appendChild(p);
      wrap.appendChild(em);
      return;
    }

    if (mappings.dashboardSites && mappings.dashboardSites.length) {
      var dashCard = document.createElement("div");
      dashCard.className = "card";
      dashCard.style.marginBottom = "1rem";
      var dashHdr = document.createElement("div");
      dashHdr.className = "card-header";
      var dashTitle = document.createElement("h2");
      setText(dashTitle, "ServerPilot Dashboard");
      dashHdr.appendChild(dashTitle);
      dashCard.appendChild(dashHdr);
      var dashBody = document.createElement("div");
      dashBody.style.padding = "1rem";
      var dashNote = document.createElement("p");
      dashNote.style.color = "var(--text-muted)";
      dashNote.style.fontSize = "0.85rem";
      dashNote.style.marginBottom = "0.75rem";
      setText(dashNote, "These sites proxy to the ServerPilot web panel. They are not linked to a Docker container and are not orphaned.");
      dashBody.appendChild(dashNote);
      mappings.dashboardSites.forEach(function(s) {
        var row = document.createElement("div");
        row.style.display = "flex";
        row.style.alignItems = "center";
        row.style.gap = "0.5rem";
        row.style.marginBottom = "0.5rem";
        var dom = document.createElement("strong");
        setText(dom, s.domain || "Unknown");
        row.appendChild(dom);
        var badge = document.createElement("span");
        badge.className = "badge badge-info";
        setText(badge, "ServerPilot");
        row.appendChild(badge);
        if (s.proxy_pass) {
          var proxy = document.createElement("span");
          proxy.style.color = "var(--text-muted)";
          proxy.style.fontSize = "0.8rem";
          setText(proxy, s.proxy_pass);
          row.appendChild(proxy);
        }
        dashBody.appendChild(row);
      });
      dashCard.appendChild(dashBody);
      wrap.appendChild(dashCard);
    }

    var tw = document.createElement("div");
    tw.className = "table-wrap";
    var table = document.createElement("table");

    var thead = document.createElement("thead");
    var trh = document.createElement("tr");
    ["Container", "Port", "", "Domain", "SSL", "Status"].forEach(function(h) {
      var th = document.createElement("th");
      setText(th, h);
      trh.appendChild(th);
    });
    thead.appendChild(trh);
    table.appendChild(thead);

    var tbody = document.createElement("tbody");

    // Mapped
    if (mappings.mapped) {
      mappings.mapped.forEach(function(m) {
        var tr = document.createElement("tr");

        var td1 = document.createElement("td");
        var s1 = document.createElement("strong");
        setText(s1, m.container_name);
        td1.appendChild(s1);
        tr.appendChild(td1);

        var td2 = document.createElement("td");
        var ptag = document.createElement("span");
        ptag.className = "port-tag";
        setText(ptag, String(m.container_port));
        td2.appendChild(ptag);
        tr.appendChild(td2);

        var td3 = document.createElement("td");
        td3.style.textAlign = "center";
        var arrow = document.createElement("span");
        arrow.className = "mapping-arrow";
        setText(arrow, "\u2194");
        td3.appendChild(arrow);
        tr.appendChild(td3);

        var td4 = document.createElement("td");
        var domS = document.createElement("strong");
        setText(domS, m.nginx_domain);
        td4.appendChild(domS);
        tr.appendChild(td4);

        var td5 = document.createElement("td");
        var sslS = document.createElement("span");
        sslS.className = "ssl-icon " + (m.ssl_enabled ? "ssl-enabled" : "ssl-disabled");
        setText(sslS, m.ssl_enabled ? "\uD83D\uDD12" : "\uD83D\uDD13");
        td5.appendChild(sslS);
        tr.appendChild(td5);

        var td6 = document.createElement("td");
        var okBadge = document.createElement("span");
        okBadge.className = "badge badge-running";
        setText(okBadge, "Linked");
        td6.appendChild(okBadge);
        tr.appendChild(td6);

        tbody.appendChild(tr);
      });
    }

    // Unmapped containers
    if (mappings.unmappedContainers) {
      mappings.unmappedContainers.forEach(function(c) {
        var tr = document.createElement("tr");

        var td1 = document.createElement("td");
        var s1 = document.createElement("strong");
        setText(s1, c.name || c.containerName || "Unknown");
        td1.appendChild(s1);
        tr.appendChild(td1);

        var td2 = document.createElement("td");
        setText(td2, "-");
        td2.style.color = "var(--text-muted)";
        tr.appendChild(td2);

        var td3 = document.createElement("td");
        td3.style.textAlign = "center";
        var arrow = document.createElement("span");
        arrow.style.color = "var(--text-muted)";
        setText(arrow, "\u2194");
        td3.appendChild(arrow);
        tr.appendChild(td3);

        var td4 = document.createElement("td");
        setText(td4, "-");
        td4.style.color = "var(--text-muted)";
        tr.appendChild(td4);

        var td5 = document.createElement("td");
        setText(td5, "-");
        td5.style.color = "var(--text-muted)";
        tr.appendChild(td5);

        var td6 = document.createElement("td");
        var noSite = document.createElement("span");
        noSite.className = "badge badge-info";
        setText(noSite, "No site");
        td6.appendChild(noSite);
        tr.appendChild(td6);

        tbody.appendChild(tr);
      });
    }

    // Orphaned sites
    if (mappings.orphanedSites) {
      mappings.orphanedSites.forEach(function(s) {
        var tr = document.createElement("tr");

        var td1 = document.createElement("td");
        setText(td1, "-");
        td1.style.color = "var(--text-muted)";
        tr.appendChild(td1);

        var td2 = document.createElement("td");
        setText(td2, "-");
        td2.style.color = "var(--text-muted)";
        tr.appendChild(td2);

        var td3 = document.createElement("td");
        td3.style.textAlign = "center";
        var arrow = document.createElement("span");
        arrow.style.color = "var(--red)";
        setText(arrow, "\u2194");
        td3.appendChild(arrow);
        tr.appendChild(td3);

        var td4 = document.createElement("td");
        var domS = document.createElement("strong");
        setText(domS, s.domain || s.nginxDomain || "Unknown");
        td4.appendChild(domS);
        tr.appendChild(td4);

        var td5 = document.createElement("td");
        var sslS = document.createElement("span");
        sslS.className = "ssl-icon " + (s.ssl_enabled ? "ssl-enabled" : "ssl-disabled");
        setText(sslS, s.ssl_enabled ? "\uD83D\uDD12" : "\uD83D\uDD13");
        td5.appendChild(sslS);
        tr.appendChild(td5);

        var td6 = document.createElement("td");
        var wBadge = document.createElement("span");
        wBadge.className = "badge badge-warning";
        setText(wBadge, "Orphaned");
        td6.appendChild(wBadge);
        tr.appendChild(td6);

        tbody.appendChild(tr);
      });
    }

    table.appendChild(tbody);
    tw.appendChild(table);
    wrap.appendChild(tw);
  }

  // ── Container Logs Modal ──
  var containerLogsModal = document.getElementById("containerLogsModal");
