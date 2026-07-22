/* Mappings tab */
"use strict";

  function mappingConfigName(m) {
    if (m && m.config_name) return m.config_name;
    var path = (m && m.nginx_config_path) || "";
    if (path) {
      var idx = path.lastIndexOf("/");
      return idx >= 0 ? path.slice(idx + 1) : path;
    }
    return (m && m.nginx_domain) || "";
  }

  function siteConfigName(s) {
    var path = (s && s.config_path) || "";
    if (path) {
      var idx = path.lastIndexOf("/");
      return idx >= 0 ? path.slice(idx + 1) : path;
    }
    return (s && s.domain) || "";
  }

  function mappingPortLabel(m) {
    if (!m) return "-";
    var host = m.host_port || "";
    var container = m.container_port || "";
    if (host && container && host !== container) return host + " \u2192 " + container;
    if (host) return host;
    if (container) return container;
    return "-";
  }

  function refreshMappingViews() {
    return Promise.all([
      loadMappings(),
      typeof loadContainers === "function" ? loadContainers({ force: true }) : Promise.resolve(),
      typeof loadSites === "function" ? loadSites({ force: true }) : Promise.resolve()
    ]);
  }

  function findContainerByName(name) {
    if (!name || !containers || !containers.length) return null;
    return containers.find(function(c) { return c.name === name; }) || null;
  }

  function detectHostPortForMapping(containerName, containerPort) {
    var c = findContainerByName(containerName);
    if (!c || !c.ports) return "";
    var match = c.ports.find(function(p) {
      return String(p.container_port || "") === String(containerPort || "");
    });
    return match && match.host_port ? String(match.host_port) : "";
  }

  function populateMappingContainerSelect(selectedName) {
    var select = document.getElementById("mappingEditContainerSelect");
    if (!select) return;
    select.innerHTML = "";
    var manual = document.createElement("option");
    manual.value = "";
    setText(manual, "Type name manually");
    select.appendChild(manual);
    (containers || []).forEach(function(c) {
      var opt = document.createElement("option");
      opt.value = c.name || "";
      setText(opt, c.name || c.id || "container");
      select.appendChild(opt);
    });
    if (selectedName) {
      var found = false;
      for (var i = 0; i < select.options.length; i++) {
        if (select.options[i].value === selectedName) {
          select.selectedIndex = i;
          found = true;
          break;
        }
      }
      if (!found && selectedName) {
        var extra = document.createElement("option");
        extra.value = selectedName;
        setText(extra, selectedName + " (not running)");
        select.appendChild(extra);
        select.value = selectedName;
      }
    }
  }

  function openMappingEditModal(m) {
    var modal = document.getElementById("mappingEditModal");
    if (!modal) return;
    var domain = (m && m.nginx_domain) || "";
    var configName = mappingConfigName(m);
    setText(document.getElementById("mappingEditSub"), "Edit mapping for " + (domain || configName));
    document.getElementById("mappingEditSiteId").value = (m && m.site_id) || "";
    document.getElementById("mappingEditConfigName").value = configName;
    document.getElementById("mappingEditDomain").value = domain;
    document.getElementById("mappingEditContainerName").value = (m && m.container_name) || "";
    document.getElementById("mappingEditHostPort").value = (m && m.host_port) || "";
    document.getElementById("mappingEditContainerPort").value = (m && m.container_port) || "3000";
    populateMappingContainerSelect((m && m.container_name) || "");
    modal.classList.add("show");
  }

  function appendMappingActions(td, m, siteDomain) {
    var domain = siteDomain || (m && m.nginx_domain) || "";
    var configName = mappingConfigName(m);
    if (!domain && !configName) return;

    var editBtn = document.createElement("button");
    editBtn.className = "btn btn-sm btn-primary";
    editBtn.style.marginRight = "0.35rem";
    setText(editBtn, "Edit");
    editBtn.addEventListener("click", function() { openMappingEditModal(m); });
    td.appendChild(editBtn);

    var configBtn = document.createElement("button");
    configBtn.className = "btn btn-sm btn-outline";
    configBtn.style.marginRight = "0.35rem";
    setText(configBtn, "Nginx");
    configBtn.title = "Edit nginx config";
    configBtn.addEventListener("click", function() {
      if (typeof openConfigEditor === "function") {
        openConfigEditor(configName || domain, domain || configName);
      }
    });
    td.appendChild(configBtn);

    var domainBtn = document.createElement("button");
    domainBtn.className = "btn btn-sm btn-outline";
    domainBtn.style.marginRight = "0.35rem";
    setText(domainBtn, "Domain");
    domainBtn.addEventListener("click", function() {
      var nd = window.prompt("New domain for " + domain, domain);
      if (!nd) return;
      runStreamedOperation("/api/sites/update-domain", {
        current_domain: domain,
        config_name: configName,
        new_domain: nd.trim().toLowerCase(),
        enable_ssl: true,
        remove_old_cert: true
      }, "Updating Domain", domain + " -> " + nd).then(function() {
        return refreshMappingViews();
      });
    });
    td.appendChild(domainBtn);

    if (m && m.container_name) {
      var syncBtn = document.createElement("button");
      syncBtn.className = "btn btn-sm btn-warning";
      syncBtn.style.marginRight = "0.35rem";
      setText(syncBtn, "Sync port");
      syncBtn.title = "Repoint nginx to this container's current host port";
      syncBtn.addEventListener("click", function() {
        confirmAction(
          "Sync port",
          "Update nginx for \"" + domain + "\" to match container \"" + m.container_name + "\"?",
          async function() {
            try {
              await apiFetch("/api/sites/sync-port", {
                method: "POST",
                body: {
                  site_id: m.site_id || "",
                  container_id: m.container_id || "",
                  container_name: m.container_name || "",
                  container_port: String(m.container_port || "3000")
                }
              });
              showToast("Nginx synced to container port", "success");
              await refreshMappingViews();
            } catch (err) {
              showToast("Sync failed: " + err.message, "error");
            }
          }
        );
      });
      td.appendChild(syncBtn);
    }

    var deleteBtn = document.createElement("button");
    deleteBtn.className = "btn btn-sm btn-danger";
    setText(deleteBtn, "Delete");
    deleteBtn.title = "Remove nginx site, SSL cert, and registry entry";
    deleteBtn.addEventListener("click", function() {
      confirmAction(
        "Delete site",
        "Remove " + (domain || configName) + "? This deletes the nginx config and unlinks the mapping.",
        async function() {
          try {
            await runStreamedOperation(
              "/api/sites/delete",
              { domain: domain || configName, config_name: configName || domain },
              "Deleting Site",
              domain || configName
            );
            showToast("Site deleted", "success");
            await refreshMappingViews();
          } catch (err) {
            showToast("Delete failed: " + ((err && err.message) || "error"), "error");
          }
        }
      );
    });
    td.appendChild(deleteBtn);
  }

  async function loadMappings() {
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
      if (containers && containers.length) {
        var cWrap = document.getElementById("containersContent");
        if (cWrap) {
          if (typeof window.renderContainers === "function") {
            window.renderContainers(cWrap);
          } else if (typeof window.loadContainers === "function") {
            window.loadContainers();
          }
        }
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

    var info = document.createElement("p");
    info.style.color = "var(--text-muted)";
    info.style.fontSize = "0.85rem";
    info.style.margin = "0 0 1rem";
    setText(info, "Mappings combine the site registry and nginx configs with live docker ps. A row can show a container name even when Containers is empty (stopped container or docker unavailable). Orphan means the link is stale.");
    wrap.appendChild(info);

    var tw = document.createElement("div");
    tw.className = "table-wrap";
    var table = document.createElement("table");

    var thead = document.createElement("thead");
    var trh = document.createElement("tr");
    ["Container", "Host \u2192 container", "", "Domain", "SSL", "Status", "Actions"].forEach(function(h) {
      var th = document.createElement("th");
      setText(th, h);
      trh.appendChild(th);
    });
    thead.appendChild(trh);
    table.appendChild(thead);

    var tbody = document.createElement("tbody");

    if (mappings.mapped) {
      mappings.mapped.forEach(function(m) {
        var tr = document.createElement("tr");

        var td1 = document.createElement("td");
        var s1 = document.createElement("strong");
        setText(s1, m.container_name || "(no container)");
        td1.appendChild(s1);
        tr.appendChild(td1);

        var td2 = document.createElement("td");
        var ptag = document.createElement("span");
        ptag.className = "port-tag";
        setText(ptag, mappingPortLabel(m));
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
        var statusBadge = document.createElement("span");
        if (m.orphaned) {
          statusBadge.className = "badge badge-warning";
          setText(statusBadge, "Orphan");
        } else {
          statusBadge.className = "badge badge-running";
          setText(statusBadge, "Linked");
        }
        td6.appendChild(statusBadge);
        tr.appendChild(td6);

        var tdAct = document.createElement("td");
        appendMappingActions(tdAct, m, m.nginx_domain);
        tr.appendChild(tdAct);

        tbody.appendChild(tr);
      });
    }

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

        var tdAct = document.createElement("td");
        var assocBtn = document.createElement("button");
        assocBtn.className = "btn btn-sm btn-primary";
        setText(assocBtn, "Associate");
        assocBtn.addEventListener("click", function() {
          if (typeof window.openAssociateModal === "function") {
            window.openAssociateModal(c, "nextjs");
          }
        });
        tdAct.appendChild(assocBtn);
        tr.appendChild(tdAct);

        tbody.appendChild(tr);
      });
    }

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

        var tdAct = document.createElement("td");
        appendMappingActions(tdAct, { nginx_domain: s.domain, config_name: siteConfigName(s), orphaned: true }, s.domain);
        tr.appendChild(tdAct);

        tbody.appendChild(tr);
      });
    }

    table.appendChild(tbody);
    tw.appendChild(table);
    wrap.appendChild(tw);
  }

  (function bindMappingEditModal() {
    var modal = document.getElementById("mappingEditModal");
    var form = document.getElementById("mappingEditForm");
    if (!modal || !form) return;

    var select = document.getElementById("mappingEditContainerSelect");
    if (select) {
      select.addEventListener("change", function() {
        if (select.value) {
          document.getElementById("mappingEditContainerName").value = select.value;
          var detected = detectHostPortForMapping(select.value, document.getElementById("mappingEditContainerPort").value);
          if (detected) document.getElementById("mappingEditHostPort").value = detected;
        }
      });
    }

    onEl("mappingEditCancelBtn", "click", function() { modal.classList.remove("show"); });
    modal.addEventListener("click", function(e) {
      if (e.target === modal) modal.classList.remove("show");
    });

    onEl("mappingEditDetectPortBtn", "click", function() {
      var containerName = document.getElementById("mappingEditContainerName").value.trim();
      var containerPort = document.getElementById("mappingEditContainerPort").value.trim() || "3000";
      var detected = detectHostPortForMapping(containerName, containerPort);
      if (detected) {
        document.getElementById("mappingEditHostPort").value = detected;
        showToast("Host port set to " + detected, "success");
        return;
      }
      showToast("No published host port found for that container", "error");
    });

    form.addEventListener("submit", async function(e) {
      e.preventDefault();
      var saveBtn = document.getElementById("mappingEditSaveBtn");
      if (saveBtn) saveBtn.disabled = true;
      try {
        var body = {
          site_id: document.getElementById("mappingEditSiteId").value.trim(),
          config_name: document.getElementById("mappingEditConfigName").value.trim(),
          domain: document.getElementById("mappingEditDomain").value.trim(),
          container_name: document.getElementById("mappingEditContainerName").value.trim(),
          host_port: parseInt(document.getElementById("mappingEditHostPort").value, 10),
          container_port: parseInt(document.getElementById("mappingEditContainerPort").value, 10) || 3000
        };
        var selected = select && select.value ? findContainerByName(select.value) : null;
        if (selected && selected.id) body.container_id = selected.id;
        await apiFetch("/api/sites/update-mapping", { method: "POST", body: body });
        modal.classList.remove("show");
        showToast("Mapping updated", "success");
        await refreshMappingViews();
      } catch (err) {
        showToast("Update failed: " + ((err && err.message) || "error"), "error");
      } finally {
        if (saveBtn) saveBtn.disabled = false;
      }
    });
  })();

  // ── Container Logs Modal ──
  var containerLogsModal = document.getElementById("containerLogsModal");
