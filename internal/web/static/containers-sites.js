/* Container-centric multi-site management (loaded after main dashboard script). */
(function() {
  var expandedContainers = {};
  var composeProjects = [];
  var _assocPendingContainer = null;

  function siteProxyPort(site) {
    var proxy = (site && site.proxy_pass) || "";
    var m = proxy.match(/:(\d+)(?:\/|$)/);
    return m ? m[1] : "";
  }

  function mappingForSite(site) {
    var port = siteProxyPort(site);
    for (var i = 0; i < (mappings.mapped || []).length; i++) {
      var m = mappings.mapped[i];
      if (site.domain && m.nginx_domain === site.domain) return m;
      if (port && String(m.host_port || m.container_port) === String(port)) return m;
    }
    return null;
  }

  function sitesByContainer(container) {
    var out = [];
    var id = container.id || "";
    var name = container.name || "";
    (mappings.mapped || []).forEach(function(m) {
      if ((id && m.container_id === id) || (name && m.container_name === name)) {
        var site = null;
        for (var i = 0; i < sites.length; i++) {
          if (sites[i].domain === m.nginx_domain) { site = sites[i]; break; }
        }
        out.push({ mapping: m, site: site });
      }
    });
    return out;
  }

  function hasPublishedTCPPort(container) {
    if (!container.ports) return false;
    for (var i = 0; i < container.ports.length; i++) {
      var p = container.ports[i];
      if (p.host_port && (p.protocol || "tcp") === "tcp") return true;
    }
    return false;
  }

  function publishedTCPPorts(container) {
    var out = [];
    (container.ports || []).forEach(function(p) {
      if (p.host_port && (p.protocol || "tcp") === "tcp") {
        out.push(p);
      }
    });
    return out;
  }

  function exposedOnlyTCPPorts(container) {
    var out = [];
    var seen = {};
    function addMapping(p) {
      if (!p || p.host_port || !p.container_port || (p.protocol || "tcp") !== "tcp") return;
      var key = p.container_port + "/" + (p.protocol || "tcp");
      if (seen[key]) return;
      seen[key] = true;
      out.push(p);
    }
    (container.ports || []).forEach(addMapping);
    (container.exposed_ports || []).forEach(addMapping);
    return out;
  }

  function refreshContainerView() {
    return window.loadContainers();
  }

  function associateTemplateForContainer(container) {
    var labels = (typeof containerLabels !== "undefined" ? containerLabels : {}) || {};
    var label = labels[container.name] || "";
    if (label === "api" || label === "nestjs" || label === "nextjs" || label === "frontend" || label === "minio") {
      return label;
    }
    return "api";
  }

  function bodySizeFromForm() {
    var sel = document.getElementById("optBodySize");
    if (!sel) return "";
    if (sel.value === "__custom__") {
      var custom = document.getElementById("optBodySizeCustom");
      return custom ? String(custom.value || "").trim() : "";
    }
    return sel.value || "";
  }

  function initBodySizeSelect() {
    var sel = document.getElementById("optBodySize");
    var custom = document.getElementById("optBodySizeCustom");
    if (!sel || sel.dataset.bound === "1") return;
    sel.dataset.bound = "1";
    sel.addEventListener("change", function() {
      if (!custom) return;
      var show = sel.value === "__custom__";
      custom.style.display = show ? "block" : "none";
      if (show) custom.focus();
    });
  }

  function siteDomainFromItem(item) {
    if (!item) return "";
    return (item.site && item.site.domain) || (item.mapping && item.mapping.nginx_domain) || "";
  }

  function appendMetaBadge(row, text, className) {
    var badge = document.createElement("span");
    badge.className = className || "badge badge-info";
    badge.style.marginLeft = "8px";
    setText(badge, text);
    row.appendChild(badge);
  }

  function renderSiteSummaryRow(row, site, mapping) {
    var domain = siteDomainFromItem({ site: site, mapping: mapping });
    var titleWrap = document.createElement("div");
    titleWrap.style.display = "flex";
    titleWrap.style.flexWrap = "wrap";
    titleWrap.style.alignItems = "center";
    titleWrap.style.gap = "6px";

    if (domain) {
      var link = document.createElement("a");
      link.href = (site && site.ssl_enabled ? "https://" : "http://") + domain;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.style.fontWeight = "600";
      setText(link, domain);
      titleWrap.appendChild(link);
    } else {
      var title = document.createElement("strong");
      setText(title, "?");
      titleWrap.appendChild(title);
    }

    if (site) {
      appendMetaBadge(titleWrap, site.enabled ? "Enabled" : "Disabled", "badge " + (site.enabled ? "badge-running" : "badge-stopped"));
      if (site.ssl_enabled) appendMetaBadge(titleWrap, "SSL", "badge badge-info");
      if (site.www_enabled) appendMetaBadge(titleWrap, "WWW", "badge badge-info");
    }
    if (mapping && mapping.orphaned) appendMetaBadge(titleWrap, "Orphan", "badge badge-warning");
    if (mapping && mapping.redirect_active) appendMetaBadge(titleWrap, "Redirect active", "badge badge-running");

    row.appendChild(titleWrap);

    var meta = document.createElement("div");
    meta.style.marginTop = "4px";
    meta.style.color = "var(--text-muted)";
    meta.style.fontSize = "0.75rem";
    var parts = [];
    if (mapping && (mapping.host_port || mapping.container_port)) {
      parts.push("port " + (mapping.host_port || "?") + " → container " + (mapping.container_port || "?"));
    }
    if (site && site.proxy_pass) parts.push("proxy " + site.proxy_pass);
    if (site && site.redirect_target && !site.proxy_pass) parts.push("redirect → " + site.redirect_target);
    setText(meta, parts.join(" · ") || "No routing metadata");
    row.appendChild(meta);
  }

  function appendSiteActions(tdAct, site, configName, mapping) {
    if (!site) return;
    if (site.redirect_target && !site.proxy_pass) return;

    var toggleBtn = document.createElement("button");
    toggleBtn.className = "btn btn-sm " + (site.enabled ? "btn-warning" : "btn-success");
    setText(toggleBtn, site.enabled ? "Disable" : "Enable");
    toggleBtn.addEventListener("click", function() {
      var action = site.enabled ? "disable" : "enable";
      confirmAction("Confirm " + action, "Are you sure you want to " + action + " " + site.domain + "?", async function() {
        try {
          await apiFetch("/api/sites/" + action, { method: "POST", body: { domain: site.domain } });
          showToast("Site " + action + "d", "success");
          await refreshContainerView();
        } catch (err) { showToast("Failed: " + err.message, "error"); }
      });
    });
    tdAct.appendChild(toggleBtn);

    if (!site.ssl_enabled) {
      var sslBtn = document.createElement("button");
      sslBtn.className = "btn btn-sm btn-success";
      setText(sslBtn, "Enable SSL");
      sslBtn.addEventListener("click", function() {
        runStreamedOperation("/api/ssl/enable", { domain: site.domain }, "Enabling SSL", site.domain);
      });
      tdAct.appendChild(sslBtn);
    } else {
      var sslOff = document.createElement("button");
      sslOff.className = "btn btn-sm btn-danger";
      setText(sslOff, "Disable SSL");
      sslOff.addEventListener("click", function() {
        runStreamedOperation("/api/ssl/disable", { domain: site.domain }, "Disabling SSL", site.domain);
      });
      tdAct.appendChild(sslOff);
    }

    if (!site.www_enabled && site.domain && site.domain.indexOf("www.") !== 0) {
      var wwwBtn = document.createElement("button");
      wwwBtn.className = "btn btn-sm btn-outline";
      setText(wwwBtn, "Enable WWW");
      wwwBtn.addEventListener("click", function() {
        runStreamedOperation("/api/sites/enable-www", { domain: site.domain, config_name: configName }, "Enabling WWW", site.domain);
      });
      tdAct.appendChild(wwwBtn);
    }

    if (mapping && mapping.redirect_active) {
      var deactRed = document.createElement("button");
      deactRed.className = "btn btn-sm btn-warning";
      setText(deactRed, "Deactivate Redirect");
      deactRed.addEventListener("click", function() {
        confirmAction("Deactivate Redirect", "Restore the original site config for " + site.domain + "?", async function() {
          try {
            await apiFetch("/api/sites/redirect/deactivate", { method: "POST", body: { config_name: configName } });
            showToast("Redirect deactivated", "success");
            await refreshContainerView();
          } catch (err) { showToast("Failed: " + err.message, "error"); }
        });
      });
      tdAct.appendChild(deactRed);
    } else if (!site.redirect_target) {
      var actRed = document.createElement("button");
      actRed.className = "btn btn-sm btn-outline";
      setText(actRed, "Activate Redirect");
      actRed.addEventListener("click", function() {
        var target = window.prompt("Redirect " + site.domain + " to URL or domain:", "https://");
        if (!target) return;
        apiFetch("/api/sites/redirect/activate", {
          method: "POST",
          body: { config_name: configName, target: target, code: 301 }
        }).then(function() {
          showToast("Redirect activated", "success");
          return refreshContainerView();
        }).catch(function(err) { showToast("Failed: " + err.message, "error"); });
      });
      tdAct.appendChild(actRed);
    }

    var domainBtn = document.createElement("button");
    domainBtn.className = "btn btn-sm btn-outline";
    setText(domainBtn, "Change Domain");
    domainBtn.addEventListener("click", function() {
      var nd = window.prompt("New domain for " + site.domain, "");
      if (!nd) return;
      runStreamedOperation("/api/sites/update-domain", {
        current_domain: site.domain,
        config_name: configName,
        new_domain: nd.trim().toLowerCase(),
        enable_ssl: true,
        remove_old_cert: true
      }, "Updating Domain", site.domain + " -> " + nd);
    });
    tdAct.appendChild(domainBtn);

    var editBtn = document.createElement("button");
    editBtn.className = "btn btn-sm btn-outline";
    setText(editBtn, "Edit Config");
    editBtn.addEventListener("click", function() { openConfigEditor(configName, site.domain); });
    tdAct.appendChild(editBtn);

    var deleteBtn = document.createElement("button");
    deleteBtn.className = "btn btn-sm btn-danger";
    setText(deleteBtn, "Delete");
    deleteBtn.addEventListener("click", function() {
      confirmAction("Delete Site", "Delete " + site.domain + " completely?", function() {
        runStreamedOperation("/api/sites/delete", { domain: site.domain, config_name: configName }, "Deleting Site", site.domain);
      });
    });
    tdAct.appendChild(deleteBtn);
  }

  function renderContainerSitesPanel(container, tbody) {
    var tr = document.createElement("tr");
    tr.className = "container-sites-panel-row";
    var td = document.createElement("td");
    td.colSpan = 6;
    var panel = document.createElement("div");
    panel.className = "container-sites-panel";

    var linked = sitesByContainer(container);
    var h = document.createElement("h4");
    setText(h, "Sites (" + linked.length + ")");
    panel.appendChild(h);

    if (linked.length) {
      linked.forEach(function(item) {
        var row = document.createElement("div");
        row.className = "container-site-row";
        var site = item.site;
        var m = item.mapping;
        renderSiteSummaryRow(row, site, m);
        var actions = document.createElement("div");
        actions.className = "actions-cell";
        actions.style.marginTop = "6px";
        if (site) {
          var configName = site.config_path ? site.config_path.split("/").pop() : site.domain;
          appendSiteActions(actions, site, configName, m);
        }
        row.appendChild(actions);
        panel.appendChild(row);
      });
    } else {
      var empty = document.createElement("p");
      empty.style.color = "var(--text-muted)";
      empty.style.fontSize = "0.8rem";
      setText(empty, "No sites linked to this container yet.");
      panel.appendChild(empty);
    }

    var portActions = document.createElement("div");
    portActions.style.marginTop = "12px";
    if (hasPublishedTCPPort(container)) {
      var addBtn = document.createElement("button");
      addBtn.className = "btn btn-sm btn-primary";
      setText(addBtn, "+ Add Site");
      var templateType = associateTemplateForContainer(container);
      addBtn.addEventListener("click", function() { window.openAssociateModal(container, templateType); });
      portActions.appendChild(addBtn);
    } else {
      var warn = document.createElement("div");
      warn.className = "port-resolve-banner";
      setText(warn, "This container has no TCP port published on the host. Nginx cannot reach it until a port is published.");
      portActions.appendChild(warn);
      var exposed = exposedOnlyTCPPorts(container);
      if (exposed.length) {
        exposed.forEach(function(p) {
          var resolveBtn = document.createElement("button");
          resolveBtn.className = "btn btn-sm btn-warning";
          resolveBtn.style.marginRight = "6px";
          setText(resolveBtn, "Resolve port " + p.container_port);
          resolveBtn.addEventListener("click", function() { openPortResolveModal(container, p); });
          portActions.appendChild(resolveBtn);
        });
      }
    }
    panel.appendChild(portActions);
    td.appendChild(panel);
    tr.appendChild(td);
    tbody.appendChild(tr);
  }

  function renderGlobalSections(wrap) {
    var redirects = (mappings.standalone_redirects || []).length ? mappings.standalone_redirects : sites.filter(function(s) { return s.redirect_target && !s.proxy_pass; });
    if (redirects.length || document.getElementById("createRedirectBtn")) {
      var card = document.createElement("div");
      card.className = "card";
      card.style.marginTop = "1rem";
      var hdr = document.createElement("div");
      hdr.className = "card-header";
      hdr.style.display = "flex";
      hdr.style.justifyContent = "space-between";
      var h2 = document.createElement("h2");
      setText(h2, "Standalone Redirects");
      hdr.appendChild(h2);
      card.appendChild(hdr);
      var body = document.createElement("div");
      body.style.padding = "1rem";
      if (!redirects.length) {
        var p = document.createElement("p");
        p.style.color = "var(--text-muted)";
        setText(p, "No standalone redirects.");
        body.appendChild(p);
      } else {
        redirects.forEach(function(s) {
          var row = document.createElement("div");
          row.style.marginBottom = "8px";
          setText(row, (s.domain || "?") + " → " + (s.redirect_target || "?"));
          body.appendChild(row);
        });
      }
      card.appendChild(body);
      wrap.appendChild(card);
    }

    var unassigned = mappings.unassigned_sites || [];
    var orphans = mappings.orphanedSites || [];
    if (mappings.dashboardSites && mappings.dashboardSites.length) {
      var dashCard = document.createElement("div");
      dashCard.className = "card";
      dashCard.style.marginTop = "1rem";
      var dashHdr = document.createElement("div");
      dashHdr.className = "card-header";
      var dashTitle = document.createElement("h2");
      setText(dashTitle, "ServerPilot Dashboard");
      dashHdr.appendChild(dashTitle);
      dashCard.appendChild(dashHdr);
      var dashBody = document.createElement("div");
      dashBody.style.padding = "1rem";
      mappings.dashboardSites.forEach(function(s) {
        var row = document.createElement("div");
        row.style.marginBottom = "8px";
        setText(row, (s.domain || "?") + " — ServerPilot panel (no container)");
        dashBody.appendChild(row);
      });
      dashCard.appendChild(dashBody);
      wrap.appendChild(dashCard);
    }
    if (unassigned.length || orphans.length) {
      var card2 = document.createElement("div");
      card2.className = "card";
      card2.style.marginTop = "1rem";
      var h2b = document.createElement("h2");
      setText(h2b, "Unassigned / Orphan Sites");
      card2.appendChild(h2b);
      var body2 = document.createElement("div");
      body2.style.padding = "1rem";
      orphans.concat(unassigned).forEach(function(s) {
        var row = document.createElement("div");
        row.style.marginBottom = "8px";
        setText(row, (s.domain || "?") + " — " + (s.proxy_pass || s.redirect_target || "no target"));
        body2.appendChild(row);
      });
      card2.appendChild(body2);
      wrap.appendChild(card2);
    }
  }

  window.openPortResolveModal = async function(container, portMapping) {
    try {
      var resp = await apiFetch("/api/containers/port-analysis?container_id=" + encodeURIComponent(container.id));
      var data = (resp && resp.data) || {};
      var msg = "";
      if (data.can_auto_publish) {
        msg = "ServerPilot can recreate this container with port 127.0.0.1:<host>:" + portMapping.container_port + ". Continue?";
        if (!window.confirm(msg)) return;
        var publishResp = await apiFetch("/api/containers/publish-port", {
          method: "POST",
          body: {
            container_id: container.id,
            host_port: 0,
            container_port: portMapping.container_port,
            protocol: portMapping.protocol || "tcp"
          }
        });
        var publishData = (publishResp && publishResp.data) || {};
        var publishedPort = publishData.port || "";
        showToast("Port published" + (publishedPort ? " on " + publishedPort : ""), "success");
        await refreshContainerView();
      } else {
        msg = (data.reasons || []).join("\n") || "Automatic publish is not safe.";
        if (data.manual_command) msg += "\n\nManual:\n" + data.manual_command;
        window.alert(msg);
      }
    } catch (err) {
      showToast("Resolve failed: " + err.message, "error");
    }
  };

  window.__spLoadContainers = async function(opts) {
    opts = opts || {};
    var wrap = document.getElementById("containersContent");
    var silent = !!opts.silent;
    var force = !!opts.force;
    var hadSnapshot = !!(SP.cache && SP.cache.dashboardCore);
    try {
      if (!silent && !hadSnapshot && wrap) {
        showSpinner(wrap);
      }

      var core = await fetchDashboardCore({ force: force });
      applyDashboardCoreState(core);
      applyReplicaLabels();
      setText(document.getElementById("containerCount"), String(containers.length));
      renderContainers(wrap);
      updateTabTimestamp("containers");

      // Compose metadata is optional; load in the background without blocking the list.
      fetchComposeProjects({ force: force }).then(function(projects) {
        composeProjects = projects || [];
        if (activeTab === "containers" && wrap) {
          renderContainers(wrap);
        }
      }).catch(function() { /* non-fatal */ });
    } catch (err) {
      if (!wrap) return;
      wrap.innerHTML = "";
      var em = document.createElement("div");
      em.className = "empty-state";
      var p = document.createElement("p");
      setText(p, "Failed to load containers: " + err.message);
      em.appendChild(p);
      wrap.appendChild(em);
    }
  };
  window.loadContainers = window.__spLoadContainers;

  function renderContainers(wrap) {
    wrap.innerHTML = "";
    if (!containers.length) {
      var em = document.createElement("div");
      em.className = "empty-state";
      var p = document.createElement("p");
      setText(p, "No containers found");
      em.appendChild(p);
      wrap.appendChild(em);
      return;
    }
    var tw = document.createElement("div");
    tw.className = "table-wrap";
    var table = document.createElement("table");
    var thead = document.createElement("thead");
    var trh = document.createElement("tr");
    ["", "Name", "Image", "Status", "Ports", "Actions"].forEach(function(h) {
      var th = document.createElement("th");
      setText(th, h);
      trh.appendChild(th);
    });
    thead.appendChild(trh);
    table.appendChild(thead);
    var tbody = document.createElement("tbody");
    var replicaNames = {};
    containerReplicas.forEach(function(r) { if (r.name) replicaNames[r.name] = true; });

    function renderRow(c, replica) {
      var isReplica = !!replica;
      var tr = document.createElement("tr");
      if (isReplica) tr.className = "replica-row";
      var linked = sitesByContainer(c);

      var tdExp = document.createElement("td");
      var chev = document.createElement("button");
      chev.className = "btn btn-sm btn-outline container-expand-btn";
      var key = c.id || c.name;
      setText(chev, expandedContainers[key] ? "▼" : "▶");
      chev.addEventListener("click", function() {
        expandedContainers[key] = !expandedContainers[key];
        renderContainers(wrap);
      });
      tdExp.appendChild(chev);
      tr.appendChild(tdExp);

      var tdName = document.createElement("td");
      if (isReplica) tdName.style.paddingLeft = "1.6rem";
      var nameStrong = document.createElement("strong");
      if (isReplica && replica) {
        setText(nameStrong, (replica.name || c.name) + " \u2190 " + (replica.parent_name || ""));
      } else {
        setText(nameStrong, c.name);
      }
      tdName.appendChild(nameStrong);
      if (isReplica && replica && replica.alias) {
        var alias = document.createElement("div");
        alias.style.fontSize = "0.7rem";
        alias.style.color = "var(--accent)";
        setText(alias, "label: " + replica.alias + " \u00b7 template: " + (replica.template_type || "back"));
        tdName.appendChild(alias);
      }
      if (c.compose && c.compose.is_compose) {
        var composeBadge = document.createElement("span");
        composeBadge.className = "badge badge-info";
        composeBadge.style.marginLeft = "6px";
        setText(composeBadge, (c.compose.project || "compose") + "/" + (c.compose.service || "service"));
        tdName.appendChild(composeBadge);
      }
      if (linked.length === 1) {
        var domainBadge = document.createElement("span");
        domainBadge.className = "badge badge-info";
        domainBadge.style.marginLeft = "6px";
        domainBadge.title = "Associated site — expand row for actions";
        setText(domainBadge, siteDomainFromItem(linked[0]));
        tdName.appendChild(domainBadge);
      } else if (linked.length > 1) {
        var countBadge = document.createElement("span");
        countBadge.className = "badge badge-info";
        countBadge.style.marginLeft = "6px";
        setText(countBadge, linked.length + " sites");
        tdName.appendChild(countBadge);
      } else if (isReplica && replica && replica.domain) {
        var replicaDomainBadge = document.createElement("span");
        replicaDomainBadge.className = "badge badge-info";
        replicaDomainBadge.style.marginLeft = "6px";
        setText(replicaDomainBadge, replica.domain);
        tdName.appendChild(replicaDomainBadge);
      }
      tr.appendChild(tdName);

      var tdImg = document.createElement("td");
      if (isReplica && replica) {
        var sync = document.createElement("span");
        sync.className = replica.outdated ? "badge badge-stopped" : "badge badge-running";
        setText(sync, replica.outdated ? "Outdated" : "Synced");
        tdImg.appendChild(sync);
      } else {
        var imgCode = document.createElement("span");
        imgCode.style.fontFamily = "monospace";
        imgCode.style.fontSize = "0.8rem";
        setText(imgCode, c.image || "-");
        tdImg.appendChild(imgCode);
      }
      tr.appendChild(tdImg);

      var tdStatus = document.createElement("td");
      var badge = document.createElement("span");
      badge.className = "badge badge-running";
      setText(badge, c.status || "?");
      tdStatus.appendChild(badge);
      tr.appendChild(tdStatus);

      var tdPorts = document.createElement("td");
      var published = c.ports || [];
      var exposed = c.exposed_ports || [];
      published.forEach(function(p) {
        var ptag = document.createElement("span");
        ptag.className = "port-tag";
        setText(ptag, p.host_port + " \u2192 " + p.container_port + "/" + (p.protocol || "tcp"));
        tdPorts.appendChild(ptag);
      });
      exposed.forEach(function(p) {
        var ptag = document.createElement("span");
        ptag.className = "port-tag";
        ptag.style.color = "#d29922";
        setText(ptag, "Interno " + p.container_port + "/" + (p.protocol || "tcp"));
        tdPorts.appendChild(ptag);
      });
      if (!published.length && !exposed.length) {
        setText(tdPorts, "Sin puertos declarados");
      }
      tr.appendChild(tdPorts);

      var tdAct = document.createElement("td");
      tdAct.className = "actions-cell";

      var logsBtn = document.createElement("button");
      logsBtn.className = "btn btn-sm btn-outline";
      logsBtn.style.marginRight = "0.35rem";
      setText(logsBtn, "Logs");
      logsBtn.addEventListener("click", function() { openContainerLogsModal(c); });
      tdAct.appendChild(logsBtn);

      if (typeof reloadContainerEnv === "function") {
        var reloadEnvBtn = document.createElement("button");
        reloadEnvBtn.className = "btn btn-sm btn-outline";
        reloadEnvBtn.style.marginRight = "0.35rem";
        setText(reloadEnvBtn, "Reload env");
        reloadEnvBtn.disabled = !c.id;
        reloadEnvBtn.title = "Recreate this container with a selected managed app environment file.";
        reloadEnvBtn.addEventListener("click", function() { reloadContainerEnv(c); });
        tdAct.appendChild(reloadEnvBtn);
      }

      if (!isReplica && typeof openReplicaModal === "function") {
        var reps = replicasByParentName()[c.name] || [];
        var replicaBtn = document.createElement("button");
        replicaBtn.className = "btn btn-sm btn-outline";
        replicaBtn.style.marginRight = "0.35rem";
        setText(replicaBtn, "Create replica");
        replicaBtn.disabled = reps.length >= 3;
        replicaBtn.title = replicaBtn.disabled ? "Maximum 3 replicas reached" : "Clone this container into an independent replica";
        replicaBtn.addEventListener("click", function() { openReplicaModal(c); });
        tdAct.appendChild(replicaBtn);
      }

      if (isReplica && replica) {
        var replicaTemplate = replica.template_type || "back";
        if (replicaTemplate !== "back") {
          var manageBtn = document.createElement("button");
          manageBtn.className = "btn btn-sm btn-primary";
          manageBtn.style.marginRight = "0.35rem";
          setText(manageBtn, replica.domain ? "Manage Site" : associateButtonText(replicaTemplate));
          manageBtn.addEventListener("click", function() {
            if (replica.domain) {
              window.openSitesTab(c);
            } else {
              window.openAssociateModal(c, replicaTemplate);
            }
          });
          tdAct.appendChild(manageBtn);
        }
        if (typeof syncReplica === "function") {
          var syncBtn = document.createElement("button");
          syncBtn.className = "btn btn-sm btn-warning";
          syncBtn.style.marginRight = "0.35rem";
          setText(syncBtn, "Sync with parent");
          syncBtn.addEventListener("click", function() { syncReplica(replica); });
          tdAct.appendChild(syncBtn);
        }
        if (typeof deleteReplica === "function") {
          var delBtn = document.createElement("button");
          delBtn.className = "btn btn-sm btn-danger";
          setText(delBtn, "Delete");
          delBtn.addEventListener("click", function() { deleteReplica(replica); });
          tdAct.appendChild(delBtn);
        }
      }

      if (!linked.length && hasPublishedTCPPort(c)) {
        var addSiteBtn = document.createElement("button");
        addSiteBtn.className = "btn btn-sm btn-primary";
        setText(addSiteBtn, "Add Site");
        addSiteBtn.addEventListener("click", function() {
          expandedContainers[key] = true;
          window.openAssociateModal(c, associateTemplateForContainer(c));
        });
        tdAct.appendChild(addSiteBtn);
      }

      tr.appendChild(tdAct);
      tbody.appendChild(tr);

      if (expandedContainers[key]) {
        renderContainerSitesPanel(c, tbody);
      }
    }

    var standalone = [];
    var composeGroups = {};
    containers.forEach(function(c) {
      if (replicaNames[c.name]) return;
      if (c.compose && c.compose.is_compose && c.compose.project) {
        if (!composeGroups[c.compose.project]) composeGroups[c.compose.project] = [];
        composeGroups[c.compose.project].push(c);
        return;
      }
      standalone.push(c);
    });

    Object.keys(composeGroups).sort().forEach(function(project) {
      var header = document.createElement("tr");
      header.className = "compose-group-row";
      var td = document.createElement("td");
      td.colSpan = 6;
      var strong = document.createElement("strong");
      setText(strong, "Compose stack: " + project);
      td.appendChild(strong);
      header.appendChild(td);
      tbody.appendChild(header);
      composeGroups[project].forEach(function(c) { renderRow(c); });
    });

    standalone.forEach(function(c) {
      renderRow(c);
      var reps = replicasByParentName()[c.name] || [];
      reps.forEach(function(rep) {
        renderRow(containerForReplica(rep), rep);
      });
    });

    table.appendChild(tbody);
    tw.appendChild(table);
    wrap.appendChild(tw);
    renderGlobalSections(wrap);
  }
  window.renderContainers = renderContainers;

  window.openAssociateModal = function(container, templateType) {
    initBodySizeSelect();
    if (!container) return;
    if (container.compose && container.compose.is_compose && !publishedTCPPorts(container).length) {
      showToast("Compose service is internal-only. Publish via stack deploy before adding a site.", "warning");
      return;
    }
    var modal = document.getElementById("associateModal");
    var containerId = document.getElementById("assocContainerId");
    var containerName = document.getElementById("assocContainerName");
    var portSelect = document.getElementById("assocPortSelect");
    var portWrap = document.getElementById("assocPortSelectWrap");
    var allocate = document.getElementById("assocAllocate");
    var submitBtn = document.getElementById("assocSubmitBtn");
    var templateEl = document.getElementById("assocTemplate");
    var domainEl = document.getElementById("assocDomain");
    if (!modal || !containerId || !portSelect || !submitBtn) return;

    _assocPendingContainer = container;
    containerId.value = container.id || "";
    if (containerName) containerName.value = container.name || "";

    var label = templateType || "api";
    var templateNames = {
      api: "API reverse proxy",
      nestjs: "NestJS site",
      nextjs: "Next.js site",
      frontend: "Frontend/SPA site",
      minio: "MinIO object storage"
    };
    var actionText = "Create " + (templateNames[label] || "an Nginx site");
    setText(document.getElementById("associateModalSub"), actionText + " for \"" + (container.name || "") + "\"");

    if (domainEl) domainEl.value = "";
    var includeWWW = document.getElementById("assocIncludeWWW");
    if (includeWWW) includeWWW.checked = false;
    var enableSSL = document.getElementById("assocEnableSSL");
    if (enableSSL) enableSSL.checked = false;
    var allowShared = document.getElementById("assocAllowShared");
    if (allowShared) allowShared.checked = false;
    if (templateEl) templateEl.value = label;
    var bodySizeSel = document.getElementById("optBodySize");
    var bodySizeCustom = document.getElementById("optBodySizeCustom");
    if (bodySizeSel) bodySizeSel.value = "";
    if (bodySizeCustom) {
      bodySizeCustom.value = "";
      bodySizeCustom.style.display = "none";
    }

    var allocateMsg = document.getElementById("assocAllocateMsg");
    if (allocateMsg) {
      allocateMsg.style.color = "var(--text-muted)";
      allocateMsg.textContent = "";
    }

    portSelect.innerHTML = "";
    var published = publishedTCPPorts(container);
    published.forEach(function(p, idx) {
      var opt = document.createElement("option");
      opt.value = JSON.stringify({ host: p.host_port, container: p.container_port });
      setText(opt, p.host_port + " \u2192 " + p.container_port + "/" + (p.protocol || "tcp"));
      portSelect.appendChild(opt);
      if (idx === 0) portSelect.value = opt.value;
    });
    var exposed = exposedOnlyTCPPorts(container);
    if (portWrap) portWrap.style.display = published.length ? "block" : "none";
    if (allocate) allocate.style.display = (!published.length && exposed.length) ? "block" : "none";
    submitBtn.disabled = !published.length;
    modal.classList.add("show");
  };

  window.allocatePortForAssoc = async function() {
    var btn = document.getElementById("assocAllocateBtn");
    var msg = document.getElementById("assocAllocateMsg");
    var portSelect = document.getElementById("assocPortSelect");
    var portWrap = document.getElementById("assocPortSelectWrap");
    var allocate = document.getElementById("assocAllocate");
    var submitBtn = document.getElementById("assocSubmitBtn");
    if (!btn || !msg || !portSelect) return;
    btn.disabled = true;
    msg.style.color = "var(--text-muted)";
    msg.textContent = "Reserving stable host port…";
    try {
      var exposed = _assocPendingContainer ? exposedOnlyTCPPorts(_assocPendingContainer) : [];
      var internal = exposed.length && exposed[0].container_port ? String(exposed[0].container_port) : "";
      if (!internal) throw new Error("el contenedor no declara un puerto TCP interno");
      var resp = await apiFetch("/api/containers/reserve-port", {
        method: "POST",
        body: {
          container_id: document.getElementById("assocContainerId").value,
          container_port: internal,
          protocol: "tcp"
        }
      });
      var data = (resp && resp.data) || {};
      var port = data.port;
      if (!port) throw new Error("no port returned");
      var opt = document.createElement("option");
      opt.value = JSON.stringify({ host: port, container: internal });
      setText(opt, port + " \u2192 " + internal + "/tcp (reserved)");
      portSelect.innerHTML = "";
      portSelect.appendChild(opt);
      portSelect.value = opt.value;
      if (portWrap) portWrap.style.display = "block";
      if (allocate) allocate.style.display = "none";
      if (submitBtn) submitBtn.disabled = false;
      msg.style.color = "#3fb950";
      msg.innerHTML =
        '✓ Puerto <strong>' + port + '</strong> reservado para este contenedor.<br>' +
        '<span style="font-size:0.72rem;">Si ServerPilot puede publicarlo automáticamente, usa <strong>Publicar puerto</strong> en la fila del contenedor. Si no, redepliega con:</span><br>' +
        '<code style="display:inline-block;margin-top:4px;padding:3px 6px;background:var(--bg-input);border:1px solid var(--border);border-radius:4px;font-size:0.72rem;">' +
          'docker run … -p ' + port + ':' + escapeHtml(internal) + ' …' +
        '</code><br>' +
        '<span style="font-size:0.66rem;color:var(--text-muted);">Después de publicar el puerto en el contenedor, pulsa <strong>Create Site</strong>. El puerto se conserva hasta 14 días si el contenedor queda inactivo.</span>';

      try {
        var analysisResp = await apiFetch("/api/containers/port-analysis?container_id=" + encodeURIComponent(document.getElementById("assocContainerId").value));
        var analysis = (analysisResp && analysisResp.data) || {};
        if (analysis.can_auto_publish) {
          if (window.confirm("¿Publicar automáticamente " + port + " → " + internal + " en este contenedor ahora?")) {
            var publishResp = await apiFetch("/api/containers/publish-port", {
              method: "POST",
              body: {
                container_id: document.getElementById("assocContainerId").value,
                host_port: 0,
                container_port: internal,
                protocol: "tcp"
              }
            });
            var published = ((publishResp && publishResp.data) || {}).port || port;
            showToast("Puerto publicado en " + published, "success");
            await refreshContainerView();
          }
        }
      } catch (_) { /* optional auto-publish */ }
    } catch (err) {
      msg.style.color = "#f85149";
      msg.textContent = "Failed: " + ((err && err.message) || "error");
    } finally {
      btn.disabled = false;
    }
  };

  initBodySizeSelect();

  var assocForm = document.getElementById("associateForm");
  if (assocForm) {
    assocForm.addEventListener("submit", async function(e) {
      e.preventDefault();
      var btn = document.getElementById("assocSubmitBtn");
      btn.disabled = true;
      var portData = {};
      try { portData = JSON.parse(document.getElementById("assocPortSelect").value || "{}"); } catch (_) {}
      var body = {
        template_type: document.getElementById("assocTemplate").value,
        domain: document.getElementById("assocDomain").value.trim().toLowerCase(),
        port: parseInt(portData.host, 10),
        container_port: parseInt(portData.container, 10) || 0,
        container_id: document.getElementById("assocContainerId").value,
        container_name: document.getElementById("assocContainerName").value,
        include_www: document.getElementById("assocIncludeWWW").checked,
        allow_shared_host_port: document.getElementById("assocAllowShared").checked,
        enable_ssl: document.getElementById("assocEnableSSL").checked,
        options: {
          websocket: document.getElementById("optWebSocket").checked,
          sse: document.getElementById("optSSE").checked,
          rate_limit_enabled: document.getElementById("optRateLimit").checked,
          request_buffering_off: document.getElementById("optReqBufOff").checked,
          response_buffering_off: document.getElementById("optResBufOff").checked,
          body_size: bodySizeFromForm()
        }
      };
      try {
        if (typeof ensureRecentReauth === "function") {
          await ensureRecentReauth();
        }
        await apiFetch("/api/sites/create", { method: "POST", body: body });
        document.getElementById("associateModal").classList.remove("show");
        showToast("Site created", "success");
        if (body.enable_ssl) {
          runStreamedOperation("/api/ssl/enable", { domain: body.domain }, "Enabling SSL", body.domain);
        }
        await refreshContainerView();
      } catch (err) {
        var msg = (err && err.message) || "error";
        if (msg.indexOf("share port") >= 0 && window.confirm("This port already has a site. Create another domain on the same port?")) {
          body.allow_shared_host_port = true;
          try {
            await apiFetch("/api/sites/create", { method: "POST", body: body });
            document.getElementById("associateModal").classList.remove("show");
            showToast("Site created", "success");
            await refreshContainerView();
          } catch (err2) { showToast("Failed: " + err2.message, "error"); }
        } else {
          showToast("Failed: " + msg, "error");
        }
      } finally {
        btn.disabled = false;
        setText(btn, "Create Site");
      }
    }, true);
  }

  window.openSitesTab = function(container) {
    var containersTab = document.querySelector('.tab-btn[data-tab="containers"]');
    if (containersTab) containersTab.click();
    if (container) {
      var key = container.id || container.name;
      if (key) expandedContainers[key] = true;
    }
    return window.loadContainers();
  };

  // Initial tab load runs from showDashboard() after /api/session/status confirms auth.
  // Do not fetch protected APIs here — panel-containers is "active" in HTML even on login.
})();
