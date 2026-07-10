/* Container-centric multi-site management (loaded after main dashboard script). */
(function() {
  var expandedContainers = {};
  var composeProjects = [];

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
    (container.ports || []).forEach(function(p) {
      if (!p.host_port && p.container_port && (p.protocol || "tcp") === "tcp") {
        out.push(p);
      }
    });
    return out;
  }

  function refreshContainerView() {
    return loadContainers();
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
        var title = document.createElement("strong");
        setText(title, (site && site.domain) || m.nginx_domain || "?");
        row.appendChild(title);
        if (m.orphaned) {
          var ob = document.createElement("span");
          ob.className = "badge badge-warning";
          ob.style.marginLeft = "8px";
          setText(ob, "Orphan");
          row.appendChild(ob);
        }
        if (m.redirect_active) {
          var rb = document.createElement("span");
          rb.className = "badge badge-running";
          rb.style.marginLeft = "8px";
          setText(rb, "Redirect active");
          row.appendChild(rb);
        }
        var portInfo = document.createElement("span");
        portInfo.style.marginLeft = "8px";
        portInfo.style.color = "var(--text-muted)";
        portInfo.style.fontSize = "0.75rem";
        setText(portInfo, "port " + (m.host_port || m.container_port || "?"));
        row.appendChild(portInfo);
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
      addBtn.addEventListener("click", function() { openAssociateModal(container, "api"); });
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
        var portResp = await apiFetch("/api/system/port");
        var hostPort = (portResp && portResp.data && portResp.data.port) || 0;
        if (!hostPort) throw new Error("no port allocated");
        await apiFetch("/api/containers/publish-port", {
          method: "POST",
          body: {
            container_id: container.id,
            host_port: hostPort,
            container_port: portMapping.container_port,
            protocol: portMapping.protocol || "tcp"
          }
        });
        showToast("Port published on " + hostPort, "success");
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

  var _origLoadContainers = window.loadContainers;
  window.loadContainers = async function() {
    var wrap = document.getElementById("containersContent");
    try {
      var results = await Promise.all([
        apiFetch("/api/containers"),
        apiFetch("/api/sites"),
        apiFetch("/api/mappings"),
        loadReplicas(),
        apiFetch("/api/compose/projects").catch(function() { return { data: [] }; })
      ]);
      containers = (results[0] && results[0].data) ? results[0].data : [];
      sites = (results[1] && results[1].data) ? results[1].data : [];
      var mappingsData = (results[2] && results[2].data) ? results[2].data : results[2];
      composeProjects = (results[4] && results[4].data) ? results[4].data : [];
      mappings = {
        mapped: (mappingsData && mappingsData.mapped) || [],
        unmappedContainers: (mappingsData && mappingsData.unmappedContainers) || [],
        orphanedSites: (mappingsData && mappingsData.orphanedSites) || [],
        standalone_redirects: (mappingsData && mappingsData.standalone_redirects) || [],
        unassigned_sites: (mappingsData && mappingsData.unassigned_sites) || []
      };
      applyReplicaLabels();
      setText(document.getElementById("containerCount"), String(containers.length));
      if (typeof renderContainersV2 === "function") renderContainersV2(wrap);
      else if (_origLoadContainers) await _origLoadContainers();
      updateTabTimestamp("containers");
    } catch (err) {
      wrap.innerHTML = "";
      var em = document.createElement("div");
      em.className = "empty-state";
      var p = document.createElement("p");
      setText(p, "Failed to load containers: " + err.message);
      em.appendChild(p);
      wrap.appendChild(em);
    }
  };

  window.loadSites = window.loadContainers;

  window.renderContainersV2 = function(wrap) {
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

    function renderRow(c, isReplica) {
      var tr = document.createElement("tr");
      if (isReplica) tr.className = "replica-row";

      var tdExp = document.createElement("td");
      var chev = document.createElement("button");
      chev.className = "btn btn-sm btn-outline container-expand-btn";
      var key = c.id || c.name;
      setText(chev, expandedContainers[key] ? "▼" : "▶");
      chev.addEventListener("click", function() {
        expandedContainers[key] = !expandedContainers[key];
        renderContainersV2(wrap);
      });
      tdExp.appendChild(chev);
      tr.appendChild(tdExp);

      var tdName = document.createElement("td");
      var nameStrong = document.createElement("strong");
      setText(nameStrong, c.name);
      tdName.appendChild(nameStrong);
      if (c.compose && c.compose.is_compose) {
        var composeBadge = document.createElement("span");
        composeBadge.className = "badge badge-info";
        composeBadge.style.marginLeft = "6px";
        setText(composeBadge, (c.compose.project || "compose") + "/" + (c.compose.service || "service"));
        tdName.appendChild(composeBadge);
      }
      var count = sitesByContainer(c).length;
      if (count) {
        var badge = document.createElement("span");
        badge.className = "badge badge-info";
        badge.style.marginLeft = "6px";
        setText(badge, count + " site" + (count === 1 ? "" : "s"));
        tdName.appendChild(badge);
      }
      tr.appendChild(tdName);

      var tdImg = document.createElement("td");
      var imgCode = document.createElement("span");
      imgCode.style.fontFamily = "monospace";
      imgCode.style.fontSize = "0.8rem";
      setText(imgCode, c.image || "-");
      tdImg.appendChild(imgCode);
      tr.appendChild(tdImg);

      var tdStatus = document.createElement("td");
      var badge = document.createElement("span");
      badge.className = "badge badge-running";
      setText(badge, c.status || "?");
      tdStatus.appendChild(badge);
      tr.appendChild(tdStatus);

      var tdPorts = document.createElement("td");
      (c.ports || []).concat(c.exposed_ports || []).forEach(function(p) {
        var ptag = document.createElement("span");
        ptag.className = "port-tag";
        if (p.host_port) setText(ptag, p.host_port + ":" + p.container_port + "/" + (p.protocol || "tcp"));
        else {
          ptag.style.color = "#d29922";
          setText(ptag, "exposed " + p.container_port + "/" + (p.protocol || "tcp"));
        }
        tdPorts.appendChild(ptag);
      });
      if (!c.ports || !c.ports.length) setText(tdPorts, "None");
      tr.appendChild(tdPorts);

      var tdAct = document.createElement("td");
      tdAct.className = "actions-cell";
      var logsBtn = document.createElement("button");
      logsBtn.className = "btn btn-sm btn-outline";
      setText(logsBtn, "Logs");
      logsBtn.addEventListener("click", function() { openContainerLogsModal(c); });
      tdAct.appendChild(logsBtn);
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
      composeGroups[project].forEach(function(c) { renderRow(c, false); });
    });

    standalone.forEach(function(c) {
      renderRow(c, false);
      var reps = replicasByParentName()[c.name] || [];
      reps.forEach(function(rep) {
        renderRow(containerForReplica(rep), true);
      });
    });

    table.appendChild(tbody);
    tw.appendChild(table);
    wrap.appendChild(tw);
    renderGlobalSections(wrap);
  };

  var _origOpenAssociate = window.openAssociateModal;
  window.openAssociateModal = function(container, templateType) {
    if (container && container.compose && container.compose.is_compose && !publishedTCPPorts(container).length) {
      showToast("Compose service is internal-only. Publish via stack deploy before adding a site.", "warning");
      return;
    }
    _assocPendingContainer = container;
    document.getElementById("assocContainerId").value = container.id;
    document.getElementById("assocContainerName").value = container.name || "";
    setText(document.getElementById("associateModalSub"), "Add site for \"" + container.name + "\"");
    document.getElementById("assocDomain").value = "";
    document.getElementById("assocIncludeWWW").checked = false;
    document.getElementById("assocEnableSSL").checked = false;
    document.getElementById("assocAllowShared").checked = false;
    document.getElementById("assocTemplate").value = templateType || "api";

    var portSelect = document.getElementById("assocPortSelect");
    portSelect.innerHTML = "";
    var published = publishedTCPPorts(container);
    published.forEach(function(p, idx) {
      var opt = document.createElement("option");
      opt.value = JSON.stringify({ host: p.host_port, container: p.container_port });
      setText(opt, p.host_port + " → " + p.container_port + "/" + (p.protocol || "tcp"));
      portSelect.appendChild(opt);
      if (idx === 0) portSelect.value = opt.value;
    });
    document.getElementById("assocPortSelectWrap").style.display = published.length ? "block" : "none";
    document.getElementById("assocAllocate").style.display = published.length ? "none" : "block";
    document.getElementById("assocSubmitBtn").disabled = !published.length;
    document.getElementById("associateModal").classList.add("show");
  };

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
          body_size: document.getElementById("optBodySize").value || ""
        }
      };
      try {
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
    return loadContainers();
  };
})();
