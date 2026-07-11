/* Sites tab */
"use strict";

    var wrap = document.getElementById("sitesContent");
    try {
      var results = await Promise.all([
        apiFetch("/api/sites"),
        apiFetch("/api/containers"),
        apiFetch("/api/mappings"),
        loadLabels(),
        loadReplicas()
      ]);
      var resp = results[0];
      var containersResp = results[1];
      var mappingsResp = results[2];
      sites = (resp && resp.data) ? resp.data : (Array.isArray(resp) ? resp : []);
      containers = (containersResp && containersResp.data) ? containersResp.data : (Array.isArray(containersResp) ? containersResp : []);
      var mappingsData = (mappingsResp && mappingsResp.data) ? mappingsResp.data : mappingsResp;
      mappings = {
        mapped: (mappingsData && mappingsData.mapped) || [],
        unmappedContainers: (mappingsData && mappingsData.unmappedContainers) || [],
        orphanedSites: (mappingsData && mappingsData.orphanedSites) || [],
        dashboardSites: (mappingsData && mappingsData.dashboardSites) || []
      };
      applyReplicaLabels();
      setText(document.getElementById("siteCount"), String(sites.length + engineSiteCandidates().length));
      renderSites(wrap);
      updateTabTimestamp("sites");
    } catch(err) {
      wrap.innerHTML = "";
      var em = document.createElement("div");
      em.className = "empty-state";
      var p = document.createElement("p");
      setText(p, "Failed to load sites: " + err.message);
      em.appendChild(p);
      wrap.appendChild(em);
    }
  }

  function siteProxyPort(site) {
    var proxy = (site && site.proxy_pass) || "";
    var m = proxy.match(/:(\d+)(?:\/|$)/);
    return m ? m[1] : "";
  }

  function mappingForSite(site) {
    var port = siteProxyPort(site);
    for (var i = 0; i < mappings.mapped.length; i++) {
      var m = mappings.mapped[i];
      if (site.domain && m.nginx_domain === site.domain) return m;
      if (port && String(m.container_port) === String(port)) return m;
    }
    return null;
  }

  function containerByName(name) {
    for (var i = 0; i < containers.length; i++) {
      if (containers[i].name === name) return containers[i];
    }
    return null;
  }

  function engineSiteCandidates() {
    var mappedNames = {};
    (mappings.mapped || []).forEach(function(m) {
      if (m.container_name) mappedNames[m.container_name] = true;
    });
    var out = [];
    (containers || []).forEach(function(c) {
      var label = containerLabels[c.name] || "";
      if (!label || label === "back" || mappedNames[c.name]) return;
      var port = "";
      if (c.ports && c.ports.length) {
        for (var i = 0; i < c.ports.length; i++) {
          if (c.ports[i].host_port) {
            port = String(c.ports[i].host_port);
            break;
          }
        }
      }
      if (!port) return;
      out.push({ container: c, label: label, host_port: port });
    });
    out.sort(function(a,b) { return String(a.container.name).localeCompare(String(b.container.name)); });
    return out;
  }

  function appendEngineCell(tr, mapping, fallbackName) {
    var td = document.createElement("td");
    if (!mapping && !fallbackName) {
      setText(td, "-");
      td.style.color = "var(--text-muted)";
      tr.appendChild(td);
      return;
    }
    var name = mapping ? mapping.container_name : fallbackName;
    var label = containerLabels[name] || "";
    if (label) {
      var badge = document.createElement("span");
      badge.className = "label-badge label-badge-" + label.replace(/[^a-z-]/g, "");
      setText(badge, label);
      td.appendChild(badge);
      td.appendChild(document.createTextNode(" "));
    }
    var s = document.createElement("strong");
    setText(s, name);
    td.appendChild(s);
    tr.appendChild(td);
  }

  function renderSites(wrap) {
    wrap.innerHTML = "";
    var pendingEngines = engineSiteCandidates();
    if (!sites.length && !pendingEngines.length) {
      var em = document.createElement("div");
      em.className = "empty-state";
      var p = document.createElement("p");
      setText(p, "No Nginx sites configured");
      em.appendChild(p);
      wrap.appendChild(em);
      return;
    }
    var tw = document.createElement("div");
    tw.className = "table-wrap";
    var table = document.createElement("table");

    var thead = document.createElement("thead");
    var trh = document.createElement("tr");
    ["Domain", "Engine", "Port", "Target", "SSL", "WWW", "Auto-Renew", "Status", "Actions"].forEach(function(h) {
      var th = document.createElement("th");
      setText(th, h);
      trh.appendChild(th);
    });
    thead.appendChild(trh);
    table.appendChild(thead);

    var tbody = document.createElement("tbody");
    sites.forEach(function(s) {
      var tr = document.createElement("tr");
      var siteMapping = mappingForSite(s);
      var configName = s.config_path ? s.config_path.split("/").pop() : s.domain;

      // Domain
      var tdDomain = document.createElement("td");
      var domStrong = document.createElement("strong");
      setText(domStrong, s.domain);
      tdDomain.appendChild(domStrong);
      tr.appendChild(tdDomain);

      if (s.redirect_target) {
        var tdRedirectEngine = document.createElement("td");
        var redirectBadge = document.createElement("span");
        redirectBadge.className = "badge badge-running";
        if (s.redirect_delay) {
          setText(redirectBadge, "Redirect " + s.redirect_delay + "s");
        } else {
          setText(redirectBadge, "Redirect " + (s.redirect_code || 301));
        }
        tdRedirectEngine.appendChild(redirectBadge);
        tr.appendChild(tdRedirectEngine);
      } else {
        appendEngineCell(tr, siteMapping, "");
      }

      // Port
      var tdPort = document.createElement("td");
      var ptag = document.createElement("span");
      ptag.className = "port-tag";
      setText(ptag, String(s.listen_port));
      tdPort.appendChild(ptag);
      tr.appendChild(tdPort);

      // Proxy Pass
      var tdProxy = document.createElement("td");
      var proxyCode = document.createElement("span");
      proxyCode.style.fontFamily = '"SF Mono","Fira Code",monospace';
      proxyCode.style.fontSize = "0.8125rem";
      proxyCode.style.color = "var(--text-secondary)";
      setText(proxyCode, s.redirect_target || s.proxy_pass || "-");
      tdProxy.appendChild(proxyCode);
      tr.appendChild(tdProxy);

      // SSL
      var tdSSL = document.createElement("td");
      var sslSpan = document.createElement("span");
      sslSpan.className = "ssl-icon " + (s.ssl_enabled ? "ssl-enabled" : "ssl-disabled");
      setText(sslSpan, s.ssl_enabled ? "\uD83D\uDD12" : "\uD83D\uDD13");
      tdSSL.appendChild(sslSpan);
      var sslLabel = document.createTextNode(" " + (s.ssl_enabled ? "Enabled" : "Disabled"));
      tdSSL.appendChild(sslLabel);
      tr.appendChild(tdSSL);

      // WWW
      var tdWWW = document.createElement("td");
      var wwwBadge = document.createElement("span");
      wwwBadge.className = "badge " + (s.www_enabled ? "badge-running" : "badge-stopped");
      setText(wwwBadge, s.www_enabled ? "Enabled" : "Disabled");
      tdWWW.appendChild(wwwBadge);
      tr.appendChild(tdWWW);

      // Auto-Renew
      var tdRenew = document.createElement("td");
      setText(tdRenew, s.ssl_auto_renew ? "Yes" : "No");
      tdRenew.style.color = s.ssl_auto_renew ? "var(--green)" : "var(--text-muted)";
      tr.appendChild(tdRenew);

      // Status
      var tdEnabled = document.createElement("td");
      var enBadge = document.createElement("span");
      enBadge.className = "badge " + (s.enabled ? "badge-running" : "badge-stopped");
      setText(enBadge, s.enabled ? "Enabled" : "Disabled");
      tdEnabled.appendChild(enBadge);
      tr.appendChild(tdEnabled);

      // Actions
      var tdAct = document.createElement("td");
      tdAct.className = "actions-cell";

      // Enable/Disable toggle
      var toggleBtn = document.createElement("button");
      toggleBtn.className = "btn btn-sm " + (s.enabled ? "btn-warning" : "btn-success");
      setText(toggleBtn, s.enabled ? "Disable" : "Enable");
      (function(site) {
        toggleBtn.addEventListener("click", function() {
          var action = site.enabled ? "disable" : "enable";
          confirmAction("Confirm " + action, "Are you sure you want to " + action + " " + site.domain + "?", async function() {
            try {
              await apiFetch("/api/sites/" + action, { method: "POST", body: { domain: site.domain } });
              showToast("Site " + action + "d successfully", "success");
              await Promise.all([loadSites(), loadMappings(), loadContainers()]);
            } catch(err) { showToast("Failed: " + err.message, "error"); }
          });
        });
      })(s);
      tdAct.appendChild(toggleBtn);

      // SSL toggle
      var sslBtn = document.createElement("button");
      if (s.ssl_enabled) {
        sslBtn.className = "btn btn-sm btn-danger";
        setText(sslBtn, "Disable SSL");
      } else {
        sslBtn.className = "btn btn-sm btn-success";
        setText(sslBtn, "Enable SSL");
      }
      (function(site) {
        sslBtn.addEventListener("click", function() {
          var action = site.ssl_enabled ? "disable" : "enable";
          confirmAction("SSL " + action, "Are you sure you want to " + action + " SSL for " + site.domain + "?", function() {
            runStreamedOperation(
              "/api/ssl/" + action,
              { domain: site.domain },
              (action === "enable" ? "Enabling" : "Disabling") + " SSL",
              site.domain
            );
          });
        });
      })(s);
      tdAct.appendChild(sslBtn);

      // WWW enable
      var wwwBtn = document.createElement("button");
      var canEnableWWW = s.domain && s.domain !== "_" && String(s.domain).toLowerCase().indexOf("www.") !== 0;
      wwwBtn.className = "btn btn-sm " + (s.www_enabled ? "btn-outline" : "btn-success");
      setText(wwwBtn, s.www_enabled ? "WWW Enabled" : "Enable WWW");
      wwwBtn.disabled = !canEnableWWW || s.www_enabled;
      (function(site, siteConfigName) {
        wwwBtn.addEventListener("click", function() {
          var wwwDomain = "www." + site.domain;
          confirmAction("Enable WWW", "Enable " + wwwDomain + " for " + site.domain + "? If SSL is enabled, Certbot will expand the certificate too.", function() {
            runStreamedOperation(
              "/api/sites/enable-www",
              { domain: site.domain, config_name: siteConfigName },
              "Enabling WWW",
              site.domain + " + " + wwwDomain
            );
          });
        });
      })(s, configName);
      tdAct.appendChild(wwwBtn);

      // Update Domain button
      var updateDomainBtn = document.createElement("button");
      updateDomainBtn.className = "btn btn-sm btn-outline";
      setText(updateDomainBtn, "Update Domain");
      (function(site) {
        updateDomainBtn.addEventListener("click", function() {
          var currentName = site.domain && site.domain !== "_" ? site.domain : configName;
          var newDomain = window.prompt("Enter the new domain for " + currentName + ".", "");
          if (newDomain === null) return;
          newDomain = newDomain.trim().toLowerCase();
          if (!newDomain) {
            showToast("Enter a domain", "error");
            return;
          }
          if (newDomain === String(currentName || "").toLowerCase()) {
            showToast("New domain must be different", "error");
            return;
          }
          confirmAction("Update Domain", "Change " + currentName + " to " + newDomain + " and enable SSL now?", function() {
            runStreamedOperation(
              "/api/sites/update-domain",
              {
                current_domain: site.domain || "",
                config_name: configName,
                new_domain: newDomain,
                enable_ssl: true,
                remove_old_cert: true
              },
              "Updating Domain",
              currentName + " -> " + newDomain + " with SSL"
            );
          });
        });
      })(s);
      tdAct.appendChild(updateDomainBtn);

      // Edit Config button
      var editBtn = document.createElement("button");
      editBtn.className = "btn btn-sm btn-outline";
      setText(editBtn, "Edit Config");
      (function(site) {
        editBtn.addEventListener("click", function() {
          openConfigEditor(configName, site.domain);
        });
      })(s);
      tdAct.appendChild(editBtn);

      // Delete Site button
      var deleteBtn = document.createElement("button");
      deleteBtn.className = "btn btn-sm btn-danger";
      setText(deleteBtn, "Delete");
      (function(site) {
        deleteBtn.addEventListener("click", function() {
          confirmAction("Delete Site", "Are you sure you want to completely delete " + (site.domain || configName) + "? This will remove the nginx config, symlink, and SSL certificate.", function() {
            runStreamedOperation(
              "/api/sites/delete",
              { domain: site.domain, config_name: configName },
              "Deleting Site",
              "Removing all configuration for " + (site.domain || configName)
            );
          });
        });
      })(s);
      tdAct.appendChild(deleteBtn);

      tr.appendChild(tdAct);
      tbody.appendChild(tr);
    });

    pendingEngines.forEach(function(candidate) {
      var tr = document.createElement("tr");
      tr.style.background = "rgba(210,153,34,0.055)";

      var tdDomain = document.createElement("td");
      setText(tdDomain, "Not created");
      tdDomain.style.color = "var(--text-muted)";
      tr.appendChild(tdDomain);

      appendEngineCell(tr, null, candidate.container.name);

      var tdPort = document.createElement("td");
      var ptag = document.createElement("span");
      ptag.className = "port-tag";
      setText(ptag, candidate.host_port);
      tdPort.appendChild(ptag);
      tr.appendChild(tdPort);

      var tdProxy = document.createElement("td");
      var proxyCode = document.createElement("span");
      proxyCode.style.fontFamily = '"SF Mono","Fira Code",monospace';
      proxyCode.style.fontSize = "0.8125rem";
      proxyCode.style.color = "var(--text-secondary)";
      setText(proxyCode, "http://127.0.0.1:" + candidate.host_port);
      tdProxy.appendChild(proxyCode);
      tr.appendChild(tdProxy);

      var tdSSL = document.createElement("td");
      setText(tdSSL, "-");
      tdSSL.style.color = "var(--text-muted)";
      tr.appendChild(tdSSL);

      var tdRenew = document.createElement("td");
      setText(tdRenew, "-");
      tdRenew.style.color = "var(--text-muted)";
      tr.appendChild(tdRenew);

      var tdStatus = document.createElement("td");
      var badge = document.createElement("span");
      badge.className = "badge badge-warning";
      setText(badge, "Needs site");
      tdStatus.appendChild(badge);
      tr.appendChild(tdStatus);

      var tdAct = document.createElement("td");
      tdAct.className = "actions-cell";
      var createBtn = document.createElement("button");
      createBtn.className = "btn btn-sm btn-primary";
      setText(createBtn, associateButtonText(candidate.label));
      createBtn.addEventListener("click", function() {
        openAssociateModal(candidate.container, candidate.label);
      });
      tdAct.appendChild(createBtn);
      tr.appendChild(tdAct);
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    tw.appendChild(table);
    wrap.appendChild(tw);
  }

  // ── Images ──
  async function loadImages() {
