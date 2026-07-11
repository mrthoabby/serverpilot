/* Containers + replicas */
"use strict";

  async function loadLabels() {
    try {
      var resp = await apiFetch("/api/labels");
      containerLabels = (resp && resp.data) ? resp.data : {};
    } catch(e) {
      // Non-critical: keep existing labels cache.
    }
  }

  async function loadReplicas() {
    try {
      var resp = await apiFetch("/api/container-replicas");
      containerReplicas = (resp && resp.data) ? resp.data : [];
      if (!Array.isArray(containerReplicas)) containerReplicas = [];
      applyReplicaLabels();
    } catch(e) {
      containerReplicas = [];
    }
  }

  function applyReplicaLabels() {
    containerReplicas.forEach(function(r) {
      if (r && r.name && r.template_type) {
        containerLabels[r.name] = r.template_type;
      }
    });
  }

  async function setContainerLabel(containerName, label) {
    try {
      await apiFetch("/api/labels/set", { method: "POST", body: { container_name: containerName, label: label } });
      containerLabels[containerName] = label;
      showToast("Label '" + label + "' set for " + containerName, "success");
      renderContainers(document.getElementById("containersContent"));
    } catch(err) {
      showToast("Failed to set label: " + err.message, "error");
    }
  }

  async function removeContainerLabel(containerName) {
    try {
      await apiFetch("/api/labels/remove", { method: "POST", body: { container_name: containerName } });
      delete containerLabels[containerName];
      showToast("Label removed for " + containerName, "success");
      renderContainers(document.getElementById("containersContent"));
    } catch(err) {
      showToast("Failed to remove label: " + err.message, "error");
    }
  }

  async function loadContainers() {
    var wrap = document.getElementById("containersContent");
    try {
      var results = await Promise.all([apiFetch("/api/containers"), loadLabels(), loadReplicas()]);
      var resp = results[0];
      containers = (resp && resp.data) ? resp.data : (Array.isArray(resp) ? resp : []);
      applyReplicaLabels();
      setText(document.getElementById("containerCount"), String(containers.length));
      renderContainers(wrap);
      updateTabTimestamp("containers");
    } catch(err) {
      wrap.innerHTML = "";
      var em = document.createElement("div");
      em.className = "empty-state";
      var p = document.createElement("p");
      setText(p, "Failed to load containers: " + err.message);
      em.appendChild(p);
      wrap.appendChild(em);
    }
  }

  function getSiteDomains() {
    var d = {};
    mappings.mapped.forEach(function(m) {
      d[m.container_name] = m.nginx_domain || true;
    });
    return d;
  }

  function replicasByParentName() {
    var byParent = {};
    containerReplicas.forEach(function(r) {
      var p = r.parent_name || "";
      if (!byParent[p]) byParent[p] = [];
      byParent[p].push(r);
    });
    Object.keys(byParent).forEach(function(k) {
      byParent[k].sort(function(a,b) { return String(a.name).localeCompare(String(b.name)); });
    });
    return byParent;
  }

  function replicaNameSet() {
    var set = {};
    containerReplicas.forEach(function(r) { if (r.name) set[r.name] = true; });
    return set;
  }

  function containerForReplica(replica) {
    return {
      id: replica.container_id || "",
      name: replica.name,
      image: "",
      status: replica.status || "",
      ports: [{
        host_port: String(replica.host_port || ""),
        container_port: String(replica.container_port || ""),
        protocol: replica.protocol || "tcp"
      }]
    };
  }

  function associateButtonText(templateType) {
    switch (templateType) {
      case "api": return "Associate API";
      case "nestjs": return "Associate NestJS";
      case "nextjs": return "Associate Next.js";
      case "frontend": return "Associate Frontend";
      case "minio": return "Associate MinIO";
      case "gd-app": return "Associate GD-App";
      default: return "Associate Site";
    }
  }

  function openSitesTab() {
    var btn = document.querySelector('.tab-btn[data-tab="sites"]');
    if (btn) {
      btn.click();
    } else {
      loadSites();
    }
  }

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
    var siteDomains = getSiteDomains();
    var tw = document.createElement("div");
    tw.className = "table-wrap";
    var table = document.createElement("table");

    var thead = document.createElement("thead");
    var trh = document.createElement("tr");
    ["Name", "Image", "Status", "Ports", "Label", "Actions"].forEach(function(h) {
      var th = document.createElement("th");
      setText(th, h);
      trh.appendChild(th);
    });
    thead.appendChild(trh);
    table.appendChild(thead);

    var tbody = document.createElement("tbody");
    var repsByParent = replicasByParentName();
    var replicaNames = replicaNameSet();
    containers.forEach(function(c) {
      if (replicaNames[c.name]) return;
      var tr = document.createElement("tr");

      // Name
      var tdName = document.createElement("td");
      var nameStrong = document.createElement("strong");
      setText(nameStrong, c.name);
      tdName.appendChild(nameStrong);
      tr.appendChild(tdName);

      // Image
      var tdImg = document.createElement("td");
      var imgCode = document.createElement("span");
      imgCode.style.color = "var(--text-secondary)";
      imgCode.style.fontFamily = '"SF Mono","Fira Code",monospace';
      imgCode.style.fontSize = "0.8125rem";
      setText(imgCode, c.image);
      tdImg.appendChild(imgCode);
      tr.appendChild(tdImg);

      // Status
      var tdStatus = document.createElement("td");
      var statusKey = (c.status || "").toLowerCase();
      var badgeClass = "badge-created";
      if (statusKey.indexOf("running") !== -1) badgeClass = "badge-running";
      else if (statusKey.indexOf("exited") !== -1 || statusKey.indexOf("stopped") !== -1) badgeClass = "badge-stopped";
      else if (statusKey.indexOf("restarting") !== -1) badgeClass = "badge-restarting";
      var badge = document.createElement("span");
      badge.className = "badge " + badgeClass;
      var dot = document.createElement("span");
      dot.className = "badge-dot";
      badge.appendChild(dot);
      var statusText = document.createTextNode(" " + c.status);
      badge.appendChild(statusText);
      tdStatus.appendChild(badge);
      tr.appendChild(tdStatus);

      // Ports — distinguish "published to host" from "exposed only".
      // Exposed-only ports (declared in Dockerfile EXPOSE but not bound
      // with `-p host:container`) cannot be reached from nginx-on-host;
      // we colour them amber and surface a warning so the operator sees
      // the gap before clicking Associate Site.
      var tdPorts = document.createElement("td");
      var anyExposedOnly = false;
      if (c.ports && c.ports.length) {
        c.ports.forEach(function(p) {
          var ptag = document.createElement("span");
          ptag.className = "port-tag";
          if (p.host_port) {
            setText(ptag, p.host_port + ":" + p.container_port + "/" + p.protocol);
          } else {
            anyExposedOnly = true;
            ptag.style.background = "rgba(210,153,34,0.15)";
            ptag.style.color = "#d29922";
            ptag.title = "Exposed by the container but not published to the host. Nginx running on the host cannot reach this directly — redeploy the container with `-p <host>:<container>`.";
            setText(ptag, "exposed " + p.container_port + "/" + p.protocol);
          }
          tdPorts.appendChild(ptag);
        });
      }
      if (!c.ports || !c.ports.length) {
        var noPort = document.createElement("span");
        noPort.style.color = "var(--text-muted)";
        setText(noPort, "None");
        tdPorts.appendChild(noPort);
      } else if (anyExposedOnly) {
        var warn = document.createElement("div");
        warn.style.fontSize = "0.66rem";
        warn.style.color = "#d29922";
        warn.style.marginTop = "3px";
        setText(warn, "⚠ no host port published");
        tdPorts.appendChild(warn);
      }
      tr.appendChild(tdPorts);

      // Label
      var currentLabel = containerLabels[c.name] || "";
      var tdLabel = document.createElement("td");
      var labelDiv = document.createElement("div");
      labelDiv.className = "label-selector";

      ["api", "nestjs", "nextjs", "frontend", "minio", "gd-app", "back"].forEach(function(lbl) {
        var btn = document.createElement("button");
        btn.className = "label-btn" + (currentLabel === lbl ? " active-" + lbl : "");
        setText(btn, lbl);
        btn.title = currentLabel === lbl ? "Click to remove label" : "Set label to " + lbl;
        (function(containerName, label, isActive) {
          btn.addEventListener("click", function() {
            if (isActive) {
              removeContainerLabel(containerName);
            } else {
              setContainerLabel(containerName, label);
            }
          });
        })(c.name, lbl, currentLabel === lbl);
        labelDiv.appendChild(btn);
      });
      tdLabel.appendChild(labelDiv);
      tr.appendChild(tdLabel);

      // Actions (based on label)
      var tdAct = document.createElement("td");
      tdAct.className = "actions-cell";

      // Logs button — always available regardless of label/state.
      var logsBtn = document.createElement("button");
      logsBtn.className = "btn btn-sm btn-outline";
      logsBtn.style.marginRight = "0.5rem";
      setText(logsBtn, "Logs");
      logsBtn.title = "View last 10 log lines";
      (function(container) {
        logsBtn.addEventListener("click", function() {
          openContainerLogsModal(container);
        });
      })(c);
      tdAct.appendChild(logsBtn);

      var reloadEnvBtn = document.createElement("button");
      reloadEnvBtn.className = "btn btn-sm btn-outline";
      reloadEnvBtn.style.marginRight = "0.5rem";
      setText(reloadEnvBtn, "Reload env");
      reloadEnvBtn.title = "Recreate this container with a selected managed app environment file.";
      (function(container) {
        reloadEnvBtn.addEventListener("click", function() {
          reloadContainerEnv(container);
        });
      })(c);
      tdAct.appendChild(reloadEnvBtn);

      var replicaBtn = document.createElement("button");
      replicaBtn.className = "btn btn-sm btn-outline";
      replicaBtn.style.marginRight = "0.5rem";
      setText(replicaBtn, "Create replica");
      replicaBtn.disabled = (repsByParent[c.name] || []).length >= 3;
      replicaBtn.title = replicaBtn.disabled ? "Maximum 3 replicas reached" : "Clone this container into an independent replica";
      (function(container) {
        replicaBtn.addEventListener("click", function() {
          openReplicaModal(container);
        });
      })(c);
      tdAct.appendChild(replicaBtn);

      if (siteDomains[c.name]) {
        // Already has a site linked. The mapper detected a nginx site whose
        // proxy_pass targets one of this container's published host ports,
        // so showing the "Associate" button would be wrong (the user already
        // associated it).
        var linked = document.createElement("span");
        linked.className = "badge badge-info";
        setText(linked, "Asociado");
        // Show the domain on hover for context without cluttering the cell.
        // setText / textContent paths keep this XSS-safe even if a malicious
        // nginx config name somehow surfaced in the domain field.
        var linkedDom = siteDomains[c.name];
        if (typeof linkedDom === "string" && linkedDom) {
          linked.title = "Sitio nginx asociado: " + linkedDom;
        }
        tdAct.appendChild(linked);
        // If gd-app, show Deactivate button next to the badge
        if (currentLabel === "gd-app") {
          var deactBtn = document.createElement("button");
          deactBtn.className = "btn btn-sm btn-danger";
          deactBtn.style.marginLeft = "0.5rem";
          setText(deactBtn, "Deactivate");
          (function(containerName, linkedDomain) {
            deactBtn.addEventListener("click", function() {
              confirmAction("Deactivate GD-App", "This will remove the nginx config, SSL certificate, and all site configuration for " + linkedDomain + ". Continue?", function() {
                runStreamedOperation(
                  "/api/gdapp/deactivate",
                  { domain: linkedDomain },
                  "Deactivating GD-App",
                  "Removing all configuration for " + linkedDomain
                );
              });
            });
          })(c.name, siteDomains[c.name]);
          tdAct.appendChild(deactBtn);
        }
      } else if (currentLabel === "api") {
        // API label → Associate API button
        var apiBtn = document.createElement("button");
        apiBtn.className = "btn btn-sm btn-primary";
        setText(apiBtn, "Associate API");
        apiBtn.addEventListener("click", function() { openAssociateModal(c, "api"); });
        tdAct.appendChild(apiBtn);
      } else if (currentLabel === "nestjs") {
        // NestJS label → Associate Site button
        var nestBtn = document.createElement("button");
        nestBtn.className = "btn btn-sm btn-success";
        setText(nestBtn, "Associate Site");
        nestBtn.addEventListener("click", function() { openAssociateModal(c, "nestjs"); });
        tdAct.appendChild(nestBtn);
      } else if (currentLabel === "nextjs") {
        // Next.js label → Associate Next.js button
        var nextBtn = document.createElement("button");
        nextBtn.className = "btn btn-sm";
        nextBtn.style.background = "rgba(255,255,255,0.15)";
        nextBtn.style.color = "#fff";
        nextBtn.style.border = "1px solid rgba(255,255,255,0.3)";
        setText(nextBtn, "Associate Next.js");
        nextBtn.addEventListener("click", function() { openAssociateModal(c, "nextjs"); });
        tdAct.appendChild(nextBtn);
      } else if (currentLabel === "frontend") {
        // Frontend label → Associate Frontend button
        var frontBtn = document.createElement("button");
        frontBtn.className = "btn btn-sm";
        frontBtn.style.background = "rgba(255,165,0,0.15)";
        frontBtn.style.color = "#ffa500";
        frontBtn.style.border = "1px solid rgba(255,165,0,0.3)";
        setText(frontBtn, "Associate Frontend");
        frontBtn.addEventListener("click", function() { openAssociateModal(c, "frontend"); });
        tdAct.appendChild(frontBtn);
      } else if (currentLabel === "minio") {
        // MinIO label → Associate MinIO site
        var minioBtn = document.createElement("button");
        minioBtn.className = "btn btn-sm";
        minioBtn.style.background = "rgba(239,83,80,0.15)";
        minioBtn.style.color = "#ef5350";
        minioBtn.style.border = "1px solid rgba(239,83,80,0.3)";
        setText(minioBtn, "Associate MinIO");
        minioBtn.addEventListener("click", function() { openAssociateModal(c, "minio"); });
        tdAct.appendChild(minioBtn);
      } else if (currentLabel === "gd-app") {
        // GD-App label → Activate Site (full flow with SSL)
        var gdBtn = document.createElement("button");
        gdBtn.className = "btn btn-sm";
        gdBtn.style.background = "rgba(138,43,226,0.15)";
        gdBtn.style.color = "#8a2be2";
        gdBtn.style.border = "1px solid rgba(138,43,226,0.3)";
        setText(gdBtn, "Activate Site");
        (function(container) {
          gdBtn.addEventListener("click", function() {
            openGDAppActivateModal(container);
          });
        })(c);
        tdAct.appendChild(gdBtn);
      } else if (currentLabel === "back") {
        // Backend label → no action, show badge
        var backBadge = document.createElement("span");
        backBadge.className = "label-badge label-badge-back";
        setText(backBadge, "Backend");
        tdAct.appendChild(backBadge);
      } else {
        // No label → treat as backend (no action buttons)
        var backBadge2 = document.createElement("span");
        backBadge2.className = "label-badge label-badge-back";
        setText(backBadge2, "Backend");
        tdAct.appendChild(backBadge2);
      }
      tr.appendChild(tdAct);

      tbody.appendChild(tr);
      (repsByParent[c.name] || []).forEach(function(replica) {
        tbody.appendChild(renderReplicaRow(replica));
      });
    });
    table.appendChild(tbody);
    tw.appendChild(table);
    wrap.appendChild(tw);
  }

  function renderReplicaRow(replica) {
    var tr = document.createElement("tr");
    tr.style.background = "rgba(88,166,255,0.045)";

    var tdName = document.createElement("td");
    tdName.style.paddingLeft = "1.6rem";
    var strong = document.createElement("strong");
    setText(strong, (replica.name || "") + " \u2190 " + (replica.parent_name || ""));
    tdName.appendChild(strong);
    if (replica.alias) {
      var alias = document.createElement("div");
      alias.style.fontSize = "0.7rem";
      alias.style.color = "var(--accent)";
      setText(alias, "label: " + replica.alias + " · template: " + (replica.template_type || "back"));
      tdName.appendChild(alias);
    }
    tr.appendChild(tdName);

    var tdImg = document.createElement("td");
    var sync = document.createElement("span");
    sync.className = replica.outdated ? "badge badge-stopped" : "badge badge-running";
    setText(sync, replica.outdated ? "Desactualizada" : "Sincronizada");
    tdImg.appendChild(sync);
    tr.appendChild(tdImg);

    var tdStatus = document.createElement("td");
    var badge = document.createElement("span");
    badge.className = (replica.status === "running") ? "badge badge-running" : "badge badge-created";
    var dot = document.createElement("span");
    dot.className = "badge-dot";
    badge.appendChild(dot);
    badge.appendChild(document.createTextNode(" " + (replica.status || "unknown")));
    tdStatus.appendChild(badge);
    tr.appendChild(tdStatus);

    var tdPorts = document.createElement("td");
    var ptag = document.createElement("span");
    ptag.className = "port-tag";
    setText(ptag, String(replica.host_port || "?") + ":" + String(replica.container_port || "?") + "/" + (replica.protocol || "tcp"));
    tdPorts.appendChild(ptag);
    if (replica.domain) {
      var dom = document.createElement("div");
      dom.style.fontSize = "0.68rem";
      dom.style.color = "var(--text-muted)";
      setText(dom, replica.domain);
      tdPorts.appendChild(dom);
    }
    tr.appendChild(tdPorts);

    var tdLabel = document.createElement("td");
    tdLabel.appendChild(renderReplicaLabelSelector(replica));
    tr.appendChild(tdLabel);

    var tdAct = document.createElement("td");
    tdAct.className = "actions-cell";

    var logsBtn = document.createElement("button");
    logsBtn.className = "btn btn-sm btn-outline";
    logsBtn.style.marginRight = "0.5rem";
    setText(logsBtn, "Logs");
    logsBtn.disabled = !replica.container_id;
    logsBtn.addEventListener("click", function() { openContainerLogsModal(containerForReplica(replica)); });
    tdAct.appendChild(logsBtn);

    var reloadEnvBtn = document.createElement("button");
    reloadEnvBtn.className = "btn btn-sm btn-outline";
    reloadEnvBtn.style.marginRight = "0.5rem";
    setText(reloadEnvBtn, "Reload env");
    reloadEnvBtn.disabled = !replica.container_id;
    reloadEnvBtn.title = "Recreate this replica with a selected managed app environment file.";
    reloadEnvBtn.addEventListener("click", function() { reloadContainerEnv(containerForReplica(replica)); });
    tdAct.appendChild(reloadEnvBtn);

    var replicaTemplate = replica.template_type || "back";
    if (replicaTemplate !== "back") {
      var assocBtn = document.createElement("button");
      assocBtn.className = "btn btn-sm btn-primary";
      assocBtn.style.marginRight = "0.5rem";
      setText(assocBtn, replica.domain ? "Manage Site" : associateButtonText(replicaTemplate));
      assocBtn.addEventListener("click", function() {
        if (replica.domain) {
          openSitesTab(containerForReplica(replica));
        } else {
          openAssociateModal(containerForReplica(replica), replicaTemplate || "api");
        }
      });
      tdAct.appendChild(assocBtn);
    }

    var syncBtn = document.createElement("button");
    syncBtn.className = "btn btn-sm btn-warning";
    syncBtn.style.marginRight = "0.5rem";
    setText(syncBtn, "Sync with parent");
    syncBtn.addEventListener("click", function() { syncReplica(replica); });
    tdAct.appendChild(syncBtn);

    var delBtn = document.createElement("button");
    delBtn.className = "btn btn-sm btn-danger";
    setText(delBtn, "Delete");
    delBtn.addEventListener("click", function() { deleteReplica(replica); });
    tdAct.appendChild(delBtn);

    tr.appendChild(tdAct);
    return tr;
  }

  function renderReplicaLabelSelector(replica) {
    var labelDiv = document.createElement("div");
    labelDiv.className = "label-selector";
    var currentTemplate = replica.template_type || "back";
    ["api", "nestjs", "nextjs", "frontend", "minio", "gd-app", "back"].forEach(function(lbl) {
      var btn = document.createElement("button");
      btn.className = "label-btn" + (currentTemplate === lbl ? " active-" + lbl : "");
      setText(btn, lbl);
      btn.title = currentTemplate === lbl ? "Replica already uses " + lbl : "Set replica template to " + lbl;
      (function(replicaRef, templateType, isActive) {
        btn.addEventListener("click", function() {
          if (isActive) return;
          setReplicaTemplate(replicaRef, templateType);
        });
      })(replica, lbl, currentTemplate === lbl);
      labelDiv.appendChild(btn);
    });
    return labelDiv;
  }

  async function setReplicaTemplate(replica, templateType) {
    try {
      await apiFetch("/api/container-replicas/update", {
        method: "POST",
        body: {
          name: replica.name,
          alias: replica.alias || "replica",
          template_type: templateType
        }
      });
      showToast("Replica label set to " + templateType + ": " + replica.name, "success");
      await Promise.all([loadReplicas(), loadMappings(), loadSites(), loadContainers()]);
    } catch(err) {
      showToast("Failed to update replica label: " + err.message, "error");
    }
  }

  function envArrayToMap(env) {
    var out = {};
    (env || []).forEach(function(e) {
      if (!e || !e.key) return;
      out[e.key] = {
        key: e.key,
        value: e.value || "",
        sensitive: !!e.sensitive
      };
    });
    return out;
  }

  function envFingerprint(env) {
    return (env || []).map(function(e) {
      return (e.key || "") + "=" + (e.value || "");
    }).sort().join("\n");
  }

  function envDisplayValue(entry) {
    if (!entry) return "(missing)";
    if (entry.sensitive) return "******";
    return entry.value === "" ? "(empty)" : entry.value;
  }

  function renderReplicaSyncEnv(parentEnv, replicaEnv) {
    var panel = document.getElementById("replicaEnvSyncPanel");
    panel.innerHTML = "";
    panel.style.display = "block";

    parentEnv = parentEnv || [];
    replicaEnv = replicaEnv || [];
    var identical = envFingerprint(parentEnv) === envFingerprint(replicaEnv);

    var toolbar = document.createElement("div");
    toolbar.style.display = "flex";
    toolbar.style.flexWrap = "wrap";
    toolbar.style.gap = "8px";
    toolbar.style.alignItems = "center";
    toolbar.style.marginBottom = "10px";

    var status = document.createElement("span");
    status.className = identical ? "badge badge-running" : "badge badge-warning";
    setText(status, identical ? "Env iguales" : "Env diferentes");
    toolbar.appendChild(status);

    var keepBtn = document.createElement("button");
    keepBtn.type = "button";
    keepBtn.className = "btn btn-sm btn-outline";
    setText(keepBtn, "Conservar actual");
    toolbar.appendChild(keepBtn);

    var parentBtn = document.createElement("button");
    parentBtn.type = "button";
    parentBtn.className = "btn btn-sm btn-primary";
    setText(parentBtn, "Tomar del padre");
    toolbar.appendChild(parentBtn);
    panel.appendChild(toolbar);

    var compare = document.createElement("div");
    compare.style.border = "1px solid var(--border)";
    compare.style.borderRadius = "6px";
    compare.style.overflow = "hidden";
    compare.style.marginBottom = "10px";

    var header = document.createElement("div");
    header.style.display = "grid";
    header.style.gridTemplateColumns = "150px 1fr 1fr 90px";
    header.style.gap = "8px";
    header.style.padding = "6px 8px";
    header.style.borderBottom = "1px solid var(--border)";
    header.style.background = "var(--bg-input)";
    header.style.fontSize = "0.68rem";
    header.style.fontWeight = "700";
    ["KEY", "REPLICA ACTUAL", "PADRE", "ESTADO"].forEach(function(text) {
      var cell = document.createElement("div");
      cell.style.color = "var(--text-muted)";
      setText(cell, text);
      header.appendChild(cell);
    });
    compare.appendChild(header);

    var currentMap = envArrayToMap(replicaEnv);
    var parentMap = envArrayToMap(parentEnv);
    var keys = {};
    Object.keys(currentMap).forEach(function(k) { keys[k] = true; });
    Object.keys(parentMap).forEach(function(k) { keys[k] = true; });
    Object.keys(keys).sort().forEach(function(key) {
      var row = document.createElement("div");
      row.style.display = "grid";
      row.style.gridTemplateColumns = "150px 1fr 1fr 90px";
      row.style.gap = "8px";
      row.style.padding = "6px 8px";
      row.style.borderBottom = "1px solid var(--border)";
      row.style.fontSize = "0.72rem";

      var cur = currentMap[key];
      var par = parentMap[key];
      var same = !!cur && !!par && cur.value === par.value;
      [key, envDisplayValue(cur), envDisplayValue(par), same ? "igual" : "cambia"].forEach(function(text, idx) {
        var cell = document.createElement("div");
        cell.style.color = idx === 3 ? (same ? "var(--green)" : "#d29922") : "var(--text-secondary)";
        if (idx === 0) {
          cell.style.color = "var(--text-primary)";
          cell.style.fontFamily = '"SF Mono","Fira Code",monospace';
        }
        setText(cell, text);
        row.appendChild(cell);
      });
      compare.appendChild(row);
    });
    if (compare.children.length === 1) {
      var empty = document.createElement("div");
      empty.style.padding = "8px";
      empty.style.color = "var(--text-muted)";
      setText(empty, "No environment variables found on replica or parent.");
      compare.appendChild(empty);
    }
    panel.appendChild(compare);

    var selectedLabel = document.createElement("div");
    selectedLabel.style.fontSize = "0.72rem";
    selectedLabel.style.color = "var(--text-muted)";
    selectedLabel.style.margin = "8px 0 6px";
    panel.appendChild(selectedLabel);

    function choose(which) {
      var chosen = which === "parent" ? parentEnv : replicaEnv;
      keepBtn.className = which === "current" ? "btn btn-sm btn-primary" : "btn btn-sm btn-outline";
      parentBtn.className = which === "parent" ? "btn btn-sm btn-primary" : "btn btn-sm btn-outline";
      setText(selectedLabel, which === "parent" ? "Environment selected: parent" : "Environment selected: current replica");
      if (replicaEnvEditor) {
        replicaEnvEditor.setFromEntries(chosen);
      }
    }

    keepBtn.addEventListener("click", function() { choose("current"); });
    parentBtn.addEventListener("click", function() { choose("parent"); });
    choose(identical ? "parent" : "current");
  }

  function clearReplicaSyncPanel() {
    var panel = document.getElementById("replicaEnvSyncPanel");
    if (panel) {
      panel.innerHTML = "";
      panel.style.display = "none";
    }
  }

  function renderReplicaEnv(env) {
    clearReplicaSyncPanel();
    if (replicaEnvEditor) {
      replicaEnvEditor.setFromEntries(env || []);
    }
  }

  function collectReplicaEnv() {
    if (!replicaEnvEditor) return [];
    var errors = replicaEnvEditor.validate();
    if (errors.length) {
      showToast(errors[0], "error");
      return null;
    }
    return replicaEnvEditor.getEnvArray();
  }

  function renderReplicaMounts(mounts) {
    var box = document.getElementById("replicaMountSummary");
    box.innerHTML = "";
    if (!mounts || !mounts.length) {
      setText(box, "No persistent mounts detected. The replica will use the committed filesystem snapshot.");
      return;
    }
    mounts.forEach(function(m) {
      var line = document.createElement("div");
      line.style.color = m.supported ? "var(--text-muted)" : "#f85149";
      setText(line, (m.supported ? "✓ " : "⚠ ") + m.type + " " + m.destination + " will be copied into an independent replica folder");
      box.appendChild(line);
    });
  }

  async function openReplicaModal(container) {
    try {
      _replicaMode = "create";
      _replicaSyncName = "";
      var resp = await apiFetch("/api/container-replicas/preview", { method: "POST", body: { parent_id: container.id } });
      _replicaPreview = (resp && resp.data) || {};
      if (_replicaPreview.existing_replicas >= _replicaPreview.max_replicas) {
        showToast("This container already has 3 replicas", "error");
        return;
      }
      document.querySelector("#replicaModal h3").textContent = "Create Replica";
      setText(document.getElementById("replicaModalSub"), "Clone \"" + container.name + "\" into an independent container.");
      document.getElementById("replicaParentId").value = container.id;
      document.getElementById("replicaName").value = container.name + "-replica-" + ((_replicaPreview.existing_replicas || 0) + 1);
      document.getElementById("replicaName").disabled = false;
      document.getElementById("replicaAlias").value = "replica";
      document.getElementById("replicaAlias").disabled = false;
      document.getElementById("replicaTemplate").value = _replicaPreview.template_type || "api";
      document.getElementById("replicaTemplate").disabled = false;
      setText(document.getElementById("replicaSubmitBtn"), "Create Replica");
      renderReplicaEnv(_replicaPreview.env || []);
      renderReplicaMounts(_replicaPreview.mounts || []);
      document.getElementById("replicaModal").classList.add("show");
    } catch(err) {
      showToast("Failed to inspect parent: " + err.message, "error");
    }
  }

  async function openReplicaSyncModal(replica) {
    try {
      _replicaMode = "sync";
      _replicaSyncName = replica.name;
      var parent = containers.find(function(c) { return c.name === replica.parent_name || c.id === replica.parent_id; });
      var parentID = parent ? parent.id : replica.parent_id;
      var resp = await apiFetch("/api/container-replicas/preview", { method: "POST", body: { parent_id: parentID, replica_name: replica.name } });
      _replicaPreview = (resp && resp.data) || {};
      document.querySelector("#replicaModal h3").textContent = "Sync Replica";
      setText(document.getElementById("replicaModalSub"), "Reclone \"" + replica.name + "\" from parent \"" + replica.parent_name + "\" using blue-green replacement.");
      document.getElementById("replicaParentId").value = parentID;
      document.getElementById("replicaName").value = replica.name;
      document.getElementById("replicaName").disabled = true;
      document.getElementById("replicaAlias").value = replica.alias || "";
      document.getElementById("replicaAlias").disabled = true;
      document.getElementById("replicaTemplate").value = replica.template_type || "api";
      document.getElementById("replicaTemplate").disabled = true;
      setText(document.getElementById("replicaSubmitBtn"), "Sync Replica");
      renderReplicaSyncEnv(_replicaPreview.env || [], _replicaPreview.replica_env || []);
      renderReplicaMounts(_replicaPreview.mounts || []);
      document.getElementById("replicaModal").classList.add("show");
    } catch(err) {
      showToast("Failed to inspect parent: " + err.message, "error");
    }
  }

  function syncReplica(replica) {
    openReplicaSyncModal(replica);
  }

  function deleteReplica(replica) {
    confirmAction("Delete Replica", "Remove replica " + replica.name + ", its Nginx sites, SSL certificate if present, snapshot image, port reservation, and independent data folder?", function() {
      runStreamedOperation("/api/container-replicas/delete", { name: replica.name }, "Deleting Replica", replica.name);
    });
  }

  onEl("replicaCancelBtn", "click", function() {
    document.getElementById("replicaModal").classList.remove("show");
  });

  onEl("replicaModal", "click", function(e) {
    if (e.target === document.getElementById("replicaModal")) {
      document.getElementById("replicaModal").classList.remove("show");
    }
  });

  onEl("replicaForm", "submit", function(e) {
    e.preventDefault();
    var env = collectReplicaEnv();
    if (env === null) return;
    document.getElementById("replicaModal").classList.remove("show");
    if (_replicaMode === "sync") {
      runStreamedOperation("/api/container-replicas/sync", {
        name: _replicaSyncName,
        env: env
      }, "Syncing Replica", _replicaSyncName + " — blue-green replacement");
      return;
    }
    runStreamedOperation("/api/container-replicas/create", {
      parent_id: document.getElementById("replicaParentId").value,
      name: document.getElementById("replicaName").value.trim(),
      alias: document.getElementById("replicaAlias").value.trim(),
      template_type: document.getElementById("replicaTemplate").value,
      env: env
    }, "Creating Replica", document.getElementById("replicaName").value.trim());
  });

  // ── Sites ──
  async function loadSites() {
