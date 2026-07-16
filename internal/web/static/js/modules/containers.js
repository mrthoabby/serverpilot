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
      if (typeof window.loadContainers === "function") {
        window.loadContainers();
      }
    } catch(err) {
      showToast("Failed to set label: " + err.message, "error");
    }
  }

  async function removeContainerLabel(containerName) {
    try {
      await apiFetch("/api/labels/remove", { method: "POST", body: { container_name: containerName } });
      delete containerLabels[containerName];
      showToast("Label removed for " + containerName, "success");
      if (typeof window.loadContainers === "function") {
        window.loadContainers();
      }
    } catch(err) {
      showToast("Failed to remove label: " + err.message, "error");
    }
  }

  async function loadContainers() {
    if (typeof window.__spLoadContainers === "function") {
      return window.__spLoadContainers();
    }
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
