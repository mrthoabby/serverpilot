/* GCP firewall settings */
"use strict";

  // Check on first load of Users tab whether gcloud is available.
  var _gcloudChecked = false;

  // Patch loadDeployUsers to also check gcloud on first call.
  var _origLoadDeployUsers = loadDeployUsers;
  loadDeployUsers = function() {
    _origLoadDeployUsers();
    if (!_gcloudChecked) {
      _gcloudChecked = true;
      apiFetch("/api/gcloud/status").then(function(data) {
        if (data && data.success && data.data && data.data.available) {
          document.getElementById("gcloudSection").style.display = "block";
          var projEl = document.getElementById("gcloudProject");
          if (projEl && data.data.project) {
            projEl.textContent = "Project: " + data.data.project;
          }
          loadFirewallRules();
        }
      }).catch(function() {});
    }
  };

  function loadFirewallRules() {
    var wrap = document.getElementById("fwRulesContent");
    if (!wrap) return;

    apiFetch("/api/gcloud/firewall").then(function(data) {
      if (!data || !data.success) {
        wrap.innerHTML = '<div style="color:var(--text-muted);font-size:0.82rem;">Failed to load rules</div>';
        return;
      }
      var rules = data.data || [];
      if (rules.length === 0) {
        wrap.innerHTML = '<div style="color:var(--text-muted);font-size:0.82rem;">No firewall rules found</div>';
        return;
      }

      var html = '<div class="table-wrap"><table style="font-size:0.82rem;"><thead><tr>' +
        '<th>Rule Name</th><th>Direction</th><th>Allowed</th><th>Source</th><th>Status</th><th style="width:70px;"></th>' +
        '</tr></thead><tbody>';

      rules.forEach(function(r) {
        var isSP = r.name.indexOf("sp-") === 0;
        var statusBadge = r.disabled
          ? '<span class="badge badge-stopped"><span class="badge-dot"></span> disabled</span>'
          : '<span class="badge badge-running"><span class="badge-dot"></span> active</span>';
        var deleteBtn = isSP
          ? '<button onclick="closeFirewallRule(\'' + escapeHtml(r.name) + '\')" class="btn btn-secondary" style="padding:2px 8px;font-size:0.72rem;border-color:#f8514966;color:#f85149;" title="Delete rule">' +
              '<svg width="10" height="10" viewBox="0 0 16 16" fill="none" style="vertical-align:-1px;"><path d="M4 4l8 8M12 4l-8 8" stroke="#f85149" stroke-width="1.5" stroke-linecap="round"/></svg> Close' +
            '</button>'
          : '<span style="font-size:0.7rem;color:var(--text-muted);">external</span>';
        html += '<tr>' +
          '<td><code style="font-size:0.78rem;">' + escapeHtml(r.name) + '</code></td>' +
          '<td>' + escapeHtml(r.direction || "INGRESS") + '</td>' +
          '<td>' + escapeHtml(r.allowed) + '</td>' +
          '<td style="font-family:monospace;font-size:0.78rem;">' + escapeHtml(r.source_ranges || "—") + '</td>' +
          '<td>' + statusBadge + '</td>' +
          '<td style="text-align:center;">' + deleteBtn + '</td>' +
          '</tr>';
      });

      html += '</tbody></table></div>';
      wrap.innerHTML = html;
    }).catch(function() {
      wrap.innerHTML = '<div style="color:#f85149;font-size:0.82rem;">Error loading firewall rules</div>';
    });
  }

  function openFirewallPort() {
    var portEl = document.getElementById("fwPort");
    var srcEl = document.getElementById("fwSource");
    var msgEl = document.getElementById("fwMsg");
    var btn = document.getElementById("btnFwOpen");
    var port = parseInt(portEl.value, 10);
    var source = srcEl.value.trim() || "0.0.0.0/0";

    if (!port || port < 1 || port > 65535) { msgEl.style.color = "#f85149"; msgEl.textContent = "Invalid port"; return; }

    btn.disabled = true;
    msgEl.style.color = "var(--text-muted)";
    msgEl.textContent = "Opening...";

    apiFetch("/api/gcloud/firewall/open", {
      method: "POST",
      body: { port: port, source: source }
    }).then(function(data) {
      btn.disabled = false;
      if (data && data.success) {
        msgEl.style.color = "#3fb950";
        msgEl.textContent = "Port " + port + " opened!";
        portEl.value = "";
        loadFirewallRules();
        setTimeout(function() { msgEl.textContent = ""; }, 4000);
      } else {
        msgEl.style.color = "#f85149";
        msgEl.textContent = (data && data.error) || "Failed";
      }
    }).catch(function() {
      btn.disabled = false;
      msgEl.style.color = "#f85149";
      msgEl.textContent = "Connection error";
    });
  }

  function closeFirewallRule(name) {
    if (!confirm("Delete firewall rule '" + name + "'?\nThis will close the port.")) return;

    apiFetch("/api/gcloud/firewall/close", {
      method: "POST",
      body: { name: name }
    }).then(function(data) {
      if (data && data.success) {
        loadFirewallRules();
      } else {
        alert("Error: " + ((data && data.error) || "Failed to delete rule"));
      }
    }).catch(function() { alert("Connection error"); });
  }

  window.loadFirewallRules       = loadFirewallRules;
  window.openFirewallPort        = openFirewallPort;
  window.closeFirewallRule       = closeFirewallRule;
