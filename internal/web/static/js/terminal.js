(function() {
  "use strict";

  var termWS      = null;
  var termInst    = null;
  var fitAddon    = null;
  var termReady   = false;
  var termWSRetries = 0;
  var termProxyOK = null;
  var termAccessKeyData = null;
  var termInstallCommand = "curl -fsSL https://raw.githubusercontent.com/mrthoabby/serverpilot/master/install.sh | sh\nsudo sp setup\nsudo sp start -d";
  var sshWS = null;
  var sshInst = null;
  var sshFitAddon = null;
  var sshReady = false;

  function termShowFixProxy(show, hint) {
    var btn = document.getElementById("termFixProxyBtn");
    if (btn) btn.style.display = show ? "" : "none";
    termShowTerminalHint(show && hint, hint);
  }

  function termShowTerminalHint(show, hint) {
    var hintEl = document.getElementById("termFixProxyHint");
    if (hintEl) {
      hintEl.style.display = show && hint ? "" : "none";
      if (hint) hintEl.textContent = hint;
    }
  }

  function termShowConfigButtons(opts) {
    opts = opts || {};
    var settingsBtn = document.getElementById("termSettingsBtn");
    var openBtn = document.getElementById("termOpenDomainBtn");
    var sslBtn = document.getElementById("termEnableSSLBtn");
    if (settingsBtn) settingsBtn.style.display = opts.settings ? "" : "none";
    if (openBtn) {
      openBtn.style.display = opts.openDomain ? "" : "none";
      openBtn.dataset.url = opts.dashboardURL || "";
    }
    if (sslBtn) {
      sslBtn.style.display = opts.enableSSL ? "" : "none";
      sslBtn.dataset.domain = opts.configuredDomain || "";
    }
  }

  function termCurrentExternalHost() {
    var host = location.hostname || "";
    return (host && host !== "localhost" && host !== "127.0.0.1" && host !== "::1") ? host : "";
  }

  function termCopyText(text, label) {
    function done() {
      termSetStatus((label || "Text") + " copiado", "var(--green)");
      if (typeof window.showToast === "function") window.showToast((label || "Text") + " copiado", "success");
    }
    function failed() {
      termSetStatus("No se pudo copiar " + (label || "el texto"), "var(--red)");
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done).catch(failed);
      return;
    }
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    try { document.execCommand("copy") ? done() : failed(); }
    catch(e) { failed(); }
    finally { document.body.removeChild(ta); }
  }

  function termShowAccessKeyPanel(show) {
    var panel = document.getElementById("termAccessKeyPanel");
    if (panel) panel.style.display = show ? "" : "none";
  }

  function termSetAccessKey(data, loadingText) {
    var publicEl = document.getElementById("termAccessPublicKey");
    var sshEl = document.getElementById("termAccessSSHExample");
    termAccessKeyData = data || null;
    if (publicEl) publicEl.textContent = loadingText || (data && data.public_key) || "(no public key yet)";
    if (sshEl) sshEl.textContent = (data && data.ssh_command) || "ssh -i /root/.ssh/serverpilot_remote_access_ed25519 admin@<server-ip>";
    if (data && data.install_command) termInstallCommand = data.install_command;
  }

  function termLoadAccessKey() {
    var btn = document.getElementById("termAccessKeyBtn");
    if (btn) btn.disabled = true;
    termShowAccessKeyPanel(true);
    termSetAccessKey(null, "Preparing SSH access key…");
    ensureTerminalAuth().then(function() {
      return window.apiFetch("/api/terminal/access-key", { method: "POST" });
    }).then(function(resp) {
      var data = (resp && resp.data) ? resp.data : (resp || {});
      termSetAccessKey(data, "");
      if (data.public_key) {
        termSetStatus(data.generated ? "Access key generada" : "Access key lista", "var(--green)");
      } else {
        termSetStatus("No se pudo obtener la public key", "var(--red)");
      }
    }).catch(function(err) {
      if (err && err.code === "session_expired") {
        termSetStatus("Sesión expirada — inicia sesión de nuevo", "var(--red)");
        if (typeof window.showLogin === "function") window.showLogin();
        return;
      }
      if (err && err.code === "reauth_cancelled") {
        termSetAccessKey(null, "Generación cancelada.");
        termSetStatus("Generación cancelada", "var(--text-muted)");
        return;
      }
      var msg = (err && err.message) ? err.message : "falló";
      termSetAccessKey(null, "No se pudo preparar la access key: " + msg);
      termSetStatus("No se pudo preparar la access key", "var(--red)");
    }).finally(function() {
      if (btn) btn.disabled = false;
    });
  }

  function termOpenSettings(prefillDomain) {
    var btn = document.querySelector('.tab-btn[data-tab="settings"]');
    if (btn) btn.click();
    setTimeout(function() {
      var input = document.getElementById("settingsDomainInput");
      if (input && prefillDomain && !input.value) {
        input.value = prefillDomain;
        input.focus();
      }
    }, 50);
  }

  function termApplyConfigDiag(diag) {
    termShowConfigButtons({});
    termShowTerminalHint(false, "");
    if (!diag) return;

    if (diag.block_reason === "domain_missing") {
      termShowConfigButtons({ settings: true });
      termShowFixProxy(false, "");
      termShowTerminalHint(true, "El dominio del dashboard no está guardado. Configura el dominio antes de usar la terminal por HTTPS.");
      return;
    }

    if (diag.config_warning === "ssl_not_enabled") {
      termShowConfigButtons({
        enableSSL: true,
        configuredDomain: diag.configured_domain || diag.resolved_domain || ""
      });
      termShowTerminalHint(true, "El dashboard se está usando por HTTPS, pero Settings todavía marca SSL como no habilitado.");
      return;
    }

    if (diag.config_warning === "host_mismatch") {
      termShowConfigButtons({
        openDomain: !!diag.dashboard_url,
        dashboardURL: diag.dashboard_url
      });
      termShowTerminalHint(true, "Estás accediendo desde " + (diag.request_host || "otro host") + "; el dominio configurado es " + (diag.configured_domain || "otro") + ".");
    }
  }

  function termShowLogsPanel(show) {
    var panel = document.getElementById("termLogsPanel");
    if (panel) panel.style.display = show ? "" : "none";
  }

  function termSetLogs(command, logs) {
    var cmdEl = document.getElementById("termLogsCommand");
    var body = document.getElementById("termLogsBody");
    if (cmdEl) cmdEl.textContent = command || "journalctl -u serverpilot";
    if (body) body.textContent = logs || "(no logs)";
  }

  function termLoadServiceLogs() {
    var btn = document.getElementById("termLogsBtn");
    var refreshBtn = document.getElementById("termLogsRefreshBtn");
    if (btn) btn.disabled = true;
    if (refreshBtn) refreshBtn.disabled = true;
    termShowLogsPanel(true);
    termSetLogs("journalctl -u serverpilot --lines 120", "Loading logs…");

    ensureTerminalAuth().then(function() {
      return window.apiFetch("/api/terminal/service-logs?tail=120");
    }).then(function(resp) {
      var data = (resp && resp.data) ? resp.data : (resp || {});
      var logs = data.logs || "(no logs)";
      if (data.error) logs = "ERROR: " + data.error + "\n\n" + logs;
      termSetLogs(data.command, logs);
      if (data.ok) {
        termSetStatus("Logs cargados", "var(--green)");
      } else {
        termSetStatus("No se pudieron cargar todos los logs", "var(--red)");
      }
    }).catch(function(err) {
      if (err && err.code === "session_expired") {
        termSetStatus("Sesión expirada — inicia sesión de nuevo", "var(--red)");
        if (typeof window.showLogin === "function") window.showLogin();
        return;
      }
      if (err && err.code === "reauth_cancelled") {
        termSetLogs("journalctl -u serverpilot --lines 120", "Carga de logs cancelada.");
        termSetStatus("Carga de logs cancelada", "var(--text-muted)");
        return;
      }
      var msg = (err && err.message) ? err.message : "falló";
      termSetLogs("journalctl -u serverpilot --lines 120", "No se pudieron cargar los logs: " + msg);
      termSetStatus("No se pudieron cargar los logs", "var(--red)");
    }).finally(function() {
      if (btn) btn.disabled = false;
      if (refreshBtn) refreshBtn.disabled = false;
    });
  }

  function termLoadProxyStatus() {
    if (typeof window.apiFetch !== "function") return Promise.resolve(null);
    return termFetchConnectDiag("proxy-status").then(function(diag) {
      termApplyConfigDiag(diag);
      termProxyOK = !!diag.proxy_ok;
      if (diag.block_reason === "domain_missing") return diag;
      if (!diag.proxy_ok) {
        var msg = diag.proxy_message || "Faltan cabeceras WebSocket en nginx para la terminal";
        if (diag.proxy_missing && diag.proxy_missing.length) {
          msg += " (" + diag.proxy_missing.join(", ") + ")";
        }
        termShowFixProxy(true, msg);
      } else if (!diag.config_warning) {
        termShowFixProxy(false, "");
      }
      return diag;
    }).catch(function(err) {
      if (err && (err.message === "Unauthorized" || err.code === "session_expired")) {
        termSetStatus("Inicia sesión para comprobar el proxy nginx", "var(--red)");
        if (typeof window.showLogin === "function") window.showLogin();
        return null;
      }
      termShowFixProxy(false, "");
      termShowConfigButtons({});
      return null;
    });
  }

  function termFixProxy() {
    var btn = document.getElementById("termFixProxyBtn");
    if (btn) { btn.disabled = true; btn.textContent = "Reparando…"; }
    ensureTerminalAuth().then(function() {
      return window.apiFetch("/api/terminal/fix-proxy", { method: "POST" });
    }).then(function(resp) {
      var st = (resp && resp.data) ? resp.data : (resp || {});
      termProxyOK = !!st.ok;
      if (st.ok) {
        termShowFixProxy(false, "");
        termSetStatus("Proxy nginx reparado — conectando…", "var(--green)");
        termConnect();
      } else {
        var msg = st.message || "No se pudo reparar el proxy";
        termShowFixProxy(true, msg);
        termSetStatus(msg, "var(--red)");
      }
    }).catch(function(err) {
      if (err && err.code === "session_expired") {
        termSetStatus("Sesión expirada — inicia sesión de nuevo", "var(--red)");
        if (typeof window.showLogin === "function") window.showLogin();
        return;
      }
      if (err && err.code === "reauth_cancelled") {
        termSetStatus("Reparación cancelada", "var(--text-muted)");
        return;
      }
      var msg = (err && err.message) ? err.message : "falló";
      termSetStatus("Error al reparar proxy: " + msg, "var(--red)");
      termShowFixProxy(true, "Si sigue fallando: sudo sp expose --domain " + location.hostname + " --upgrade");
    }).finally(function() {
      if (btn) { btn.disabled = false; btn.textContent = "Reparar proxy WebSocket"; }
    });
  }

  function termSetStatus(msg, color) {
    var el = document.getElementById("termStatus");
    if (el) { el.textContent = msg; el.style.color = color || "var(--text-muted)"; }
  }

  function termIsNetworkError(err) {
    if (typeof navigator !== "undefined" && navigator.onLine === false) return true;
    var msg = ((err && err.message) || String(err || "")).toLowerCase();
    return msg.indexOf("failed to fetch") !== -1 ||
           msg.indexOf("network") !== -1 ||
           msg.indexOf("load failed") !== -1 ||
           msg.indexOf("name_not_resolved") !== -1;
  }

  function termSetNetworkFailure() {
    var msg = (typeof navigator !== "undefined" && navigator.onLine === false)
      ? "Sin conexión de red — reconecta e intenta de nuevo"
      : "No se pudo conectar — verifica DNS/conectividad del dominio y vuelve a intentar";
    termSetStatus(msg, "var(--red)");
    termShowFixProxy(false, "");
  }

  function termFetchConnectDiag(phase) {
    return fetch("/api/terminal/ws-check", {
      credentials: "same-origin",
      headers: { "Accept": "application/json" }
    }).then(function(r) {
      return r.json().then(function(j) {
        var d = (j && j.data) ? j.data : (j || {});
        d._phase = phase;
        return d;
      });
    });
  }

  function termExplainConnectBlock(diag) {
    if (!diag) return "No se pudo conectar";
    if (diag.block_reason === "session_expired") return "Sesión expirada — inicia sesión de nuevo";
    if (diag.block_reason === "reauth_required") return "Confirma tu contraseña para usar la terminal";
    if (diag.block_reason === "domain_missing") return "Configura el dominio del dashboard antes de usar la terminal por HTTPS";
    if (diag.block_reason === "nginx_proxy") return diag.proxy_message || "Faltan cabeceras WebSocket en nginx (HTTPS)";
    if (diag.block_reason === "ws_error") {
      var detail = diag.last_ws_reject_reason || "";
      return detail ? "Error del WebSocket: " + detail : "El servidor rechazó la conexión WebSocket";
    }
    if (diag.last_ws_reject_status === 401) return "Sesión expirada — inicia sesión de nuevo";
    if (diag.last_ws_reject_status === 403) return "Reautenticación requerida — introduce tu contraseña";
    return "No se pudo conectar a la terminal";
  }

  function termHandleConnectBlock(diag) {
    if (!diag || diag.can_connect) return false;
    var msg = termExplainConnectBlock(diag);
    termSetStatus(msg, "var(--red)");
    termApplyConfigDiag(diag);
    if (diag.block_reason === "session_expired" || diag.last_ws_reject_status === 401) {
      if (typeof window.showLogin === "function") window.showLogin();
      return true;
    }
    if (diag.block_reason === "reauth_required" || diag.last_ws_reject_status === 403) {
      return true;
    }
    if (diag.block_reason === "domain_missing") {
      return true;
    }
    if (diag.block_reason === "nginx_proxy") {
      termShowFixProxy(true, msg + (diag.proxy_missing && diag.proxy_missing.length ? " (" + diag.proxy_missing.join(", ") + ")" : ""));
      return true;
    }
    if (diag.block_reason === "ws_error") {
      var hint = (diag.last_ws_reject_reason || "") + " — usa Ver logs para revisar el servicio";
      termShowFixProxy(true, hint.trim().replace(/^— /, ""));
      return true;
    }
    return true;
  }

  function termSetConnected(connected) {
    var conn = document.getElementById("termConnectBtn");
    var disc = document.getElementById("termDisconnectBtn");
    if (conn) conn.style.display = connected ? "none" : "";
    if (disc) disc.style.display = connected ? "" : "none";
  }

  function termConnect() {
    if (termWS && termWS.readyState === WebSocket.OPEN) return;

    if (typeof Terminal === "undefined" || typeof FitAddon === "undefined") {
      termSetStatus("Terminal library failed to load — check your network/CDN access", "var(--red)");
      return;
    }

    termSetStatus("Verifying authentication…", "var(--yellow)");
    termWSRetries = 0;

    termFetchConnectDiag("start").then(function(diag) {
      if (diag.block_reason === "session_expired") {
        termHandleConnectBlock(diag);
        return;
      }
      if (diag.block_reason === "reauth_required") {
        if (typeof window.promptReauth !== "function") {
          throw new Error("re-authentication unavailable");
        }
        return window.promptReauth().then(function() {
          return termFetchConnectDiag("after-reauth");
        }).then(function(diag2) {
          if (termHandleConnectBlock(diag2)) return;
          termApplyConfigDiag(diag2);
          termOpenWebSocket();
        });
      }
      if (termHandleConnectBlock(diag)) return;
      termApplyConfigDiag(diag);
      termOpenWebSocket();
    }).catch(function(err) {
      if (termIsNetworkError(err)) {
        termSetNetworkFailure();
        return;
      }
      if (err && err.code === "session_expired") {
        termSetStatus("Sesión expirada — inicia sesión de nuevo", "var(--red)");
        if (typeof window.showLogin === "function") window.showLogin();
        return;
      }
      if (err && err.code === "reauth_cancelled") {
        termSetStatus("Connection cancelled", "var(--text-muted)");
        return;
      }
      termSetStatus("Could not connect — " + (err && err.message ? err.message : "authentication failed"), "var(--red)");
    });
  }

  function ensureTerminalAuth() {
    if (typeof window.apiFetch !== "function") {
      return Promise.reject(new Error("dashboard not ready"));
    }
    return window.apiFetch("/api/session/reauth-status").then(function(resp) {
      var data = resp.data || resp || {};
      if (data.recently_reauthenticated) {
        return;
      }
      if (typeof window.promptReauth !== "function") {
        return Promise.reject(new Error("re-authentication unavailable"));
      }
      return window.promptReauth();
    }).catch(function(err) {
      if (err && err.message === "Unauthorized") {
        var e = new Error("session expired");
        e.code = "session_expired";
        throw e;
      }
      if (err && err.message === "reauthentication cancelled") {
        var cancelled = new Error("cancelled");
        cancelled.code = "reauth_cancelled";
        throw cancelled;
      }
      throw err;
    });
  }

  function termOpenWebSocket() {
    // Initialise xterm.js once.
    if (!termReady) {
      termInst = new Terminal({
        cursorBlink: true,
        fontSize: 14,
        fontFamily: '"Cascadia Code", "Fira Code", "Menlo", monospace',
        theme: {
          background: "#0d1117",
          foreground: "#e6edf3",
          cursor:     "#00b4d8",
          selectionBackground: "rgba(0,180,216,0.3)",
          black:   "#484f58", red:     "#f85149", green:   "#3fb950", yellow: "#d29922",
          blue:    "#388bfd", magenta: "#bc8cff", cyan:    "#39c5cf", white:  "#b1bac4",
          brightBlack:   "#6e7681", brightRed:     "#ff7b72", brightGreen: "#56d364",
          brightYellow:  "#e3b341", brightBlue:    "#79c0ff", brightMagenta:"#d2a8ff",
          brightCyan:    "#56d4dd", brightWhite:   "#f0f6fc"
        },
        allowProposedApi: true
      });
      fitAddon = new FitAddon.FitAddon();
      termInst.loadAddon(fitAddon);
      termInst.open(document.getElementById("terminalContainer"));
      fitAddon.fit();

      // Resize the PTY when the terminal dimensions change.
      termInst.onResize(function(size) {
        if (termWS && termWS.readyState === WebSocket.OPEN) {
          termWS.send(JSON.stringify({ type: "resize", cols: size.cols, rows: size.rows }));
        }
      });

      window.addEventListener("resize", function() {
        if (termReady && fitAddon) fitAddon.fit();
      });

      // Wire keyboard input → WebSocket. Registered once (not per-connect) so
      // reconnects/retries don't attach duplicate handlers that double keystrokes.
      termInst.onData(function(data) {
        if (termWS && termWS.readyState === WebSocket.OPEN) {
          termWS.send(new TextEncoder().encode(data));
        }
      });

      termReady = true;
    }

    var proto = location.protocol === "https:" ? "wss:" : "ws:";
    var url   = proto + "//" + location.host + "/api/terminal/ws";

    termSetStatus("Connecting…", "var(--yellow)");
    termInst.clear();
    termInst.focus();

    var ws = new WebSocket(url);
    ws.binaryType = "arraybuffer";
    termWS = ws;

    // Track whether the socket ever opened. A WebSocket that closes BEFORE
    // opening almost always means the HTTP upgrade was rejected — most often
    // because this route requires a recent re-authentication (403). The browser
    // WebSocket API hides the HTTP status, so we infer it from "closed before open".
    var opened = false;
    var wsHadError = false;

    ws.onopen = function() {
      opened = true;
      termWSRetries = 0;
      termSetStatus("Connected", "var(--green)");
      termSetConnected(true);
      // Send initial size.
      var cols = termInst.cols, rows = termInst.rows;
      ws.send(JSON.stringify({ type: "resize", cols: cols, rows: rows }));
      termInst.focus();
    };

    ws.onmessage = function(evt) {
      if (evt.data instanceof ArrayBuffer) {
        termInst.write(new Uint8Array(evt.data));
      }
    };

    ws.onclose = function(evt) {
      termSetConnected(false);
      termWS = null;

      if (opened) {
        termSetStatus("Disconnected", "var(--text-muted)");
        return;
      }

      function continueRejectedUpgradeFlow() {
        // Upgrade rejected after auth check — retry once with forced reauth.
        if (termWSRetries >= 1) {
          termFetchConnectDiag("after-ws-fail").then(function(diag) {
            if (!termHandleConnectBlock(diag)) {
              termSetStatus("No se pudo conectar — revisa nginx o inicia sesión de nuevo", "var(--red)");
              termLoadProxyStatus().then(function(st) {
                // Proxy inspection says OK but WS still failed (possible false-positive).
                // Offer Fix button so the user can force a nginx reconfigure.
                if (!st || st.ok) {
                  termShowFixProxy(true, st
                    ? "El proxy nginx parece configurado pero el WebSocket falló — haz clic para reconfigurar nginx"
                    : "No se pudo verificar el proxy nginx — haz clic para intentar repararlo");
                }
              });
            }
          }).catch(function() {
            termSetStatus("No se pudo conectar — repara el proxy nginx o inicia sesión de nuevo", "var(--red)");
            termLoadProxyStatus().then(function(st) {
              if (!st || st.ok) {
                termShowFixProxy(true, "Verifica y repara la configuración WebSocket en nginx");
              }
            });
          });
          return;
        }
        termWSRetries++;
        termSetStatus("Connection failed — retrying with fresh authentication…", "var(--yellow)");
        if (typeof window.promptReauth === "function") {
          window.promptReauth().then(function() {
            termOpenWebSocket();
          }).catch(function(err) {
            if (err && err.message === "Unauthorized") {
              termSetStatus("Session expired — log in again", "var(--red)");
              if (typeof window.showLogin === "function") window.showLogin();
              return;
            }
            termSetStatus("Connection cancelled", "var(--text-muted)");
          });
          return;
        }
        termSetStatus("Could not connect — re-authentication unavailable", "var(--red)");
      }

      if (wsHadError) {
        termFetchConnectDiag("after-ws-error").then(function(diag) {
          if (termHandleConnectBlock(diag)) return;
          continueRejectedUpgradeFlow();
        }).catch(function(err) {
          if (termIsNetworkError(err)) {
            termSetNetworkFailure();
            return;
          }
          continueRejectedUpgradeFlow();
        });
        return;
      }

      continueRejectedUpgradeFlow();
    };

    ws.onerror = function() {
      wsHadError = true;
      // Let onclose handle status/retry — it fires right after onerror and we
      // need its "opened" check to decide whether a reauth retry is warranted.
    };
  }

  function termDisconnect() {
    if (termWS) { termWS.close(); termWS = null; }
  }

  function sshSetStatus(msg, color) {
    var el = document.getElementById("sshStatus");
    if (el) { el.textContent = msg; el.style.color = color || "var(--text-muted)"; }
  }

  function sshShowConnectPanel(show) {
    var panel = document.getElementById("sshConnectPanel");
    if (panel) panel.style.display = show ? "" : "none";
  }

  function sshShowTerminalPanel(show) {
    var panel = document.getElementById("sshTerminalPanel");
    if (panel) panel.style.display = show ? "" : "none";
  }

  function sshReadForm() {
    var host = (document.getElementById("sshHostInput") || {}).value || "";
    var user = (document.getElementById("sshUserInput") || {}).value || "admin";
    var port = (document.getElementById("sshPortInput") || {}).value || "22";
    host = host.trim();
    user = user.trim() || "admin";
    port = port.trim() || "22";
    if (!host) throw new Error("Host requerido");
    if (!/^[A-Za-z_][A-Za-z0-9_.-]{0,31}$/.test(user)) throw new Error("Usuario invalido");
    var portNum = Number(port);
    if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) throw new Error("Puerto invalido");
    return { host: host, user: user, port: String(portNum) };
  }

  function sshSetTargetLabel(params) {
    var el = document.getElementById("sshTargetLabel");
    if (el) el.textContent = params.user + "@" + params.host + ":" + params.port;
  }

  function sshConnect() {
    if (typeof Terminal === "undefined" || typeof FitAddon === "undefined") {
      sshSetStatus("Terminal library failed to load", "var(--red)");
      return;
    }

    var params;
    try { params = sshReadForm(); }
    catch (e) {
      sshSetStatus(e.message || "Datos invalidos", "var(--red)");
      return;
    }

    var btn = document.getElementById("sshConnectBtn");
    if (btn) btn.disabled = true;
    sshShowTerminalPanel(true);
    sshSetTargetLabel(params);
    sshSetStatus("Preparing access key...", "var(--yellow)");

    ensureTerminalAuth().then(function() {
      return window.apiFetch("/api/terminal/access-key", { method: "POST" });
    }).then(function() {
      sshOpenWebSocket(params);
    }).catch(function(err) {
      if (err && err.code === "session_expired") {
        sshSetStatus("Sesion expirada", "var(--red)");
        if (typeof window.showLogin === "function") window.showLogin();
        return;
      }
      if (err && err.code === "reauth_cancelled") {
        sshSetStatus("Conexion cancelada", "var(--text-muted)");
        return;
      }
      sshSetStatus("No se pudo preparar SSH", "var(--red)");
    }).finally(function() {
      if (btn) btn.disabled = false;
    });
  }

  function sshOpenWebSocket(params) {
    if (sshWS && sshWS.readyState === WebSocket.OPEN) sshWS.close();

    if (!sshReady) {
      sshInst = new Terminal({
        cursorBlink: true,
        fontSize: 14,
        fontFamily: '"Cascadia Code", "Fira Code", "Menlo", monospace',
        theme: {
          background: "#0d1117",
          foreground: "#e6edf3",
          cursor:     "#00b4d8",
          selectionBackground: "rgba(0,180,216,0.3)",
          black:   "#484f58", red:     "#f85149", green:   "#3fb950", yellow: "#d29922",
          blue:    "#388bfd", magenta: "#bc8cff", cyan:    "#39c5cf", white:  "#b1bac4",
          brightBlack:   "#6e7681", brightRed:     "#ff7b72", brightGreen: "#56d364",
          brightYellow:  "#e3b341", brightBlue:    "#79c0ff", brightMagenta:"#d2a8ff",
          brightCyan:    "#56d4dd", brightWhite:   "#f0f6fc"
        },
        allowProposedApi: true
      });
      sshFitAddon = new FitAddon.FitAddon();
      sshInst.loadAddon(sshFitAddon);
      sshInst.open(document.getElementById("sshTerminalContainer"));
      sshFitAddon.fit();
      sshInst.onResize(function(size) {
        if (sshWS && sshWS.readyState === WebSocket.OPEN) {
          sshWS.send(JSON.stringify({ type: "resize", cols: size.cols, rows: size.rows }));
        }
      });
      sshInst.onData(function(data) {
        if (sshWS && sshWS.readyState === WebSocket.OPEN) {
          sshWS.send(new TextEncoder().encode(data));
        }
      });
      window.addEventListener("resize", function() {
        if (sshReady && sshFitAddon) sshFitAddon.fit();
      });
      sshReady = true;
    }

    var proto = location.protocol === "https:" ? "wss:" : "ws:";
    var url = proto + "//" + location.host + "/api/terminal/ssh/ws" +
      "?host=" + encodeURIComponent(params.host) +
      "&user=" + encodeURIComponent(params.user) +
      "&port=" + encodeURIComponent(params.port);

    sshSetStatus("Connecting...", "var(--yellow)");
    sshInst.clear();
    sshInst.focus();

    var ws = new WebSocket(url);
    ws.binaryType = "arraybuffer";
    sshWS = ws;
    var opened = false;

    ws.onopen = function() {
      opened = true;
      sshSetStatus("Connected", "var(--green)");
      if (sshFitAddon) sshFitAddon.fit();
      ws.send(JSON.stringify({ type: "resize", cols: sshInst.cols, rows: sshInst.rows }));
      sshInst.focus();
    };

    ws.onmessage = function(evt) {
      if (evt.data instanceof ArrayBuffer) {
        sshInst.write(new Uint8Array(evt.data));
      }
    };

    ws.onclose = function() {
      sshWS = null;
      sshSetStatus(opened ? "Disconnected" : "SSH failed - verify host, user, key, and port", opened ? "var(--text-muted)" : "var(--red)");
    };

    ws.onerror = function() {
      sshSetStatus("SSH connection error", "var(--red)");
    };
  }

  function sshDisconnect() {
    if (sshWS) { sshWS.close(); sshWS = null; }
  }

  function termEnableSSLFromDiag() {
    var btn = document.getElementById("termEnableSSLBtn");
    var domain = btn ? btn.dataset.domain : "";
    if (!domain) {
      termOpenSettings("");
      return;
    }
    if (typeof window.runStreamedOperation !== "function") {
      termSetStatus("Enable SSL no está disponible — abre Settings", "var(--red)");
      termOpenSettings(domain);
      return;
    }
    ensureTerminalAuth().then(function() {
      window.runStreamedOperation("/api/settings/ssl-enable", {}, "Enabling SSL for ServerPilot", domain);
    }).catch(function(err) {
      if (err && err.code === "session_expired") {
        termSetStatus("Sesión expirada — inicia sesión de nuevo", "var(--red)");
        if (typeof window.showLogin === "function") window.showLogin();
        return;
      }
      termSetStatus("No se pudo iniciar Enable SSL", "var(--red)");
    });
  }

  // Wire buttons once DOM is ready.
  document.addEventListener("DOMContentLoaded", function() {
    var connBtn = document.getElementById("termConnectBtn");
    var discBtn = document.getElementById("termDisconnectBtn");
    var fixBtn  = document.getElementById("termFixProxyBtn");
    var logsBtn = document.getElementById("termLogsBtn");
    var accessKeyBtn = document.getElementById("termAccessKeyBtn");
    var copyInstallBtn = document.getElementById("termCopyInstallBtn");
    var addSSHBtn = document.getElementById("termAddSSHBtn");
    var copyPublicKeyBtn = document.getElementById("termCopyPublicKeyBtn");
    var copySSHExampleBtn = document.getElementById("termCopySSHExampleBtn");
    var accessKeyCloseBtn = document.getElementById("termAccessKeyCloseBtn");
    var sshConnectBtn = document.getElementById("sshConnectBtn");
    var sshConnectCloseBtn = document.getElementById("sshConnectCloseBtn");
    var sshDisconnectBtn = document.getElementById("sshDisconnectBtn");
    var sshCopyInstallBtn = document.getElementById("sshCopyInstallBtn");
    var logsRefreshBtn = document.getElementById("termLogsRefreshBtn");
    var logsCloseBtn = document.getElementById("termLogsCloseBtn");
    var settingsBtn = document.getElementById("termSettingsBtn");
    var openDomainBtn = document.getElementById("termOpenDomainBtn");
    var enableSSLBtn = document.getElementById("termEnableSSLBtn");
    if (connBtn) connBtn.addEventListener("click", termConnect);
    if (discBtn) discBtn.addEventListener("click", termDisconnect);
    if (fixBtn) fixBtn.addEventListener("click", termFixProxy);
    if (logsBtn) logsBtn.addEventListener("click", termLoadServiceLogs);
    if (accessKeyBtn) accessKeyBtn.addEventListener("click", termLoadAccessKey);
    if (copyInstallBtn) copyInstallBtn.addEventListener("click", function() { termCopyText(termInstallCommand, "Installation command"); });
    if (addSSHBtn) addSSHBtn.addEventListener("click", function() {
      sshShowConnectPanel(true);
      var hostInput = document.getElementById("sshHostInput");
      if (hostInput) hostInput.focus();
    });
    if (copyPublicKeyBtn) copyPublicKeyBtn.addEventListener("click", function() {
      if (!termAccessKeyData || !termAccessKeyData.public_key) {
        termLoadAccessKey();
        return;
      }
      termCopyText(termAccessKeyData.public_key, "Public key");
    });
    if (copySSHExampleBtn) copySSHExampleBtn.addEventListener("click", function() {
      var cmd = (termAccessKeyData && termAccessKeyData.ssh_command) || "ssh -i /root/.ssh/serverpilot_remote_access_ed25519 admin@<server-ip>";
      termCopyText(cmd, "SSH example");
    });
    if (accessKeyCloseBtn) accessKeyCloseBtn.addEventListener("click", function() { termShowAccessKeyPanel(false); });
    if (sshConnectBtn) sshConnectBtn.addEventListener("click", sshConnect);
    if (sshConnectCloseBtn) sshConnectCloseBtn.addEventListener("click", function() { sshShowConnectPanel(false); });
    if (sshDisconnectBtn) sshDisconnectBtn.addEventListener("click", sshDisconnect);
    if (sshCopyInstallBtn) sshCopyInstallBtn.addEventListener("click", function() { termCopyText(termInstallCommand, "Installation command"); });
    if (logsRefreshBtn) logsRefreshBtn.addEventListener("click", termLoadServiceLogs);
    if (logsCloseBtn) logsCloseBtn.addEventListener("click", function() { termShowLogsPanel(false); });
    if (settingsBtn) settingsBtn.addEventListener("click", function() { termOpenSettings(termCurrentExternalHost()); });
    if (openDomainBtn) openDomainBtn.addEventListener("click", function() {
      var url = openDomainBtn.dataset.url || "";
      if (url) window.location.href = url;
    });
    if (enableSSLBtn) enableSSLBtn.addEventListener("click", termEnableSSLFromDiag);

    // Auto-fit when switching to the terminal tab.
    document.querySelectorAll(".tab-btn").forEach(function(btn) {
      btn.addEventListener("click", function() {
        if (btn.dataset.tab === "terminal") {
          termLoadProxyStatus();
          setTimeout(function() { if (fitAddon) fitAddon.fit(); }, 50);
          setTimeout(function() { if (sshFitAddon) sshFitAddon.fit(); }, 80);
        } else {
          // Disconnect when leaving the terminal tab to avoid orphaned PTYs.
          termDisconnect();
          sshDisconnect();
        }
      });
    });
  });
})();
