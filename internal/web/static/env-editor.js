/* Shared environment variable editor: plain textarea + optional friendly key/value rows. */
(function(global) {
  var PREF_KEY = "sp.envEditor.friendly";
  var VALID_KEY = /^[A-Za-z_][A-Za-z0-9_]*$/;

  function parseEnvText(text) {
    var entries = [];
    var preserved = [];
    var lines = (text || "").split("\n");
    for (var i = 0; i < lines.length; i++) {
      var raw = lines[i];
      var line = raw.trim();
      if (!line || line.charAt(0) === "#") {
        preserved.push(raw);
        continue;
      }
      var work = line.indexOf("export ") === 0 ? line.slice(7) : line;
      var eq = work.indexOf("=");
      if (eq < 0) {
        preserved.push(raw);
        continue;
      }
      var key = work.slice(0, eq).trim();
      var value = work.slice(eq + 1).trim();
      if (value.length >= 2) {
        var q0 = value.charAt(0);
        var qn = value.charAt(value.length - 1);
        if ((q0 === '"' && qn === '"') || (q0 === "'" && qn === "'")) {
          value = value.slice(1, -1);
        }
      }
      if (!VALID_KEY.test(key)) {
        preserved.push(raw);
        continue;
      }
      entries.push({ key: key, value: value, sensitive: false });
    }
    return { entries: entries, preserved: preserved.join("\n") };
  }

  function serializeEnvText(entries, preserved) {
    var parts = [];
    if (preserved && preserved.trim()) {
      parts.push(preserved.replace(/\n$/, ""));
    }
    (entries || []).forEach(function(e) {
      if (e && e.key) {
        parts.push(e.key + "=" + (e.value || ""));
      }
    });
    if (!parts.length) return "";
    return parts.join("\n") + "\n";
  }

  function normalizeEntries(input) {
    if (!input || !input.length) return [];
    if (typeof input[0] === "string") {
      return parseEnvText(input.join("\n")).entries;
    }
    return input.map(function(e) {
      return {
        key: e.key || "",
        value: e.value || "",
        sensitive: !!e.sensitive
      };
    });
  }

  function validateEntries(entries) {
    var seen = {};
    var errors = [];
    (entries || []).forEach(function(e, idx) {
      var key = (e.key || "").trim();
      if (!key) return;
      if (!VALID_KEY.test(key)) {
        errors.push("Clave inválida en fila " + (idx + 1) + ": " + key);
      }
      if (seen[key]) {
        errors.push("Clave duplicada: " + key);
      }
      seen[key] = true;
    });
    return errors;
  }

  function copyToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function(resolve, reject) {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      try { document.execCommand("copy") ? resolve() : reject(new Error("copy failed")); }
      catch (e) { reject(e); }
      finally { document.body.removeChild(ta); }
    });
  }

  function generateSecret() {
    var bytes = new Uint8Array(32);
    if (global.crypto && global.crypto.getRandomValues) {
      global.crypto.getRandomValues(bytes);
    } else {
      for (var i = 0; i < bytes.length; i++) {
        bytes[i] = Math.floor(Math.random() * 256);
      }
    }
    var bin = "";
    for (var j = 0; j < bytes.length; j++) {
      bin += String.fromCharCode(bytes[j]);
    }
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function mount(rootEl, options) {
    options = options || {};
    var persistPreference = options.persistPreference !== false;
    var showSensitiveToggle = options.showSensitiveToggle !== false;
    var textareaStyle = options.textareaStyle || "width:100%;height:160px;padding:0.75rem;background:var(--bg-primary);border:1px solid var(--border);border-radius:8px;color:var(--text-primary);font-family:monospace;font-size:0.8125rem;resize:vertical;box-sizing:border-box;line-height:1.6;";

    rootEl.innerHTML = "";
    rootEl.className = (rootEl.className || "").trim() + " env-editor-root";

    var preserved = "";
    var destroyed = false;
    var expanded = false;
    var defaultTextareaHeight = "160px";
    var defaultListMaxHeight = "220px";
    var heightMatch = textareaStyle.match(/height:\s*([^;]+)/);
    if (heightMatch) defaultTextareaHeight = heightMatch[1].trim();

    var friendly = !!options.defaultFriendly;
    if (persistPreference) {
      try {
        var stored = localStorage.getItem(PREF_KEY);
        if (stored === "true") friendly = true;
        else if (stored === "false") friendly = false;
      } catch (e) {}
    }

    var toggleRow = document.createElement("label");
    toggleRow.style.cssText = "display:flex;align-items:center;gap:8px;margin-bottom:8px;font-size:0.8125rem;cursor:pointer;";
    var checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.checked = friendly;
    var toggleLabel = document.createElement("span");
    toggleLabel.textContent = "Entorno amigable";
    toggleRow.appendChild(checkbox);
    toggleRow.appendChild(toggleLabel);
    rootEl.appendChild(toggleRow);

    var plainPanel = document.createElement("div");
    plainPanel.className = "env-editor-plain";
    var textarea = document.createElement("textarea");
    textarea.className = "env-editor-textarea";
    textarea.spellcheck = false;
    textarea.style.cssText = textareaStyle;
    plainPanel.appendChild(textarea);
    rootEl.appendChild(plainPanel);

    var friendlyPanel = document.createElement("div");
    friendlyPanel.className = "env-editor-friendly";
    friendlyPanel.style.display = "none";
    var listEl = document.createElement("div");
    listEl.className = "env-editor-list";
    listEl.style.cssText = "max-height:" + defaultListMaxHeight + ";overflow:auto;border:1px solid var(--border);border-radius:6px;padding:8px;background:var(--bg-input);";
    friendlyPanel.appendChild(listEl);
    var addBtn = document.createElement("button");
    addBtn.type = "button";
    addBtn.className = "btn btn-sm btn-outline env-editor-add-btn";
    addBtn.style.marginTop = "8px";
    addBtn.textContent = "+ Añadir variable";
    friendlyPanel.appendChild(addBtn);
    rootEl.appendChild(friendlyPanel);

    function updateCopyBtnState(copyBtn, valEl, keyEl) {
      if (!copyBtn) return;
      copyBtn.disabled = !(valEl && valEl.value);
    }

    function makeRow(key, value, sensitive) {
      var row = document.createElement("div");
      row.className = "env-editor-row";
      var k = document.createElement("input");
      k.type = "text";
      k.value = key || "";
      k.placeholder = "KEY";
      k.className = "env-editor-key";
      k.style.cssText = "padding:0.35rem 0.5rem;background:var(--bg-secondary);border:1px solid var(--border);border-radius:6px;color:var(--text-primary);font-size:0.8125rem;";
      var v = document.createElement("input");
      v.type = sensitive ? "password" : "text";
      v.value = value || "";
      v.placeholder = "value";
      v.className = "env-editor-value";
      v.style.cssText = "padding:0.35rem 0.5rem;background:var(--bg-secondary);border:1px solid var(--border);border-radius:6px;color:var(--text-primary);font-size:0.8125rem;";

      var copyBtn = document.createElement("button");
      copyBtn.type = "button";
      copyBtn.className = "btn btn-sm btn-outline env-editor-row-btn";
      copyBtn.textContent = "Copiar";
      copyBtn.title = "Copiar valor";
      copyBtn.addEventListener("click", function() {
        if (!v.value) {
          if (global.showToast) global.showToast("No hay valor para copiar", "error");
          return;
        }
        copyToClipboard(v.value).then(function() {
          var label = k.value.trim() ? k.value.trim() + " copiado" : "Valor copiado";
          if (global.showToast) global.showToast(label, "success");
        }).catch(function() {
          if (global.showToast) global.showToast("No se pudo copiar", "error");
        });
      });

      var generateBtn = document.createElement("button");
      generateBtn.type = "button";
      generateBtn.className = "btn btn-sm btn-outline env-editor-row-btn";
      generateBtn.textContent = "Generar";
      generateBtn.title = "Generar secreto fuerte";
      generateBtn.addEventListener("click", function() {
        var secret = generateSecret();
        v.value = secret;
        v.type = "password";
        if (showSensitiveToggle) toggleBtn.textContent = "Show";
        updateCopyBtnState(copyBtn, v, k);
        copyToClipboard(secret).then(function() {
          if (global.showToast) global.showToast("Secreto generado y copiado", "success");
        }).catch(function() {
          if (global.showToast) global.showToast("Secreto generado", "success");
        });
      });

      var toggleBtn = document.createElement("button");
      toggleBtn.type = "button";
      toggleBtn.className = "btn btn-sm btn-outline env-editor-row-btn";
      if (showSensitiveToggle) {
        toggleBtn.textContent = sensitive ? "Show" : "Hide";
        toggleBtn.addEventListener("click", function() {
          v.type = v.type === "password" ? "text" : "password";
          toggleBtn.textContent = v.type === "password" ? "Show" : "Hide";
        });
      } else {
        toggleBtn.style.visibility = "hidden";
      }

      var removeBtn = document.createElement("button");
      removeBtn.type = "button";
      removeBtn.className = "btn btn-sm btn-outline env-editor-row-btn env-editor-row-remove";
      removeBtn.textContent = "\u2715";
      removeBtn.title = "Eliminar";
      removeBtn.addEventListener("click", function() {
        row.remove();
        if (!listEl.children.length) {
          listEl.appendChild(makeRow("", "", false));
        }
      });

      v.addEventListener("input", function() {
        updateCopyBtnState(copyBtn, v, k);
      });
      updateCopyBtnState(copyBtn, v, k);

      row.appendChild(k);
      row.appendChild(v);
      row.appendChild(copyBtn);
      row.appendChild(generateBtn);
      row.appendChild(toggleBtn);
      row.appendChild(removeBtn);
      return row;
    }

    function renderRows(entries) {
      listEl.innerHTML = "";
      entries = entries || [];
      if (!entries.length) {
        listEl.appendChild(makeRow("", "", false));
        return;
      }
      entries.forEach(function(e) {
        listEl.appendChild(makeRow(e.key, e.value, e.sensitive));
      });
    }

    function collectEntries() {
      var rows = listEl.querySelectorAll(".env-editor-row");
      var entries = [];
      rows.forEach(function(row) {
        var keyEl = row.querySelector(".env-editor-key");
        var valEl = row.querySelector(".env-editor-value");
        var key = keyEl ? keyEl.value.trim() : "";
        if (!key) return;
        entries.push({
          key: key,
          value: valEl ? valEl.value : "",
          sensitive: valEl && valEl.type === "password"
        });
      });
      return entries;
    }

    function updateView() {
      plainPanel.style.display = checkbox.checked ? "none" : "block";
      friendlyPanel.style.display = checkbox.checked ? "block" : "none";
    }

    function applyExpandedLayout() {
      if (expanded) {
        rootEl.classList.add("env-editor-expanded");
        textarea.style.height = "calc(96vh - 220px)";
        listEl.style.maxHeight = "calc(96vh - 260px)";
      } else {
        rootEl.classList.remove("env-editor-expanded");
        textarea.style.height = defaultTextareaHeight;
        listEl.style.maxHeight = defaultListMaxHeight;
      }
    }

    function syncToFriendly(showInfo) {
      var parsed = parseEnvText(textarea.value);
      preserved = parsed.preserved;
      renderRows(parsed.entries);
      if (showInfo && preserved && preserved.trim() && global.showToast) {
        global.showToast("Comentarios y líneas especiales se conservan en modo plano", "success");
      }
    }

    function syncToPlain() {
      textarea.value = serializeEnvText(collectEntries(), preserved);
    }

    checkbox.addEventListener("change", function() {
      if (checkbox.checked) {
        syncToFriendly(true);
      } else {
        syncToPlain();
      }
      if (persistPreference) {
        try { localStorage.setItem(PREF_KEY, checkbox.checked ? "true" : "false"); } catch (e) {}
      }
      updateView();
    });

    addBtn.addEventListener("click", function() {
      listEl.appendChild(makeRow("", "", false));
    });

    updateView();
    if (checkbox.checked) {
      syncToFriendly(false);
    }

    return {
      isFriendly: function() { return checkbox.checked; },
      setFromText: function(text) {
        textarea.value = text || "";
        preserved = "";
        if (checkbox.checked) {
          syncToFriendly(false);
        }
      },
      setFromEntries: function(entries) {
        var normalized = normalizeEntries(entries);
        preserved = "";
        if (checkbox.checked) {
          renderRows(normalized);
        } else {
          textarea.value = serializeEnvText(normalized, "");
        }
      },
      getText: function() {
        if (checkbox.checked) {
          return serializeEnvText(collectEntries(), preserved);
        }
        return textarea.value;
      },
      getEnvArray: function() {
        var entries = checkbox.checked ? collectEntries() : parseEnvText(textarea.value).entries;
        return entries.map(function(e) { return e.key + "=" + e.value; });
      },
      validate: function() {
        var entries = checkbox.checked ? collectEntries() : parseEnvText(textarea.value).entries;
        return validateEntries(entries);
      },
      syncToPlain: syncToPlain,
      syncToFriendly: function() {
        syncToFriendly(false);
        checkbox.checked = true;
        updateView();
        if (persistPreference) {
          try { localStorage.setItem(PREF_KEY, "true"); } catch (e) {}
        }
      },
      destroy: function() {
        if (destroyed) return;
        destroyed = true;
        textarea.value = "";
        listEl.innerHTML = "";
        rootEl.innerHTML = "";
      },
      setDisabled: function(dis) {
        textarea.disabled = dis;
        checkbox.disabled = dis;
        addBtn.disabled = dis;
        listEl.querySelectorAll("input,button").forEach(function(el) { el.disabled = dis; });
      },
      isEmpty: function() {
        var text = this.getText();
        return !text || !text.trim();
      },
      setExpanded: function(isExpanded) {
        expanded = !!isExpanded;
        applyExpandedLayout();
      },
      isExpanded: function() {
        return expanded;
      }
    };
  }

  global.EnvEditor = {
    mount: mount,
    parseEnvText: parseEnvText,
    serializeEnvText: serializeEnvText,
    validateEntries: validateEntries,
    normalizeEntries: normalizeEntries
  };
})(typeof window !== "undefined" ? window : this);
