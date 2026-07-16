/* Database tab + schema browser */
"use strict";

  // /api/db/connections (list/save/delete/test). Queries go through
  // /api/db/query which audit-logs every call. UI never sees the DSN
  // after save — to rotate the password the operator deletes + recreates.

  var _dbConnections = [];
  var _dbActiveConnId = null;

  function loadDBConnections() {
    var ts = document.getElementById("ts-db");
    if (ts) ts.textContent = new Date().toLocaleTimeString();
    var wrap = document.getElementById("dbConnections");
    if (!wrap) return;
    wrap.innerHTML = '<div class="spinner"><div class="spinner-ring"></div>Loading…</div>';
    apiFetch("/api/db/connections").then(function(resp) {
      _dbConnections = (resp && resp.data) || [];
      renderDBConnections();
    }).catch(function(err) {
      wrap.innerHTML = '<div style="padding:0.75rem;color:var(--red);font-size:0.78rem;">Error: ' + escapeHtml((err && err.message) || "failed to load") + '</div>';
    });
  }

  function renderDBConnections() {
    var wrap = document.getElementById("dbConnections");
    if (!wrap) return;
    if (_dbConnections.length === 0) {
      wrap.innerHTML = '<div style="padding:0.75rem;font-size:0.78rem;color:var(--text-muted);">No connections yet. Click <strong>+ New</strong> to add one.</div>';
      return;
    }
    var html = _dbConnections.map(function(c) {
      var active = (c.id === _dbActiveConnId);
      var bg = active ? "rgba(0,168,232,0.12)" : "transparent";
      var border = active ? "1px solid var(--accent)" : "1px solid transparent";
      var engineBadge = c.engine === "postgres"
        ? '<span style="background:#1a3a4a;color:#5db4d4;padding:1px 6px;border-radius:3px;font-size:0.62rem;">postgres</span>'
        : '<span style="background:#3a2a1a;color:#d4a85d;padding:1px 6px;border-radius:3px;font-size:0.62rem;">mysql</span>';
      return '<div data-id="' + escapeHtml(c.id) + '" onclick="selectDBConnection(\'' + escapeHtml(c.id) + '\')" ' +
        'style="padding:8px 10px;margin-bottom:4px;border-radius:6px;cursor:pointer;background:' + bg + ';border:' + border + ';">' +
        '<div style="display:flex;align-items:center;gap:6px;">' +
          '<strong style="flex:1;font-family:monospace;font-size:0.78rem;color:var(--text-primary);">' + escapeHtml(c.name) + '</strong>' +
          engineBadge +
        '</div>' +
        (c.description ? '<div style="font-size:0.66rem;color:var(--text-muted);margin-top:2px;">' + escapeHtml(c.description) + '</div>' : '') +
        '<div style="display:flex;gap:4px;margin-top:6px;">' +
          '<button type="button" onclick="event.stopPropagation();testDBConnection(\'' + escapeHtml(c.id) + '\')" class="btn btn-sm btn-outline" style="font-size:0.66rem;padding:2px 8px;">Test</button>' +
          '<button type="button" onclick="event.stopPropagation();openDBSchemaBrowser(\'' + escapeHtml(c.id) + '\')" class="btn btn-sm btn-outline" style="font-size:0.66rem;padding:2px 8px;">📂 Schema</button>' +
          '<button type="button" onclick="event.stopPropagation();editDBConnection(\'' + escapeHtml(c.id) + '\')" class="btn btn-sm btn-outline" style="font-size:0.66rem;padding:2px 8px;">Edit</button>' +
          '<button type="button" onclick="event.stopPropagation();deleteDBConnection(\'' + escapeHtml(c.id) + '\')" class="btn btn-sm" style="font-size:0.66rem;padding:2px 8px;background:transparent;border:1px solid #f8514966;color:#f85149;">Delete</button>' +
        '</div>' +
      '</div>';
    }).join('');
    wrap.innerHTML = html;
  }

  function selectDBConnection(id) {
    _dbActiveConnId = id;
    var c = _dbConnections.find(function(x) { return x.id === id; });
    var label = document.getElementById("dbActiveConn");
    var runBtn = document.getElementById("dbRunBtn");
    if (label) label.textContent = c ? (c.engine + " · " + c.name) : "";
    if (runBtn) runBtn.disabled = !c;
    renderDBConnections();
  }

  function openDBNewConnModal() {
    document.getElementById("dbConnID").value = "";
    document.getElementById("dbConnName").value = "";
    document.getElementById("dbConnEngine").value = "postgres";
    document.getElementById("dbConnDSN").value = "";
    document.getElementById("dbConnDesc").value = "";
    document.getElementById("dbConnMsg").textContent = "";
    document.getElementById("dbConnModal").style.display = "flex";
  }
  function closeDBNewConnModal() {
    document.getElementById("dbConnModal").style.display = "none";
  }

  function editDBConnection(id) {
    var c = _dbConnections.find(function(x) { return x.id === id; });
    if (!c) return;
    document.getElementById("dbConnID").value = c.id;
    document.getElementById("dbConnName").value = c.name;
    document.getElementById("dbConnEngine").value = c.engine;
    // The DSN is NOT returned by the API for security — operator must paste it again to update.
    document.getElementById("dbConnDSN").value = "";
    document.getElementById("dbConnDSN").placeholder = "Re-paste the DSN to update (existing one is encrypted)";
    document.getElementById("dbConnDesc").value = c.description || "";
    document.getElementById("dbConnMsg").textContent = "Editing existing connection. Re-paste the DSN to save changes.";
    document.getElementById("dbConnModal").style.display = "flex";
  }

  async function submitDBConn() {
    var msg = document.getElementById("dbConnMsg");
    var btn = document.getElementById("dbConnSaveBtn");
    msg.style.color = "var(--text-muted)";
    msg.textContent = "Saving…";
    btn.disabled = true;
    try {
      var body = {
        id:          document.getElementById("dbConnID").value || "",
        name:        document.getElementById("dbConnName").value.trim(),
        engine:      document.getElementById("dbConnEngine").value,
        dsn:         document.getElementById("dbConnDSN").value.trim(),
        description: document.getElementById("dbConnDesc").value.trim()
      };
      await apiFetch("/api/db/connections/save", { method: "POST", body: body });
      closeDBNewConnModal();
      showToast("Connection saved", "success");
      await loadDBConnections();
    } catch (err) {
      msg.style.color = "#f85149";
      msg.textContent = (err && err.message) || "save failed";
    } finally {
      btn.disabled = false;
    }
  }

  async function deleteDBConnection(id) {
    if (!window.confirm("Delete this connection? The encrypted DSN will be unrecoverable.")) return;
    try {
      await apiFetch("/api/db/connections/delete", { method: "POST", body: { id: id } });
      if (_dbActiveConnId === id) _dbActiveConnId = null;
      showToast("Connection deleted", "success");
      await loadDBConnections();
    } catch (err) {
      showToast("Delete failed: " + (err.message || "error"), "error");
    }
  }

  async function testDBConnection(id) {
    try {
      await apiFetch("/api/db/connections/test", { method: "POST", body: { id: id } });
      showToast("Connection OK", "success");
    } catch (err) {
      showToast("Test failed: " + ((err && err.message) || "error"), "error");
    }
  }

  async function runDBQuery() {
    if (!_dbActiveConnId) { showToast("Select a connection first", "error"); return; }
    var sql = document.getElementById("dbQuery").value.trim();
    if (!sql) { showToast("Query is empty", "error"); return; }

    var status = document.getElementById("dbQueryStatus");
    var resultWrap = document.getElementById("dbResultWrap");
    var btn = document.getElementById("dbRunBtn");
    btn.disabled = true;
    status.style.color = "var(--text-muted)";
    status.textContent = "Running…";
    resultWrap.innerHTML = "";

    try {
      var resp = await apiFetch("/api/db/query", {
        method: "POST",
        body: { connection_id: _dbActiveConnId, sql: sql }
      });
      var d = (resp && resp.data) || {};
      renderDBResult(d);
      var bits = [];
      bits.push(d.duration_ms + " ms");
      if (d.is_result_set) {
        bits.push((d.rows ? d.rows.length : 0) + " row(s)");
        if (d.truncated) bits.push("⚠ truncated at server cap");
      } else {
        bits.push((d.rows_affected || 0) + " row(s) affected");
      }
      status.style.color = "#3fb950";
      status.textContent = "✓ " + bits.join(" · ");
    } catch (err) {
      status.style.color = "#f85149";
      status.textContent = "✗ " + ((err && err.message) || "query failed");
    } finally {
      btn.disabled = false;
    }
  }

  function renderDBResult(result) {
    var wrap = document.getElementById("dbResultWrap");
    if (!wrap) return;
    if (!result.is_result_set) {
      wrap.innerHTML = '<div style="padding:1rem;color:var(--text-muted);font-size:0.82rem;">Statement executed. ' +
        (result.rows_affected || 0) + ' row(s) affected.</div>';
      return;
    }
    var cols = result.columns || [];
    var rows = result.rows || [];
    if (rows.length === 0) {
      wrap.innerHTML = '<div style="padding:1rem;color:var(--text-muted);font-size:0.82rem;">No rows returned.</div>';
      return;
    }
    var head = '<tr>' + cols.map(function(c) {
      return '<th style="text-align:left;padding:6px 10px;font-size:0.7rem;color:var(--text-muted);background:var(--bg-input);position:sticky;top:0;border-bottom:1px solid var(--border);">' + escapeHtml(c) + '</th>';
    }).join('') + '</tr>';
    var body = rows.map(function(r) {
      return '<tr>' + r.map(function(v) {
        var disp = (v === null || v === undefined) ? '<span style="color:var(--text-muted);font-style:italic;">NULL</span>' : escapeHtml(String(v));
        return '<td style="padding:5px 10px;font-family:monospace;font-size:0.72rem;color:var(--text-primary);border-bottom:1px solid var(--border);max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + escapeHtml(String(v === null ? "NULL" : v)) + '">' + disp + '</td>';
      }).join('') + '</tr>';
    }).join('');
    wrap.innerHTML = '<table style="width:100%;border-collapse:collapse;">' + head + body + '</table>';
  }

  // Ctrl+Enter / Cmd+Enter to run.
  document.addEventListener("keydown", function(e) {
    var qta = document.getElementById("dbQuery");
    if (qta && document.activeElement === qta && (e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      runDBQuery();
    }
  });

  // Backdrop close for the connection modal.
  var dbConnModalEl = document.getElementById("dbConnModal");
  if (dbConnModalEl) {
    dbConnModalEl.addEventListener("click", function(e) {
      if (e.target === this) closeDBNewConnModal();
    });
  }

  window.loadDBConnections      = loadDBConnections;
  window.selectDBConnection     = selectDBConnection;
  window.openDBNewConnModal     = openDBNewConnModal;
  window.closeDBNewConnModal    = closeDBNewConnModal;
  window.editDBConnection       = editDBConnection;
  window.submitDBConn           = submitDBConn;
  window.deleteDBConnection     = deleteDBConnection;
  window.testDBConnection       = testDBConnection;
  window.runDBQuery             = runDBQuery;

  // ── Database tab: inline cell editing + log panel ───────────────────
  // The result table is rendered as a real <table>. When the server
  // reports `editable` metadata, non-PK cells get double-click-to-edit.
  // Enter saves; Escape cancels; blur with changes triggers a save.
  // Save calls /api/db/cell-update which validates the identifier set
  // against the live pg_catalog and runs an UPDATE … WHERE pk = $N
  // with parameterised values. Every operation appends a line to the
  // logs panel below the result table.

  var _dbLastResult = null; // last QueryResult, kept so we can refresh a row in place

  function dbLog(level, text) {
    var box = document.getElementById("dbLogs");
    if (!box) return;
    if (box.firstChild && box.firstChild.classList && box.firstChild.classList.contains("dblog-empty")) {
      box.innerHTML = "";
    }
    var row = document.createElement("div");
    row.style.padding = "1px 0";
    var color = level === "error" ? "#f85149"
              : level === "ok"    ? "#3fb950"
              : level === "warn"  ? "#d29922"
              : "var(--text-muted)";
    row.style.color = color;
    var ts = new Date().toLocaleTimeString();
    var icon = level === "error" ? "✗" : level === "ok" ? "✓" : level === "warn" ? "⚠" : "•";
    row.textContent = ts + " " + icon + " " + text;
    box.appendChild(row);
    // Cap at 200 lines.
    while (box.childNodes.length > 200) box.removeChild(box.firstChild);
    box.scrollTop = box.scrollHeight;
  }
  function clearDBLogs() {
    var box = document.getElementById("dbLogs");
    if (box) box.innerHTML = '<div class="dblog-empty" style="color:var(--text-muted);">No activity yet.</div>';
  }
  window.clearDBLogs = clearDBLogs;

  // Replace renderDBResult with an editable-aware version. Unfortunately
  // the function is defined earlier; we override window.renderDBResult
  // here so callers in this script see the new behaviour.
  function renderDBResultEditable(result) {
    _dbLastResult = result;
    var wrap = document.getElementById("dbResultWrap");
    if (!wrap) return;
    if (!result.is_result_set) {
      wrap.innerHTML = '<div style="padding:1rem;color:var(--text-muted);font-size:0.82rem;">Statement executed. ' +
        (result.rows_affected || 0) + ' row(s) affected.</div>';
      return;
    }
    var cols = result.columns || [];
    var rows = result.rows || [];
    if (rows.length === 0) {
      wrap.innerHTML = '<div style="padding:1rem;color:var(--text-muted);font-size:0.82rem;">No rows returned.</div>';
      return;
    }
    var meta = result.editable; // { schema, table, primary_key: [...] } or undefined
    var editable = !!meta;
    var pkSet = {};
    if (editable) {
      for (var i = 0; i < meta.primary_key.length; i++) pkSet[meta.primary_key[i].toLowerCase()] = true;
    }

    var head = '<tr>' + cols.map(function(c) {
      var marker = pkSet[c.toLowerCase()] ? ' <span style="color:#3fb950;font-size:0.6rem;" title="Primary key">PK</span>' : '';
      return '<th style="text-align:left;padding:6px 10px;font-size:0.7rem;color:var(--text-muted);background:var(--bg-input);position:sticky;top:0;border-bottom:1px solid var(--border);">' + escapeHtml(c) + marker + '</th>';
    }).join('') + '</tr>';

    var body = rows.map(function(r, rowIdx) {
      return '<tr data-row="' + rowIdx + '">' + r.map(function(v, colIdx) {
        var col = cols[colIdx];
        var isPK = pkSet[col.toLowerCase()];
        var canEdit = editable && !isPK;
        var disp = (v === null || v === undefined)
          ? '<span style="color:var(--text-muted);font-style:italic;">NULL</span>'
          : escapeHtml(String(v));
        var cellStyle = "padding:5px 10px;font-family:monospace;font-size:0.72rem;color:var(--text-primary);border-bottom:1px solid var(--border);max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;";
        if (canEdit) {
          cellStyle += "cursor:pointer;";
        }
        var attrs = ' data-col="' + escapeHtml(col) + '" data-row-idx="' + rowIdx + '" data-col-idx="' + colIdx + '"';
        if (canEdit) attrs += ' ondblclick="startCellEdit(this)"';
        var titleVal = v === null ? "NULL (double-click to edit)" : String(v) + (canEdit ? " (double-click to edit)" : "");
        return '<td style="' + cellStyle + '" title="' + escapeHtml(titleVal) + '"' + attrs + '>' + disp + '</td>';
      }).join('') + '</tr>';
    }).join('');

    var hint = editable
      ? '<div style="padding:4px 10px;font-size:0.66rem;color:var(--text-muted);background:rgba(63,185,80,0.08);border-bottom:1px solid var(--border);">✎ Editable: <code>' + escapeHtml(meta.schema) + '.' + escapeHtml(meta.table) + '</code> · double-click any non-PK cell to edit · Enter to save · Esc to cancel</div>'
      : '<div style="padding:4px 10px;font-size:0.66rem;color:var(--text-muted);background:var(--bg-input);border-bottom:1px solid var(--border);">Read-only result (single-table SELECT against postgres + complete PK in projection unlocks inline edit)</div>';

    wrap.innerHTML = hint + '<table style="width:100%;border-collapse:collapse;">' + head + body + '</table>';
  }
  // Make renderDBResultEditable the canonical renderer called by runDBQuery.
  // The earlier definition still exists for back-compat, but we point the
  // function name at this one going forward.
  renderDBResult = renderDBResultEditable; // eslint-disable-line no-func-assign
  window.renderDBResult = renderDBResultEditable;

  // looksLikeJSON checks if a string is plausibly JSON or a postgres
  // array literal. Used to decide between single-line input and
  // multiline textarea for the cell editor.
  function looksLikeJSON(s) {
    if (typeof s !== "string") return false;
    var t = s.trim();
    return (t.startsWith("{") && t.endsWith("}")) ||
           (t.startsWith("[") && t.endsWith("]"));
  }
  // Heuristic: use a textarea when the value is long, has newlines,
  // or looks like JSON / array. Future: when we cache the schema
  // metadata for the active connection, we'll consult column types
  // (jsonb, json, array) directly. For now the heuristic catches the
  // common cases.
  function shouldUseMultilineEditor(displayVal) {
    if (typeof displayVal !== "string") return false;
    if (displayVal.length > 80) return true;
    if (displayVal.indexOf("\n") !== -1) return true;
    if (looksLikeJSON(displayVal)) return true;
    return false;
  }

  function startCellEdit(td) {
    if (!_dbLastResult || !_dbLastResult.editable) return;
    if (td.dataset.editing === "1") return;
    var rowIdx = parseInt(td.dataset.rowIdx, 10);
    var colIdx = parseInt(td.dataset.colIdx, 10);
    if (isNaN(rowIdx) || isNaN(colIdx)) return;
    var current = _dbLastResult.rows[rowIdx][colIdx];
    var displayVal = (current === null || current === undefined) ? "" : String(current);

    td.dataset.editing = "1";
    td.dataset.original = displayVal;
    td.style.padding = "0";
    td.style.whiteSpace = "normal";
    td.style.maxWidth = "none";
    td.innerHTML = "";

    var multiline = shouldUseMultilineEditor(displayVal);
    var editor;
    if (multiline) {
      editor = document.createElement("textarea");
      editor.rows = Math.max(3, Math.min(15, displayVal.split("\n").length + 1));
      editor.style.cssText = "width:100%;min-height:80px;padding:6px 10px;background:var(--bg-input);border:1px solid var(--accent);border-radius:0;color:var(--text-primary);font-family:monospace;font-size:0.74rem;resize:vertical;";
      // Pretty-print JSON if it parses, so the operator sees structure.
      if (looksLikeJSON(displayVal)) {
        try { editor.value = JSON.stringify(JSON.parse(displayVal), null, 2); }
        catch(e) { editor.value = displayVal; }
      } else {
        editor.value = displayVal;
      }
    } else {
      editor = document.createElement("input");
      editor.type = "text";
      editor.value = displayVal;
      editor.style.cssText = "width:100%;padding:5px 10px;background:var(--bg-input);border:1px solid var(--accent);border-radius:0;color:var(--text-primary);font-family:monospace;font-size:0.72rem;";
    }
    td.appendChild(editor);
    editor.focus();
    if (typeof editor.select === "function") editor.select();

    // Show inline help for multiline so the operator knows Ctrl+Enter
    // saves and Escape cancels (a plain Enter inserts a newline in the
    // textarea, unlike the single-line input).
    if (multiline) {
      var hint = document.createElement("div");
      hint.style.cssText = "padding:3px 10px;font-size:0.64rem;color:var(--text-muted);background:var(--bg-input);border-top:1px solid var(--border);";
      hint.textContent = "Ctrl+Enter (Cmd+Enter) saves · Esc cancels · JSON is pretty-printed for editing and re-serialised on save";
      td.appendChild(hint);
    }

    function commit(save) {
      if (td.dataset.editing !== "1") return;
      td.dataset.editing = "0";
      var newVal = editor.value;
      // For JSON-shaped editing, re-compact before sending so postgres
      // gets the canonical form. If the user wrote invalid JSON, send
      // as-is and let the server's $1::jsonb cast complain.
      if (multiline && looksLikeJSON(td.dataset.original)) {
        try { newVal = JSON.stringify(JSON.parse(newVal)); } catch(e) { /* keep raw */ }
      }
      if (!save || newVal === td.dataset.original) {
        renderDBResultEditable(_dbLastResult);
        return;
      }
      submitCellUpdate(rowIdx, colIdx, newVal);
    }
    editor.addEventListener("keydown", function(e) {
      if (multiline) {
        if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); commit(true); }
        else if (e.key === "Escape") { e.preventDefault(); commit(false); }
      } else {
        if (e.key === "Enter") { e.preventDefault(); commit(true); }
        else if (e.key === "Escape") { e.preventDefault(); commit(false); }
      }
    });
    editor.addEventListener("blur", function() {
      if (td.dataset.editing === "1") commit(true);
    });
  }
  window.startCellEdit = startCellEdit;

  // ── Schema browser modal ───────────────────────────────────────────
  // Loads schemas/tables/columns from /api/db/schema and renders them
  // as a collapsible tree. Each table has SELECT / INSERT / UPDATE
  // template buttons that drop a starter query into the editor.

  var _dbSchema = null;
  var _dbSchemaConnId = null;

  async function openDBSchemaBrowser(connId) {
    _dbSchemaConnId = connId;
    document.getElementById("dbSchemaContent").innerHTML = '<div class="spinner"><div class="spinner-ring"></div>Loading…</div>';
    document.getElementById("dbSchemaFilter").value = "";
    document.getElementById("dbSchemaModal").style.display = "flex";
    try {
      var resp = await apiFetch("/api/db/schema?connection_id=" + encodeURIComponent(connId));
      _dbSchema = (resp && resp.data) || { schemas: [] };
      renderDBSchemaTree();
    } catch (err) {
      document.getElementById("dbSchemaContent").innerHTML =
        '<div style="color:var(--red);padding:0.75rem;font-size:0.78rem;">Failed to load: ' + escapeHtml((err && err.message) || "error") + '</div>';
    }
  }
  function closeDBSchemaBrowser() {
    document.getElementById("dbSchemaModal").style.display = "none";
  }

  function renderDBSchemaTree() {
    var box = document.getElementById("dbSchemaContent");
    if (!box) return;
    if (!_dbSchema || !_dbSchema.schemas || _dbSchema.schemas.length === 0) {
      box.innerHTML = '<div style="color:var(--text-muted);padding:0.75rem;">No tables found in this database.</div>';
      return;
    }
    var filter = (document.getElementById("dbSchemaFilter").value || "").toLowerCase();
    var html = "";
    _dbSchema.schemas.forEach(function(sch) {
      var schTables = (sch.tables || []).filter(function(t) {
        if (!filter) return true;
        if (t.name.toLowerCase().indexOf(filter) !== -1) return true;
        return (t.columns || []).some(function(c) { return c.name.toLowerCase().indexOf(filter) !== -1; });
      });
      if (schTables.length === 0) return;
      html += '<div style="margin-bottom:8px;">';
      html += '<div style="font-weight:700;color:var(--accent);font-size:0.78rem;padding:4px 0;">' + escapeHtml(sch.name) + ' <span style="color:var(--text-muted);font-weight:400;">(' + schTables.length + ' relations)</span></div>';
      schTables.forEach(function(t, idx) {
        var key = sch.name + '.' + t.name;
        var kindBadge = '';
        if (t.kind === 'view')        kindBadge = '<span style="background:#1a3a3a;color:#5de4cc;padding:0 5px;border-radius:3px;font-size:0.6rem;margin-left:4px;">view</span>';
        else if (t.kind === 'matview')kindBadge = '<span style="background:#3a2a1a;color:#d4a85d;padding:0 5px;border-radius:3px;font-size:0.6rem;margin-left:4px;">matview</span>';
        else if (t.kind === 'foreign')kindBadge = '<span style="background:#3a1a3a;color:#d45dd4;padding:0 5px;border-radius:3px;font-size:0.6rem;margin-left:4px;">foreign</span>';
        else if (t.kind === 'partitioned') kindBadge = '<span style="background:#1a2a3a;color:#5da8d4;padding:0 5px;border-radius:3px;font-size:0.6rem;margin-left:4px;">partitioned</span>';
        html += '<div style="margin-left:8px;border-left:1px solid var(--border);padding-left:10px;margin-bottom:4px;">';
        html += '<div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;padding:3px 0;">';
        html +=   '<button type="button" onclick="toggleSchemaTable(\'' + escapeHtml(key) + '\')" id="ttog-' + escapeHtml(key) + '" style="background:none;border:none;color:var(--text-primary);cursor:pointer;font-family:monospace;padding:0;font-size:0.78rem;">▸ ' + escapeHtml(t.name) + '</button>';
        html += kindBadge;
        html += '<span style="flex:1;"></span>';
        html += '<button type="button" onclick="schemaInsertSelect(\'' + escapeHtml(sch.name) + '\',\'' + escapeHtml(t.name) + '\')" class="btn btn-sm btn-outline" style="font-size:0.62rem;padding:1px 6px;">SELECT</button>';
        if (t.kind !== 'view' && t.kind !== 'matview') {
          html += '<button type="button" onclick="schemaInsertUpdate(\'' + escapeHtml(sch.name) + '\',\'' + escapeHtml(t.name) + '\')" class="btn btn-sm btn-outline" style="font-size:0.62rem;padding:1px 6px;">UPDATE</button>';
          html += '<button type="button" onclick="schemaInsertInsert(\'' + escapeHtml(sch.name) + '\',\'' + escapeHtml(t.name) + '\')" class="btn btn-sm btn-outline" style="font-size:0.62rem;padding:1px 6px;">INSERT</button>';
        }
        html += '</div>';
        html += '<div id="tcols-' + escapeHtml(key) + '" style="display:none;padding:3px 0 6px 12px;">';
        (t.columns || []).forEach(function(c) {
          var pkBadge = c.is_pk ? ' <span style="color:#3fb950;font-size:0.6rem;">PK</span>' : '';
          var nullBadge = c.nullable ? '' : ' <span style="color:#f85149;font-size:0.6rem;" title="NOT NULL">NN</span>';
          var defBadge = c.default ? ' <span style="color:var(--text-muted);font-size:0.6rem;" title="default: ' + escapeHtml(c.default) + '">def</span>' : '';
          html += '<div style="font-size:0.7rem;color:var(--text-muted);padding:1px 0;">' +
                  '<span style="color:var(--text-primary);">' + escapeHtml(c.name) + '</span>' + pkBadge + nullBadge + defBadge +
                  ' <span style="color:#5db4d4;">' + escapeHtml(c.type) + '</span>' +
                  '</div>';
        });
        html += '</div>';
        html += '</div>';
      });
      html += '</div>';
    });
    box.innerHTML = html;
  }
  function filterDBSchemaTree() { renderDBSchemaTree(); }

  function toggleSchemaTable(key) {
    var div = document.getElementById("tcols-" + key);
    var btn = document.getElementById("ttog-" + key);
    if (!div) return;
    if (div.style.display === "none") {
      div.style.display = "block";
      if (btn) btn.textContent = btn.textContent.replace("▸", "▾");
    } else {
      div.style.display = "none";
      if (btn) btn.textContent = btn.textContent.replace("▾", "▸");
    }
  }

  // schemaFindTable looks up a table in the loaded tree. Returns null if
  // not found (e.g. operator manipulated the DOM during load).
  function schemaFindTable(schema, table) {
    if (!_dbSchema) return null;
    for (var i = 0; i < _dbSchema.schemas.length; i++) {
      if (_dbSchema.schemas[i].name !== schema) continue;
      var tables = _dbSchema.schemas[i].tables || [];
      for (var j = 0; j < tables.length; j++) {
        if (tables[j].name === table) return tables[j];
      }
    }
    return null;
  }

  // putQueryAndClose drops `sql` into the editor, switches the active
  // connection if needed, and closes the schema modal. Never auto-runs.
  function putQueryAndClose(sql) {
    var ta = document.getElementById("dbQuery");
    if (ta) ta.value = sql;
    if (_dbSchemaConnId && _dbSchemaConnId !== _dbActiveConnId) {
      selectDBConnection(_dbSchemaConnId);
    }
    closeDBSchemaBrowser();
    if (ta) ta.focus();
  }

  function schemaInsertSelect(schema, table) {
    var t = schemaFindTable(schema, table);
    var cols = t ? (t.columns || []).map(function(c) { return '"' + c.name + '"'; }) : ['*'];
    var sql = 'SELECT ' + cols.join(', ') + '\nFROM "' + schema + '"."' + table + '"\nLIMIT 100;';
    putQueryAndClose(sql);
  }
  function schemaInsertUpdate(schema, table) {
    var t = schemaFindTable(schema, table);
    if (!t) return;
    var nonPK = (t.columns || []).filter(function(c) { return !c.is_pk; });
    var pk = (t.columns || []).filter(function(c) { return c.is_pk; });
    var setLines = nonPK.map(function(c) { return '  "' + c.name + '" = NULL  -- ' + c.type; }).join(',\n');
    var whereLines = pk.length > 0
      ? pk.map(function(c) { return '"' + c.name + '" = NULL  -- ' + c.type; }).join(' AND ')
      : '"id" = NULL  -- no PK detected; provide a WHERE manually';
    var sql = '-- Replace NULLs and uncomment / edit each line you need\n' +
              'UPDATE "' + schema + '"."' + table + '" SET\n' + setLines + '\nWHERE ' + whereLines + ';';
    putQueryAndClose(sql);
  }
  function schemaInsertInsert(schema, table) {
    var t = schemaFindTable(schema, table);
    if (!t) return;
    var insertable = (t.columns || []).filter(function(c) {
      // Skip columns with a default and that are PK (typically serial/identity).
      return !(c.is_pk && c.default);
    });
    var colList = insertable.map(function(c) { return '"' + c.name + '"'; }).join(', ');
    var valList = insertable.map(function(c) { return 'NULL  /* ' + c.type + (c.nullable ? '' : ' NOT NULL') + ' */'; }).join(',\n  ');
    var sql = 'INSERT INTO "' + schema + '"."' + table + '" (\n  ' + colList + '\n) VALUES (\n  ' + valList + '\n);';
    putQueryAndClose(sql);
  }

  // Backdrop close.
  var schModal = document.getElementById("dbSchemaModal");
  if (schModal) {
    schModal.addEventListener("click", function(e) { if (e.target === this) closeDBSchemaBrowser(); });
  }

  window.openDBSchemaBrowser  = openDBSchemaBrowser;
  window.closeDBSchemaBrowser = closeDBSchemaBrowser;
  window.toggleSchemaTable    = toggleSchemaTable;
  window.filterDBSchemaTree   = filterDBSchemaTree;
  window.schemaInsertSelect   = schemaInsertSelect;
  window.schemaInsertUpdate   = schemaInsertUpdate;
  window.schemaInsertInsert   = schemaInsertInsert;

  async function submitCellUpdate(rowIdx, colIdx, newVal) {
    if (!_dbLastResult || !_dbLastResult.editable) return;
    var meta = _dbLastResult.editable;
    var col = _dbLastResult.columns[colIdx];

    // Build pk_values + expected_values from the row snapshot we
    // currently have on screen. expected_values is everything the
    // operator saw at SELECT time; the server uses it for an
    // optimistic-concurrency CAS so the UPDATE only applies if NO
    // column in the row was modified concurrently. The cell being
    // edited is included with its ORIGINAL value (pre-edit) so we
    // also detect if the same cell raced with another writer.
    var pkValues = {};
    var expectedValues = {};
    var pkSet = {};
    for (var k = 0; k < meta.primary_key.length; k++) {
      pkSet[meta.primary_key[k].toLowerCase()] = true;
    }
    for (var i = 0; i < _dbLastResult.columns.length; i++) {
      var c = _dbLastResult.columns[i];
      var v = _dbLastResult.rows[rowIdx][i];
      if (pkSet[c.toLowerCase()]) {
        pkValues[c] = v;
      } else {
        // Snapshot ALL non-PK columns including the one being edited
        // (with its ORIGINAL value — newVal is the future value, not
        // part of the CAS).
        expectedValues[c] = v;
      }
    }

    // Treat empty string as SQL NULL only when the original was null.
    // Otherwise '' stays ''.
    var sendVal = newVal;
    if (newVal === "" && _dbLastResult.rows[rowIdx][colIdx] === null) {
      sendVal = null;
    }

    dbLog("info", 'UPDATE "' + meta.schema + '"."' + meta.table + '" SET "' + col + '" = $1 WHERE PK + CAS(' + Object.keys(expectedValues).length + ' cols) …');
    try {
      var resp = await apiFetch("/api/db/cell-update", {
        method: "POST",
        body: {
          connection_id: _dbActiveConnId,
          schema: meta.schema,
          table: meta.table,
          column: col,
          new_value: sendVal,
          pk_values: pkValues,
          expected_values: expectedValues
        }
      });
      var d = (resp && resp.data) || {};
      _dbLastResult.rows[rowIdx][colIdx] = (d.new_value !== undefined) ? d.new_value : sendVal;
      renderDBResultEditable(_dbLastResult);
      var skippedNote = (d.cas_skipped && d.cas_skipped.length)
        ? ' · CAS skipped: ' + d.cas_skipped.join(", ")
        : '';
      dbLog("ok", '1 row updated in ' + (d.duration_ms || 0) + ' ms · CAS(' + (d.cas_column_count || 0) + ' cols)' + skippedNote);
    } catch (err) {
      // Rollback the visual edit and surface the error. The server
      // distinguishes "deleted" vs "modified concurrently" via the
      // conflict_kind field in the response Data — apiFetch only
      // bubbles up the message string, but we can hint based on its
      // text content.
      renderDBResultEditable(_dbLastResult);
      var msg = (err && err.message) || "cell update failed";
      var level = "error";
      if (msg.indexOf("modified concurrently") !== -1) {
        level = "warn"; // not really our error — someone else's edit raced us
      }
      dbLog(level, msg);
    }
  }

  // Hook the existing runDBQuery to also dump a log line on success/error.
  // We wrap the original function in a closure so the log panel becomes
  // the single timeline of "what just happened on the DB".
  (function() {
    var orig = window.runDBQuery;
    if (typeof orig !== "function") return;
    window.runDBQuery = async function() {
      var sql = (document.getElementById("dbQuery") || {}).value || "";
      var preview = sql.replace(/\s+/g, " ").trim();
      if (preview.length > 80) preview = preview.slice(0, 77) + "…";
      dbLog("info", "executing: " + preview);
      try {
        await orig();
        // The original handler updates the status bar; we mirror to logs.
        var status = (document.getElementById("dbQueryStatus") || {}).textContent || "";
        if (status) {
          if (status.indexOf("✓") !== -1) dbLog("ok", status.replace(/^✓\s*/, ""));
          else if (status.indexOf("✗") !== -1) dbLog("error", status.replace(/^✗\s*/, ""));
        }
      } catch (e) {
        dbLog("error", (e && e.message) || "query failed");
      }
    };
  })();
