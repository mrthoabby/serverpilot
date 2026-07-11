// ── Cases ─────────────────────────────────────────────────────────────────
(function() {
  var casesFilter = '';       // '' | 'public' | 'private'
  var casesData   = [];       // last fetched list
  var caseDeleteId = null;    // id pending delete confirmation
  var onEl = window.onEl || function(id, event, handler) {
    var el = document.getElementById(id);
    if (el) el.addEventListener(event, handler);
    return el;
  };

  // Filter toggle
  window.setCasesFilter = function(v) {
    casesFilter = v;
    var btns = { '': 'casesFilterAll', 'public': 'casesFilterPublic', 'private': 'casesFilterPrivate' };
    Object.keys(btns).forEach(function(k) {
      var el = document.getElementById(btns[k]);
      if (el) {
        el.style.background = (k === v) ? 'var(--accent)' : 'none';
        el.style.color      = (k === v) ? '#fff' : 'var(--text-secondary)';
      }
    });
    var lbl = document.getElementById('casesFilterLabel');
    if (lbl) lbl.textContent = v ? ('Showing ' + v + ' only') : '';
    renderCases(casesData);
  };

  // Load cases from API
  window.loadCases = function() {
    apiFetch('/api/cases').then(function(data) {
      casesData = data.data || [];
      document.getElementById('caseCount').textContent = casesData.length;
      renderCases(casesData);
    }).catch(function(e) {
      document.getElementById('casesContent').innerHTML =
        '<div style="padding:1.5rem;color:var(--red);font-size:0.875rem;">Failed to load cases: ' + esc(e.message) + '</div>';
    });
  };

  function renderCases(all) {
    var list = casesFilter ? all.filter(function(c) { return c.visibility === casesFilter; }) : all;
    var el = document.getElementById('casesContent');
    if (!list.length) {
      var msg = casesFilter
        ? 'No ' + casesFilter + ' cases yet.'
        : 'No cases yet. Click <strong>New Case</strong> to create one.';
      el.innerHTML = '<div class="cases-empty">' + msg + '</div>';
      return;
    }
    el.innerHTML = list.map(function(c) {
      var badge = c.visibility === 'private'
        ? '<span class="case-badge-private">🔒 Private</span>'
        : '<span class="case-badge-public">🌐 Public</span>';
      var tags = (c.tags || []).map(function(t) {
        return '<span class="case-tag">' + esc(t) + '</span>';
      }).join('');
      var desc = c.description
        ? '<div class="case-card-desc">' + esc(c.description) + '</div>'
        : '<div class="case-card-desc" style="color:var(--text-muted);font-style:italic;">No description</div>';
      var ts = c.updated_at ? new Date(c.updated_at).toLocaleDateString() : '';
      return '<div class="case-card" onclick="openCaseModal(' + JSON.stringify(c).replace(/"/g, '&quot;') + ')">' +
        '<div class="case-card-actions" onclick="event.stopPropagation();">' +
          '<button class="case-action-btn" onclick="openCaseModal(' + JSON.stringify(c).replace(/"/g, '&quot;') + ')">Edit</button>' +
          '<button class="case-action-btn del" onclick="openCaseDeleteModal(' + JSON.stringify(c).replace(/"/g, '&quot;') + ')">Delete</button>' +
        '</div>' +
        '<div class="case-card-header">' + badge + '<span class="case-card-title">' + esc(c.title) + '</span></div>' +
        desc +
        '<div class="case-card-footer">' + tags + (ts ? '<span style="font-size:0.7rem;color:var(--text-muted);margin-left:auto;">Updated ' + ts + '</span>' : '') + '</div>' +
      '</div>';
    }).join('');
  }

  // Escape helper
  function esc(s) {
    if (!s) return '';
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  // Open modal for view/edit (pass null for new)
  window.openCaseModal = function(caseObj) {
    document.getElementById('caseModal').style.display = 'flex';
    document.getElementById('caseModalErr').textContent = '';

    if (!caseObj) {
      // New case
      document.getElementById('caseModalTitle').textContent = 'New Case';
      document.getElementById('caseEditId').value = '';
      document.getElementById('caseInputTitle').value = '';
      document.getElementById('caseInputDesc').value = '';
      document.getElementById('caseInputTags').value = '';
      document.getElementById('caseVisPublic').checked = true;
      onCaseVisibilityChange();
      document.getElementById('caseViewMode').style.display = 'none';
      document.getElementById('caseEditMode').style.display = 'block';
      document.getElementById('caseModalSaveBtn').textContent = 'Create';
    } else {
      // View/edit existing
      document.getElementById('caseModalTitle').textContent = caseObj.title;
      document.getElementById('caseEditId').value = caseObj.id;
      // Populate edit fields for potential switch to edit
      document.getElementById('caseInputTitle').value = caseObj.title;
      document.getElementById('caseInputDesc').value = caseObj.description || '';
      document.getElementById('caseInputTags').value = (caseObj.tags || []).join(', ');
      if (caseObj.visibility === 'private') {
        document.getElementById('caseVisPrivate').checked = true;
      } else {
        document.getElementById('caseVisPublic').checked = true;
      }
      onCaseVisibilityChange();
      document.getElementById('caseModalSaveBtn').textContent = 'Save';
      // Render view pane
      var badge = caseObj.visibility === 'private'
        ? '<span class="case-badge-private">🔒 Private</span>'
        : '<span class="case-badge-public">🌐 Public</span>';
      document.getElementById('caseViewVisibilityBadge').innerHTML = badge;
      document.getElementById('caseViewTitleEl').textContent = caseObj.title;
      document.getElementById('caseViewDesc').textContent = caseObj.description || '(no description)';
      document.getElementById('caseViewTags').innerHTML = (caseObj.tags || []).map(function(t) {
        return '<span class="case-tag">' + esc(t) + '</span>';
      }).join('');
      var created = caseObj.created_at ? new Date(caseObj.created_at).toLocaleString() : '';
      var updated = caseObj.updated_at ? new Date(caseObj.updated_at).toLocaleString() : '';
      document.getElementById('caseViewMeta').textContent = 'Created: ' + created + (updated ? ' · Updated: ' + updated : '');
      document.getElementById('caseViewMode').style.display = 'block';
      document.getElementById('caseEditMode').style.display = 'none';
    }
    setTimeout(function() { document.getElementById('caseInputTitle').focus(); }, 50);
  };

  window.closeCaseModal = function() {
    document.getElementById('caseModal').style.display = 'none';
  };

  window.switchCaseToEdit = function() {
    document.getElementById('caseViewMode').style.display = 'none';
    document.getElementById('caseEditMode').style.display = 'block';
    setTimeout(function() { document.getElementById('caseInputTitle').focus(); }, 30);
  };

  window.onCaseVisibilityChange = function() {
    var isPrivate = document.getElementById('caseVisPrivate').checked;
    var lpub = document.getElementById('visLabelPublic');
    var lpriv = document.getElementById('visLabelPrivate');
    if (lpub)  { lpub.style.borderColor  = isPrivate ? 'var(--border)' : 'var(--accent)';  lpub.style.color  = isPrivate ? 'var(--text-secondary)' : 'var(--accent)'; }
    if (lpriv) { lpriv.style.borderColor = isPrivate ? 'var(--yellow)' : 'var(--border)'; lpriv.style.color = isPrivate ? 'var(--yellow)' : 'var(--text-secondary)'; }
  };

  window.saveCase = function() {
    var id    = document.getElementById('caseEditId').value;
    var title = document.getElementById('caseInputTitle').value.trim();
    var desc  = document.getElementById('caseInputDesc').value.trim();
    var vis   = document.getElementById('caseVisPrivate').checked ? 'private' : 'public';
    var rawTags = document.getElementById('caseInputTags').value;
    var tags  = rawTags.split(',').map(function(t){ return t.trim(); }).filter(Boolean);
    var errEl = document.getElementById('caseModalErr');

    if (!title) { errEl.textContent = 'Title is required.'; return; }

    var btn = document.getElementById('caseModalSaveBtn');
    btn.disabled = true;
    btn.textContent = 'Saving...';

    var url  = id ? '/api/cases/update' : '/api/cases/create';
    var body = id
      ? { id: id, title: title, description: desc, visibility: vis, tags: tags }
      : { title: title, description: desc, visibility: vis, tags: tags };

    apiFetch(url, { method: 'POST', body: JSON.stringify(body) }).then(function() {
      closeCaseModal();
      loadCases();
    }).catch(function(e) {
      errEl.textContent = e.message || 'Save failed.';
    }).finally(function() {
      btn.disabled = false;
      btn.textContent = id ? 'Save' : 'Create';
    });
  };

  // Delete modal
  window.openCaseDeleteModal = function(caseObj) {
    caseDeleteId = caseObj.id;
    document.getElementById('caseDeleteDesc').textContent =
      'Permanently delete "' + caseObj.title + '"? This cannot be undone.';
    document.getElementById('caseDeleteModal').style.display = 'flex';
  };

  window.closeCaseDeleteModal = function() {
    caseDeleteId = null;
    document.getElementById('caseDeleteModal').style.display = 'none';
  };

  window.confirmDeleteCase = function() {
    if (!caseDeleteId) return;
    var btn = document.getElementById('caseDeleteConfirmBtn');
    btn.disabled = true;
    btn.textContent = 'Deleting...';
    apiFetch('/api/cases/delete', { method: 'POST', body: JSON.stringify({ id: caseDeleteId }) })
      .then(function() {
        closeCaseDeleteModal();
        loadCases();
      })
      .catch(function(e) {
        closeCaseDeleteModal();
        showToast('Delete failed: ' + (e.message || 'unknown error'), 'error');
      })
      .finally(function() {
        btn.disabled = false;
        btn.textContent = 'Delete';
      });
  };

  // Close modals on backdrop click
  onEl('caseModal', 'click', function(e) {
    if (e.target === this) closeCaseModal();
  });
  onEl('caseDeleteModal', 'click', function(e) {
    if (e.target === this) closeCaseDeleteModal();
  });
})();
