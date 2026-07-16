/* Dashboard bootstrap + window exports */
"use strict";

window.SP = window.SP || {};

(async function init() {
  try {
    var resp = await apiFetch("/api/session/status");
    var data = resp && resp.data ? resp.data : resp;
    if (data && data.authenticated) {
      showDashboard();
    } else {
      showLogin();
    }
  } catch (e) {
    showLogin();
  }
})();

// Export core tab loaders and helpers for other scripts, inline handlers, and extensions.
window.loadContainers = loadContainers;
window.loadSites = loadSites;
window.loadImages = loadImages;
window.loadMappings = loadMappings;
window.loadResources = loadResources;
window.loadReplicas = loadReplicas;
window.loadLabels = loadLabels;
window.showLogin = showLogin;
window.showDashboard = showDashboard;
window.onEl = onEl;
window.setText = setText;
window.apiFetch = apiFetch;
window.showToast = showToast;
window.escapeHtml = escapeHtml;
window.promptReauth = promptReauth;
window.esc = esc;
window.loadSettings = loadSettings;
window.confirmAction = confirmAction;
window.runStreamedOperation = runStreamedOperation;
window.openConfigEditor = openConfigEditor;
window.openContainerLogsModal = openContainerLogsModal;
window.openGDAppActivateModal = openGDAppActivateModal;
window.openReplicaModal = openReplicaModal;
window.syncReplica = syncReplica;
window.deleteReplica = deleteReplica;
window.applyReplicaLabels = applyReplicaLabels;
window.containerForReplica = containerForReplica;
window.replicasByParentName = replicasByParentName;
window.checkForUpdates = checkForUpdates;

// Mirror on SP namespace for modular access.
window.SP.apiFetch = apiFetch;
window.SP.showToast = showToast;
window.SP.setText = setText;
window.SP.onEl = onEl;
window.SP.escapeHtml = escapeHtml;
window.SP.state = {
  containers: containers,
  sites: sites,
  mappings: mappings,
  images: images,
  containerLabels: containerLabels,
  containerReplicas: containerReplicas,
  activeTab: activeTab
};
