/* Images tab */
"use strict";

  async function loadImages() {
    var wrap = document.getElementById("imagesContent");
    try {
      var resp = await apiFetch("/api/images");
      images = (resp && resp.data) ? resp.data : (Array.isArray(resp) ? resp : []);
      setText(document.getElementById("imageCount"), String(images.length));
      selectedImageIDs = {};
      updateDeleteButtons();
      renderImages(wrap);
      updateTabTimestamp("images");
    } catch(err) {
      wrap.innerHTML = "";
      var em = document.createElement("div");
      em.className = "empty-state";
      var p = document.createElement("p");
      setText(p, "Failed to load images: " + err.message);
      em.appendChild(p);
      wrap.appendChild(em);
    }
  }

  function updateDeleteButtons() {
    var count = Object.keys(selectedImageIDs).length;
    var delBtn = document.getElementById("deleteSelectedImagesBtn");
    var forceBtn = document.getElementById("deleteSelectedForceBtn");
    if (count > 0) {
      delBtn.style.display = "";
      forceBtn.style.display = "";
      setText(delBtn, "Delete (" + count + ")");
      setText(forceBtn, "Force Delete (" + count + ")");
    } else {
      delBtn.style.display = "none";
      forceBtn.style.display = "none";
    }
  }

  function renderImages(wrap) {
    wrap.innerHTML = "";
    if (!images.length) {
      var em = document.createElement("div");
      em.className = "empty-state";
      var p = document.createElement("p");
      setText(p, "No Docker images found");
      em.appendChild(p);
      wrap.appendChild(em);
      return;
    }

    var tw = document.createElement("div");
    tw.className = "table-wrap";
    var table = document.createElement("table");

    var thead = document.createElement("thead");
    var trh = document.createElement("tr");

    // Select-all checkbox header
    var thCheck = document.createElement("th");
    thCheck.style.width = "36px";
    var selectAll = document.createElement("input");
    selectAll.type = "checkbox";
    selectAll.className = "img-checkbox";
    selectAll.title = "Select / deselect all";
    selectAll.addEventListener("change", function() {
      var checked = selectAll.checked;
      images.forEach(function(img) {
        if (checked) {
          selectedImageIDs[img.id] = true;
        } else {
          delete selectedImageIDs[img.id];
        }
      });
      // Update all row checkboxes.
      table.querySelectorAll("tbody .img-checkbox").forEach(function(cb) {
        cb.checked = checked;
      });
      updateDeleteButtons();
    });
    thCheck.appendChild(selectAll);
    trh.appendChild(thCheck);

    ["Repository", "Tag", "Image ID", "Size", "Created"].forEach(function(h) {
      var th = document.createElement("th");
      setText(th, h);
      trh.appendChild(th);
    });
    thead.appendChild(trh);
    table.appendChild(thead);

    var tbody = document.createElement("tbody");
    images.forEach(function(img) {
      var tr = document.createElement("tr");

      // Checkbox
      var tdCheck = document.createElement("td");
      var cb = document.createElement("input");
      cb.type = "checkbox";
      cb.className = "img-checkbox";
      cb.checked = !!selectedImageIDs[img.id];
      (function(imageID) {
        cb.addEventListener("change", function() {
          if (cb.checked) {
            selectedImageIDs[imageID] = true;
          } else {
            delete selectedImageIDs[imageID];
          }
          // Update select-all checkbox state.
          selectAll.checked = Object.keys(selectedImageIDs).length === images.length;
          updateDeleteButtons();
        });
      })(img.id);
      tdCheck.appendChild(cb);
      tr.appendChild(tdCheck);

      // Repository
      var tdRepo = document.createElement("td");
      var repoStrong = document.createElement("strong");
      setText(repoStrong, img.repository || "<none>");
      if (img.repository === "<none>") repoStrong.style.color = "var(--text-muted)";
      tdRepo.appendChild(repoStrong);
      tr.appendChild(tdRepo);

      // Tag
      var tdTag = document.createElement("td");
      var tagSpan = document.createElement("span");
      tagSpan.className = "port-tag";
      setText(tagSpan, img.tag || "<none>");
      if (img.tag === "<none>") tagSpan.style.color = "var(--text-muted)";
      tdTag.appendChild(tagSpan);
      tr.appendChild(tdTag);

      // Image ID (short)
      var tdID = document.createElement("td");
      var idSpan = document.createElement("span");
      idSpan.className = "img-id-short";
      idSpan.title = img.id;
      var shortID = img.id.replace("sha256:", "").substring(0, 12);
      setText(idSpan, shortID);
      tdID.appendChild(idSpan);
      tr.appendChild(tdID);

      // Size
      var tdSize = document.createElement("td");
      setText(tdSize, img.size || "-");
      tdSize.style.fontFamily = '"SF Mono","Fira Code",monospace';
      tdSize.style.fontSize = "0.8125rem";
      tr.appendChild(tdSize);

      // Created
      var tdCreated = document.createElement("td");
      tdCreated.style.color = "var(--text-secondary)";
      tdCreated.style.fontSize = "0.8125rem";
      setText(tdCreated, img.created || "-");
      tr.appendChild(tdCreated);

      tbody.appendChild(tr);
    });

    table.appendChild(tbody);
    tw.appendChild(table);
    wrap.appendChild(tw);
  }

  async function deleteSelectedImages(force) {
    var ids = Object.keys(selectedImageIDs);
    if (!ids.length) return;

    var label = force ? "Force delete" : "Delete";
    confirmAction(
      label + " " + ids.length + " image(s)?",
      "This will remove " + ids.length + " Docker image(s)" + (force ? " (forced, even if in use by containers)" : "") + ". This action cannot be undone.",
      async function() {
        try {
          var resp = await apiFetch("/api/images/delete", {
            method: "POST",
            body: { ids: ids, force: force }
          });
          var data = (resp && resp.data) ? resp.data : resp;
          var removedCount = data.removed ? data.removed.length : 0;
          var errorCount = data.errors ? data.errors.length : 0;

          if (removedCount > 0) {
            showToast(removedCount + " image(s) removed", "success");
          }
          if (errorCount > 0) {
            showToast(errorCount + " image(s) failed: " + data.errors[0], "error");
          }

          selectedImageIDs = {};
          await loadImages();
        } catch(err) {
          showToast("Failed to delete images: " + err.message, "error");
        }
      }
    );
  }

  onEl("deleteSelectedImagesBtn", "click", function() {
    deleteSelectedImages(false);
  });

  onEl("deleteSelectedForceBtn", "click", function() {
    deleteSelectedImages(true);
  });
