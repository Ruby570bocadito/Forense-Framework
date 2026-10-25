// Forense-Framework web UI: module option panels, confirmations and job polling.
(function () {
  "use strict";

  // Show only the option fields of the selected module.
  var select = document.getElementById("module-select");
  function syncOptions() {
    if (!select) return;
    document.querySelectorAll(".module-options").forEach(function (el) {
      el.classList.toggle("active", el.dataset.module === select.value);
    });
    var help = document.getElementById("module-help");
    var option = select.options[select.selectedIndex];
    if (help && option) help.textContent = option.dataset.description || "";
  }
  if (select) { select.addEventListener("change", syncOptions); syncOptions(); }

  // Confirmation for destructive actions.
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (ev) {
      if (!window.confirm(form.dataset.confirm)) ev.preventDefault();
    });
  });

  // Background jobs: live queue with progress and cancellation (SSE with polling fallback),
  // and a page reload when a job finishes.
  var box = document.getElementById("jobs");
  if (!box) return;
  var url = box.dataset.url;
  var known = {};
  function render(jobs) {
    var running = false, finishedNow = false;
    var list = box.querySelector("ul");
    list.textContent = "";
    jobs.slice(0, 8).forEach(function (job) {
      var li = document.createElement("li");
      var state = box.dataset["status" + job.status.charAt(0).toUpperCase() + job.status.slice(1)] || job.status;
      li.textContent = "[" + state + "] " + job.description;
      if (job.status === "running" && (job.stage || job.progress)) {
        var detail = job.total > 0 ? box.dataset.progress.replace("{done}", job.done).replace("{total}", job.total) + " — " : "";
        li.appendChild(document.createElement("div")).textContent = detail + (job.stage || job.progress);
      }
      if (job.message && job.status !== "running") {
        li.appendChild(document.createElement("div")).textContent = job.message;
      }
      if (job.link && job.status === "done") {
        var a = document.createElement("a");
        a.href = job.link; a.textContent = " → " + (box.dataset.open || "open");
        li.appendChild(a);
      }
      if (job.cancellable && (job.status === "queued" || job.status === "running")) {
        var form = document.createElement("form");
        form.method = "post";
        form.action = box.dataset.cancelUrl.replace("JOBID", job.id);
        form.className = "inline";
        var csrf = document.createElement("input");
        csrf.type = "hidden"; csrf.name = "csrf_token"; csrf.value = box.dataset.csrf;
        form.appendChild(csrf);
        var cancel = document.createElement("button");
        cancel.className = "secondary small"; cancel.type = "submit";
        cancel.textContent = box.dataset.cancelLabel || "Cancel";
        cancel.setAttribute("aria-label", (box.dataset.cancelLabel || "Cancel") + ": " + job.description);
        form.appendChild(cancel);
        li.appendChild(form);
      }
      if (job.status === "failed" || job.status === "cancelled") li.className = "bad";
      list.appendChild(li);
      if (job.status === "queued" || job.status === "running") running = true;
      if (known[job.id] && known[job.id] !== job.status && job.status !== "queued" && job.status !== "running") finishedNow = true;
      known[job.id] = job.status;
    });
    box.hidden = jobs.length === 0;
    if (finishedNow && box.dataset.reload === "1") window.location.reload();
    return running;
  }
  function poll() {
    var again = function (running) { window.setTimeout(poll, running ? 1500 : 6000); };
    fetch(url, { credentials: "same-origin" }).then(function (r) { return r.json(); }).then(function (jobs) {
      again(render(jobs));
    }).catch(function () { window.setTimeout(poll, 8000); });
  }
  if (box.dataset.stream && window.EventSource) {
    var source = new EventSource(box.dataset.stream);
    source.onmessage = function (ev) {
      var running;
      try { running = render(JSON.parse(ev.data)); } catch (err) { return; }
      if (!running) { source.close(); window.setTimeout(poll, 6000); }  // idle: back to a slow poll
    };
    source.onerror = function () { source.close(); poll(); };  // stream unavailable: plain polling
  } else {
    poll();
  }
})();

// Chart tooltips: any element with data-tip (SVG marks included) shows its text next to the pointer.
(function () {
  "use strict";
  var tip = null;
  function show(ev) {
    var target = ev.target.closest ? ev.target.closest("[data-tip]") : null;
    if (!target) { hide(); return; }
    if (!tip) { tip = document.createElement("div"); tip.className = "viz-tooltip"; document.body.appendChild(tip); }
    tip.textContent = target.getAttribute("data-tip");
    tip.hidden = false;
    var x = ev.clientX + 14, y = ev.clientY + 14;
    var w = tip.offsetWidth, h = tip.offsetHeight;
    if (x + w > window.innerWidth - 8) x = ev.clientX - w - 14;
    if (y + h > window.innerHeight - 8) y = ev.clientY - h - 14;
    tip.style.left = x + "px"; tip.style.top = y + "px";
  }
  function hide() { if (tip) tip.hidden = true; }
  document.addEventListener("mousemove", show);
  document.addEventListener("mouseleave", hide);
  document.addEventListener("scroll", hide, true);
})();

// "Use as draft" copies the generated narrative into the conclusions editor.
(function () {
  "use strict";
  document.querySelectorAll("[data-copy-target]").forEach(function (button) {
    button.addEventListener("click", function () {
      var source = document.getElementById(button.dataset.copySource);
      var target = document.getElementById(button.dataset.copyTarget);
      if (source && target) { target.value = source.value; target.focus(); }
    });
  });
})();

// Findings bulk review: the header checkbox toggles the checkboxes of the visible rows.
(function () {
  "use strict";
  document.addEventListener("change", function (ev) {
    var box = ev.target;
    if (!box.matches || !box.matches("input[data-checkall]")) return;
    document.querySelectorAll('table input[name="ids"]').forEach(function (cell) {
      cell.checked = box.checked;
    });
  });
})();
