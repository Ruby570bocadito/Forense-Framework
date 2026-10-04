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

  // Poll background jobs and reload the page when one finishes.
  var box = document.getElementById("jobs");
  if (!box) return;
  var url = box.dataset.url;
  var known = {};
  function poll() {
    fetch(url, { credentials: "same-origin" }).then(function (r) { return r.json(); }).then(function (jobs) {
      var running = false, finishedNow = false;
      var list = box.querySelector("ul");
      list.textContent = "";
      jobs.slice(0, 8).forEach(function (job) {
        var li = document.createElement("li");
        var state = box.dataset["status" + job.status.charAt(0).toUpperCase() + job.status.slice(1)] || job.status;
        li.textContent = "[" + state + "] " + job.description + (job.progress && job.status === "running" ? " — " + job.progress : "") +
          (job.message ? " — " + job.message : "");
        if (job.link && job.status === "done") {
          var a = document.createElement("a");
          a.href = job.link; a.textContent = " → " + (box.dataset.open || "open");
          li.appendChild(a);
        }
        if (job.status === "failed") li.className = "bad";
        list.appendChild(li);
        if (job.status === "queued" || job.status === "running") running = true;
        if (known[job.id] && known[job.id] !== job.status && (job.status === "done" || job.status === "failed")) finishedNow = true;
        known[job.id] = job.status;
      });
      box.hidden = jobs.length === 0;
      if (finishedNow && box.dataset.reload === "1") window.location.reload();
      window.setTimeout(poll, running ? 1500 : 6000);
    }).catch(function () { window.setTimeout(poll, 8000); });
  }
  poll();
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
