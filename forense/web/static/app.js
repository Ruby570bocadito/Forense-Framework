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
