// Minimal vanilla JS — no framework, no build step.

// TOTP countdown: each [data-remaining] element holds the server-computed
// seconds-until-refresh at page load. Count it down client-side and reload
// the page once it hits zero so displayed codes never go stale.
(function () {
  var els = document.querySelectorAll("[data-remaining]");
  if (els.length === 0) return;

  var remaining = parseInt(els[0].getAttribute("data-remaining"), 10);
  if (isNaN(remaining)) return;

  var timer = setInterval(function () {
    remaining -= 1;
    if (remaining <= 0) {
      clearInterval(timer);
      window.location.reload();
      return;
    }
    els.forEach(function (el) {
      el.textContent = remaining + "s";
    });
  }, 1000);
})();

// Copy-to-clipboard buttons: [data-copy] holds the text to copy.
document.addEventListener("click", function (e) {
  var btn = e.target.closest("[data-copy]");
  if (!btn) return;
  var text = btn.getAttribute("data-copy");
  if (!navigator.clipboard) return;
  navigator.clipboard.writeText(text).then(function () {
    var original = btn.textContent;
    btn.textContent = "Copied!";
    setTimeout(function () {
      btn.textContent = original;
    }, 1500);
  });
});

// Confirm destructive actions.
document.addEventListener("submit", function (e) {
  var form = e.target;
  if (form.hasAttribute("data-confirm")) {
    if (!window.confirm(form.getAttribute("data-confirm"))) {
      e.preventDefault();
    }
  }
});
