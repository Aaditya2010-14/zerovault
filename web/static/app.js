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

// Show/Hide password toggle: the real value already sits in the page
// (data-secret attribute, escaped by html/template) — toggling is a pure
// display change, never a separate fetch, so there's no extra network
// request that could leak the password to a proxy or extension.
document.addEventListener("click", function (e) {
  var btn = e.target.closest("[data-toggle-secret]");
  if (!btn) return;
  var span = btn.previousElementSibling;
  if (!span || !span.classList.contains("secret")) return;

  var revealed = span.getAttribute("data-revealed") === "true";
  if (revealed) {
    span.textContent = "••••••••";
    span.setAttribute("data-revealed", "false");
    btn.textContent = "Show";
  } else {
    span.textContent = span.getAttribute("data-secret");
    span.setAttribute("data-revealed", "true");
    btn.textContent = "Hide";
  }
});

// Highlight the current section in the nav.
(function () {
  var links = document.querySelectorAll("nav .nav-links a");
  links.forEach(function (a) {
    if (a.getAttribute("href") === window.location.pathname) {
      a.classList.add("active");
    }
  });
})();

// About page: scramble the hex-banner text to look like an encrypted vault
// file, swapping a handful of characters every tick.
(function () {
  var el = document.getElementById("hex-banner");
  if (!el) return;

  var hexChars = "0123456789abcdef";
  var length = 128;
  var chars = [];
  for (var i = 0; i < length; i++) {
    chars.push(hexChars[Math.floor(Math.random() * hexChars.length)]);
  }
  el.textContent = chars.join("");

  setInterval(function () {
    var swaps = 6 + Math.floor(Math.random() * 7); // 6-12 characters
    for (var i = 0; i < swaps; i++) {
      var idx = Math.floor(Math.random() * length);
      chars[idx] = hexChars[Math.floor(Math.random() * hexChars.length)];
    }
    el.textContent = chars.join("");
  }, 80);
})();

// Live-filter the vault entry grid as you type.
(function () {
  var input = document.getElementById("entry-search");
  var grid = document.getElementById("entry-grid");
  if (!input || !grid) return;

  var cards = Array.prototype.slice.call(grid.querySelectorAll(".entry-card"));

  input.addEventListener("input", function () {
    var q = input.value.trim().toLowerCase();
    cards.forEach(function (card) {
      var name = (card.getAttribute("data-name") || "").toLowerCase();
      card.style.display = name.indexOf(q) === -1 ? "none" : "";
    });
  });
})();

// Confirm destructive actions.
document.addEventListener("submit", function (e) {
  var form = e.target;
  if (form.hasAttribute("data-confirm")) {
    if (!window.confirm(form.getAttribute("data-confirm"))) {
      e.preventDefault();
    }
  }
});
