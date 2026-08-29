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

// Sliding nav pill: a blue block that glides beneath the tab you're on
// (current page) and previews under whichever tab you hover.
(function () {
  var nav = document.querySelector("nav");
  var pill = document.querySelector(".nav-pill");
  if (!nav || !pill) return;

  var links = Array.prototype.slice.call(nav.querySelectorAll("a")).filter(function (a) {
    return !a.classList.contains("brand");
  });
  if (links.length === 0) return;

  function moveTo(el, instant) {
    if (instant) pill.style.transition = "none";
    pill.style.width = el.offsetWidth + "px";
    pill.style.height = el.offsetHeight + "px";
    pill.style.transform = "translate(" + el.offsetLeft + "px, " + el.offsetTop + "px)";
    pill.style.opacity = "1";
    if (instant) {
      pill.offsetHeight; // force reflow so the instant placement paints before transitions resume
      pill.style.transition = "";
    }
  }

  var active = links.find(function (a) {
    return a.getAttribute("href") === window.location.pathname;
  });
  if (active) active.classList.add("active");

  links.forEach(function (a) {
    a.addEventListener("mouseenter", function () { moveTo(a); });
  });

  nav.addEventListener("mouseleave", function () {
    if (active) {
      moveTo(active);
    } else {
      pill.style.opacity = "0";
    }
  });

  if (active) {
    requestAnimationFrame(function () { moveTo(active, true); });
  }
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
