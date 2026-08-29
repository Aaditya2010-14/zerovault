// Minimal vanilla JS — no framework, no build step.

// Password field show/hide: [data-toggle-password] sits next to a
// .password-field's input. Toggling flips the input between password
// (dots) and text, and swaps which eye icon (open/closed) is visible —
// letting people actually verify what they typed before submitting, so a
// master password set (or changed) blind never happens again.
document.addEventListener("click", function (e) {
  var btn = e.target.closest("[data-toggle-password]");
  if (!btn) return;
  var field = btn.closest(".password-field");
  var input = field && field.querySelector("input");
  if (!input) return;

  var revealed = input.type === "text";
  input.type = revealed ? "password" : "text";
  btn.classList.toggle("revealed", !revealed);
  btn.setAttribute("aria-label", revealed ? "Show password" : "Hide password");
});

// TOTP countdown rings: each [data-totp-ring] holds the server-computed
// seconds-until-refresh and period at page load. Count down client-side,
// animating the ring's stroke-dashoffset, and reload once any ring hits
// zero so displayed codes never go stale.
(function () {
  var rings = document.querySelectorAll("[data-totp-ring]");
  if (rings.length === 0) return;

  var period = parseInt(rings[0].getAttribute("data-period"), 10) || 30;
  var remaining = parseInt(rings[0].getAttribute("data-remaining"), 10);
  if (isNaN(remaining)) return;

  var circumference = 2 * Math.PI * 18;

  function paint() {
    rings.forEach(function (ring) {
      var fill = ring.querySelector("[data-totp-ring-fill]");
      var text = ring.querySelector("[data-totp-ring-text]");
      var frac = Math.max(0, remaining / period);
      if (fill) {
        fill.setAttribute("stroke-dasharray", circumference.toFixed(1));
        fill.setAttribute("stroke-dashoffset", (circumference * (1 - frac)).toFixed(1));
        fill.style.stroke = remaining <= 5 ? "var(--danger)" : remaining <= 10 ? "var(--warning)" : "var(--success)";
      }
      if (text) text.textContent = remaining;
    });
  }
  paint();

  var timer = setInterval(function () {
    remaining -= 1;
    if (remaining <= 0) {
      clearInterval(timer);
      window.location.reload();
      return;
    }
    paint();
  }, 1000);
})();

// Generic show/hide toggle: [data-toggle-target="id"] shows/hides the
// element with that id (used for the TOTP add-form and QR panels), CSP-safe
// replacement for an inline onclick handler.
document.addEventListener("click", function (e) {
  var btn = e.target.closest("[data-toggle-target]");
  if (!btn) return;
  e.preventDefault();
  var el = document.getElementById(btn.getAttribute("data-toggle-target"));
  if (!el) return;
  if (el.classList.contains("totp-qr-panel")) {
    el.classList.toggle("open");
  } else {
    el.style.display = el.style.display === "none" || !el.style.display ? "block" : "none";
  }
});

// Range sliders: mirror the live value next to the label.
(function () {
  var length = document.getElementById("length");
  var lengthValue = document.getElementById("length-value");
  if (length && lengthValue) {
    length.addEventListener("input", function () {
      lengthValue.textContent = length.value;
    });
  }
  var entropy = document.getElementById("min_entropy");
  var entropyValue = document.getElementById("entropy-value");
  if (entropy && entropyValue) {
    entropy.addEventListener("input", function () {
      entropyValue.textContent = parseFloat(entropy.value).toFixed(1);
    });
  }
})();

// Scanner mode tabs: file vs. git, driving a hidden input plus which extra
// fields are shown — no page reload needed to switch modes.
(function () {
  var tabs = document.querySelectorAll("[data-scan-mode]");
  var modeInput = document.getElementById("scan-mode-input");
  var gitRow = document.getElementById("git-depth-row");
  var pathLabel = document.getElementById("scan-path-label");
  if (tabs.length === 0 || !modeInput) return;

  tabs.forEach(function (tab) {
    tab.addEventListener("click", function (e) {
      e.preventDefault();
      var mode = tab.getAttribute("data-scan-mode");
      modeInput.value = mode;
      tabs.forEach(function (t) { t.classList.toggle("active", t === tab); });
      if (gitRow) gitRow.style.display = mode === "git" ? "" : "none";
      if (pathLabel) pathLabel.textContent = mode === "git" ? "Git repository path" : "Directory path";
    });
  });
})();

// Drag-and-drop file zones on the File Encryption page.
(function () {
  document.querySelectorAll("[data-drop-zone]").forEach(function (zone) {
    var input = document.getElementById(zone.getAttribute("data-target"));
    var filenameEl = zone.querySelector("[data-drop-zone-filename]");
    if (!input) return;

    zone.addEventListener("click", function () { input.click(); });

    function showFile() {
      if (input.files && input.files[0] && filenameEl) {
        filenameEl.textContent = "📎 " + input.files[0].name;
      }
    }
    input.addEventListener("change", showFile);

    ["dragenter", "dragover"].forEach(function (evt) {
      zone.addEventListener(evt, function (e) {
        e.preventDefault();
        zone.classList.add("drag-over");
      });
    });
    ["dragleave", "drop"].forEach(function (evt) {
      zone.addEventListener(evt, function (e) {
        e.preventDefault();
        zone.classList.remove("drag-over");
      });
    });
    zone.addEventListener("drop", function (e) {
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) {
        input.files = e.dataTransfer.files;
        showFile();
      }
    });
  });
})();

// Toast/snackbar: a single shared element, reused for every notification.
function getToast() {
  var toast = document.getElementById("toast");
  if (!toast) {
    toast = document.createElement("div");
    toast.id = "toast";
    toast.className = "toast";
    document.body.appendChild(toast);
  }
  return toast;
}

function clearToastTimers(toast) {
  clearTimeout(toast._hideTimer);
  clearInterval(toast._countdownTimer);
}

function showToast(message) {
  var toast = getToast();
  clearToastTimers(toast);
  toast.textContent = message;
  // Force reflow so re-triggering the animation works on rapid repeat clicks.
  toast.classList.remove("toast-visible");
  void toast.offsetWidth;
  toast.classList.add("toast-visible");
  toast._hideTimer = setTimeout(function () {
    toast.classList.remove("toast-visible");
  }, 2000);
}

// Clipboard auto-clear: a copied secret only lives in the clipboard for
// CLIPBOARD_CLEAR_SECONDS, matching the CLI's `-copy` behavior — the toast
// stays up the whole time with a live countdown so it's obvious the
// clipboard is about to be wiped, not just "copied and forgotten".
var CLIPBOARD_CLEAR_SECONDS = 10;

function showClipboardCountdownToast() {
  var toast = getToast();
  clearToastTimers(toast);
  var remaining = CLIPBOARD_CLEAR_SECONDS;
  toast.textContent = "Copied! Clears in " + remaining + "s";
  toast.classList.remove("toast-visible");
  void toast.offsetWidth;
  toast.classList.add("toast-visible");

  toast._countdownTimer = setInterval(function () {
    remaining -= 1;
    if (remaining > 0) {
      toast.textContent = "Copied! Clears in " + remaining + "s";
      return;
    }
    clearInterval(toast._countdownTimer);
    if (navigator.clipboard) {
      navigator.clipboard.writeText("").catch(function () {});
    }
    toast.textContent = "Clipboard cleared";
    toast._hideTimer = setTimeout(function () {
      toast.classList.remove("toast-visible");
    }, 2000);
  }, 1000);
}

// Copy-to-clipboard buttons: [data-copy] holds the text to copy. The button
// itself never changes (icon-only, fixed size) — feedback is a toast
// instead, plus a brief press effect so the click still feels acknowledged.
// [data-copy-secret] additionally marks a button whose copied value is
// sensitive (a password, not a username) — those get the auto-clearing
// countdown toast instead of the plain "Copied" one.
document.addEventListener("click", function (e) {
  var btn = e.target.closest("[data-copy]");
  if (!btn) return;
  var text = btn.getAttribute("data-copy");
  var isSecret = btn.hasAttribute("data-copy-secret");

  btn.classList.add("btn-press");
  setTimeout(function () {
    btn.classList.remove("btn-press");
  }, 100);

  if (!navigator.clipboard) return;
  navigator.clipboard.writeText(text).then(function () {
    if (isSecret) {
      showClipboardCountdownToast();
    } else {
      showToast("Copied to clipboard");
    }
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
    btn.classList.remove("revealed");
    btn.setAttribute("aria-label", "Show password");
  } else {
    span.textContent = span.getAttribute("data-secret");
    span.setAttribute("data-revealed", "true");
    btn.classList.add("revealed");
    btn.setAttribute("aria-label", "Hide password");
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

// Back-to-vault arrow: play a physical button-press (depth) effect before
// navigating so the click feels acknowledged.
document.addEventListener("click", function (e) {
  var el = e.target.closest("[data-bounce-nav]");
  if (!el) return;
  e.preventDefault();
  el.classList.add("press");
  setTimeout(function () {
    window.location.href = el.getAttribute("href");
  }, 250);
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
