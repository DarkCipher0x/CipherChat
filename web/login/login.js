// Chat portal sign-in: username + password + authenticator code -> a chat-only session in its own cookie.
// The same accounts as the admin portal; failures look identical (no username probing) and count for fail2ban.
// Also the invite / reset links of chat-only accounts (#enrol=TOKEN), as on the admin sign-in page.
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var form = $("login"), err = $("err"), go = $("go"), code = $("code");

  function post(path, body) {
    return fetch("/chat/api/auth/" + path, {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-Requested-With": "dcx-portal" },
      body: JSON.stringify(body)
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) { return { ok: r.ok, status: r.status, j: j }; });
    });
  }
  function digits(input, done) {
    input.addEventListener("input", function () {
      input.value = input.value.replace(/\D/g, "").slice(0, 6);
      if (input.value.length === 6 && done) done();
    });
  }
  function next() {
    var n = new URLSearchParams(location.search).get("next") || "/chat/";
    location.replace(/^\/chat\/[A-Za-z0-9._\/-]*$/.test(n) ? n : "/chat/");
  }

  var enrolToken = (location.hash.match(/^#enrol=([A-Za-z0-9_-]{20,100})$/) || [])[1];
  if (enrolToken) {
    history.replaceState(null, "", location.pathname);         // don't leave the token in the address bar
    startEnrol(enrolToken);
    return;
  }

  fetch("/chat/api/auth/status", { credentials: "same-origin", headers: { "X-Requested-With": "dcx-portal" }, cache: "no-store" })
    .then(function (r) { return r.ok ? r.json() : {}; })
    .then(function (s) { if (s.signed_in) next(); else offerPasskeys(); })
    .catch(function () {});

  // Passkeys: a button, and (where the browser supports it) the saved passkey offered right in the username box's
  // autofill, which is how Bitwarden and the browser's own manager show them.
  var conditional = null;
  function offerPasskeys() {
    var pk = window.cipherchatPasskey;
    if (!pk || !pk.supported()) return;
    $("passkey-go").hidden = false;
    $("passkey-go").addEventListener("click", function () {
      if (conditional) conditional.abort();
      err.hidden = true;
      pk.get("login").then(next).catch(function (e) { if (e.name !== "NotAllowedError" && e.name !== "AbortError") fail(e.message); });
    });
    if (window.PublicKeyCredential.isConditionalMediationAvailable) {
      window.PublicKeyCredential.isConditionalMediationAvailable().then(function (ok) {
        if (!ok) return;
        conditional = new AbortController();
        pk.get("login", "conditional", conditional.signal).then(next).catch(function () {});
      }).catch(function () {});
    }
  }

  digits(code, function () { if ($("username").value && $("password").value) form.requestSubmit(); });
  function fail(m) { err.textContent = m; err.hidden = false; code.value = ""; code.focus(); go.disabled = false; }

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    if (go.disabled) return;
    var user = $("username").value.trim().toLowerCase(), pw = $("password").value;
    if (!user || !pw) return fail("Enter your username and password.");
    if (!/^\d{6}$/.test(code.value)) return fail("Enter the 6-digit code from your authenticator app.");
    err.hidden = true; go.disabled = true;
    post("login", { username: user, password: pw, code: code.value }).then(function (res) {
      if (res.ok) { $("password").value = ""; next(); return; }
      fail(res.status === 429 ? "Too many attempts from this connection. Wait a minute and try again." : (res.j.error || "Sign-in failed."));
    }).catch(function () { fail("Couldn't reach the server. Check your connection."); });
  });

  // The authenticator key as a QR code, drawn here in the page (the key never goes to any other site or service)
  function drawQr(canvas, text) {
    import("/chat/public/vendor/qrcode/qrcode.mjs").then(function (m) {
      var q = m.default(0, "M");
      q.addData(text);
      q.make();
      var n = q.getModuleCount(), quiet = 4, size = canvas.width, cell = Math.floor(size / (n + 2 * quiet));
      var off = Math.floor((size - cell * n) / 2), g = canvas.getContext("2d");
      g.fillStyle = "#ffffff"; g.fillRect(0, 0, size, size);
      g.fillStyle = "#000000";
      for (var r = 0; r < n; r++) for (var c = 0; c < n; c++) if (q.isDark(r, c)) g.fillRect(off + c * cell, off + r * cell, cell, cell);
    }).catch(function () { canvas.hidden = true; });
  }

  // ------------------------------------------------------------------ invite / reset links
  function startEnrol(token) {
    $("signin").hidden = true; $("enrol-view").hidden = false;
    var sub = $("en-sub"), eerr = $("en-err"), btn = $("en-go"), state = { step: 1 };
    var bad = function (m) { eerr.textContent = m; eerr.hidden = false; btn.disabled = false; };
    digits($("en-code1"));
    digits($("en-code"), function () { btn.click(); });
    post("enrol/check", { token: token }).then(function (res) {
      if (!res.ok) { sub.textContent = res.status === 429 ? "Too many attempts. Wait a minute and reload." : (res.j.error || "This link can't be used."); return; }
      var k = res.j.kind;
      state.kind = k;
      $("en-title").textContent = { invite: "Set up your chat account", reset_password: "Choose a new password",
                                    reset_mfa: "Set up a new authenticator" }[k];
      sub.textContent = "Account: " + res.j.username;
      $("en-user").value = res.j.username;                 // a password manager saves the password under this account
      $("en-hint").textContent = k === "reset_mfa" ? "Enter your current password to confirm it's you."
        : "At least " + res.j.password_min + " characters, not containing your username. This is your sign-in password; your chat passphrase comes later and is separate.";
      $("en-pw-l").firstChild.textContent = k === "reset_mfa" ? "Current password" : "Choose a password";
      $("en-pw").autocomplete = k === "reset_mfa" ? "current-password" : "new-password";
      $("en-pw2-l").hidden = k === "reset_mfa";
      $("en-code1-l").hidden = k !== "reset_password";
      $("en-step1").hidden = false;
      btn.hidden = false;
      $("en-pw").focus();
    }).catch(function () { sub.textContent = "Couldn't reach the server."; });

    $("en-copy").addEventListener("click", function () {
      var t = $("en-secret").textContent.replace(/\s/g, "");
      if (navigator.clipboard) navigator.clipboard.writeText(t).then(function () { $("en-copy").textContent = "Copied"; });
    });

    $("enrol").addEventListener("submit", function (e) {
      e.preventDefault();
      if (btn.disabled) return;
      eerr.hidden = true;
      if (state.step === 1) {
        if (state.kind !== "reset_mfa" && $("en-pw").value !== $("en-pw2").value) return bad("The passwords don't match.");
        var body = { token: token, password: $("en-pw").value };
        if (state.kind === "reset_password") {
          if (!/^\d{6}$/.test($("en-code1").value)) return bad("Enter the 6-digit code from your authenticator app.");
          body.code = $("en-code1").value;
        }
        btn.disabled = true;
        post("enrol/start", body).then(function (res) {
          btn.disabled = false;
          if (!res.ok) { $("en-code1").value = ""; return bad(res.j.error || "That didn't work."); }
          $("en-pw").value = ""; $("en-pw2").value = "";
          if (res.j.done) { finish(); return; }
          state.step = 2;
          $("en-step1").hidden = true; $("en-step2").hidden = false;
          $("en-secret").textContent = res.j.secret.replace(/(.{4})/g, "$1 ").trim();
          $("en-uri").href = res.j.otpauth;
          drawQr($("en-qr"), res.j.otpauth);
          btn.textContent = "Confirm";
          $("en-code").focus();
        }).catch(function () { bad("Couldn't reach the server."); });
      } else {
        if (!/^\d{6}$/.test($("en-code").value)) return bad("Enter the 6-digit code from your authenticator app.");
        btn.disabled = true;
        post("enrol/finish", { token: token, code: $("en-code").value }).then(function (res) {
          if (res.ok) { finish(); return; }
          $("en-code").value = "";
          bad(res.j.error || "That code didn't match.");
        }).catch(function () { bad("Couldn't reach the server."); });
      }
    });

    function finish() {
      ["en-step1", "en-step2"].forEach(function (id) { $(id).hidden = true; });
      $("en-secret").textContent = "";
      btn.hidden = true;
      $("en-done").hidden = false;
      sub.textContent = "";
    }
  }
})();
