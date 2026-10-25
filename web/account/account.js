// Your account: passkeys (add, list, remove) and the sign-in password. Text only via textContent.
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var HDR = { "X-Requested-With": "dcx-portal" };
  var pk = window.cipherchatPasskey;

  function el(tag, cls, text) { var e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; }
  function show(id, text) { ["err", "ok"].forEach(function (x) { $(x).hidden = true; }); $(id).textContent = text; $(id).hidden = false; }
  function call(path, body) {
    var o = { method: body === undefined ? "GET" : "POST", credentials: "same-origin", cache: "no-store", headers: Object.assign({}, HDR) };
    if (body !== undefined) { o.headers["Content-Type"] = "application/json"; o.body = JSON.stringify(body); }
    return fetch("/chat/api/" + path, o).then(function (r) { return r.json().catch(function () { return {}; }).then(function (j) { return { status: r.status, j: j }; }); });
  }

  // "Confirm it's you" with an authenticator code (passkey.js tries a passkey first)
  function askCode(errText) {
    return new Promise(function (resolve) {
      var d = el("dialog", "adm-dialog");
      d.append(el("h2", null, "Confirm it's you"), el("p", null, "Enter the current 6-digit code from your authenticator app."));
      var input = el("input"); input.inputMode = "numeric"; input.autocomplete = "one-time-code"; input.maxLength = 6; input.placeholder = "123456";
      d.append(input);
      if (errText) d.append(el("p", "cp-err", errText));
      var row = el("div", "btns");
      var cancel = el("button", "btn btn-sm", "Cancel"), okb = el("button", "btn btn-sm btn-primary", "Confirm");
      cancel.type = okb.type = "button";
      cancel.onclick = function () { d.close(); d.remove(); resolve(null); };
      okb.onclick = function () { if (/^\d{6}$/.test(input.value)) { d.close(); d.remove(); resolve(input.value); } };
      row.append(cancel, okb); d.append(row);
      d.addEventListener("cancel", function () { d.remove(); resolve(null); });
      document.body.append(d); d.showModal(); input.focus();
    });
  }

  function withReauth(fn) {
    return fn().then(function (res) {
      if (res.status === 401 && res.j.reauth) return pk.confirm(askCode).then(fn);
      return res;
    });
  }

  function load() {
    return call("passkeys").then(function (res) {
      var box = $("pk-list"); box.textContent = "";
      (res.j.passkeys || []).forEach(function (p) {
        var row = el("div", "adm-card");
        row.append(el("h2", null, p.name), el("div", "meta", p.type + " · added " + p.created.replace("T", " ").replace("Z", " UTC") +
          (p.last_used ? " · last used " + p.last_used.replace("T", " ").replace("Z", " UTC") : " · not used yet")));
        var rm = el("button", "btn btn-sm danger", "Remove"); rm.type = "button";
        rm.onclick = function () {
          withReauth(function () { return call("passkeys/" + encodeURIComponent(p.id) + "/delete", {}); }).then(function (r) {
            if (r.status !== 200) return show("err", r.j.error || "Couldn't remove it.");
            show("ok", "Passkey removed. Also delete it from your password manager."); load();
          }).catch(function (e) { show("err", e.message); });
        };
        row.append(rm);
        box.append(row);
      });
      if (!(res.j.passkeys || []).length) box.append(el("p", "dim", "No passkeys yet."));
    });
  }

  $("pk-add").addEventListener("click", function () {
    var name = (navigator.userAgent.indexOf("Windows") >= 0 ? "Windows" : navigator.userAgent.indexOf("Android") >= 0 ? "Android" : "Passkey");
    pk.create(name + " " + new Date().toISOString().slice(0, 10), askCode).then(function () {
      show("ok", "Passkey added. Next time, choose \"Sign in with a passkey\".");
      load();
    }).catch(function (e) { if (e.name !== "NotAllowedError") show("err", e.message); });
  });

  $("pw-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    if ($("pw-new").value !== $("pw-new2").value) return show("err", "The new passwords don't match.");
    call("auth/password", { current: $("pw-cur").value, "new": $("pw-new").value, code: $("pw-code").value }).then(function (r) {
      if (r.status !== 200) return show("err", r.j.error || "That didn't work.");
      ["pw-cur", "pw-new", "pw-new2", "pw-code"].forEach(function (x) { $(x).value = ""; });
      show("ok", "Password changed. Your other sessions were signed out.");
    });
  });

  $("signout").addEventListener("click", function () { call("auth/logout", {}).finally(function () { location.replace("/chat/login/"); }); });

  call("auth/status").then(function (res) {
    if (!res.j.signed_in) { location.replace("/chat/login/?next=/chat/account/"); return; }
    $("who").textContent = res.j.user;
    $("pw-user").value = res.j.user;
    if (!pk.supported()) { $("pk-add").hidden = true; $("pk-unsupported").hidden = false; }
    load();
  });
})();
