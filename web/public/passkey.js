// Passkeys (WebAuthn) for the CipherChat portal: sign in, confirm it's you, and add a passkey. The private key stays in
// the passkey provider (Bitwarden, Windows Hello, a phone, a security key); the server only checks signatures.
// Exposes window.cipherchatPasskey. No markup is ever built from strings here.
(function () {
  "use strict";
  var HDR = { "Content-Type": "application/json", "X-Requested-With": "dcx-portal" };

  function u8(b64u) {
    var s = atob(b64u.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((b64u.length + 3) % 4));
    var out = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  }
  function b64u(buf) {
    var b = new Uint8Array(buf), s = "";
    for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function post(path, body) {
    return fetch("/chat/api/" + path, { method: "POST", credentials: "same-origin", headers: HDR, body: JSON.stringify(body || {}) })
      .then(function (r) { return r.json().catch(function () { return {}; }).then(function (j) { return { ok: r.ok, status: r.status, j: j }; }); });
  }
  function fail(res, fallback) {
    var e = new Error((res.j && res.j.error) || fallback);
    e.status = res.status; e.data = res.j;
    return e;
  }

  function supported() { return !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.get); }

  // purpose "login" (no username: the provider offers the saved passkey) or "reauth" (the signed-in account's own passkeys).
  // mediation "conditional" = offered in the username box's autofill instead of a pop-up.
  function get(purpose, mediation, signal) {
    return post("auth/passkey/begin", { purpose: purpose }).then(function (res) {
      if (!res.ok) throw fail(res, "Passkeys aren't available right now.");
      var o = res.j.publicKey;
      var opts = { publicKey: { challenge: u8(o.challenge), rpId: o.rpId, timeout: o.timeout, userVerification: o.userVerification,
        allowCredentials: (o.allowCredentials || []).map(function (c) { return { type: "public-key", id: u8(c.id) }; }) } };
      if (mediation) opts.mediation = mediation;
      if (signal) opts.signal = signal;
      return navigator.credentials.get(opts).then(function (cred) {
        var r = cred.response;
        return post("auth/passkey/finish", { flow: res.j.flow, purpose: purpose, credential: { id: cred.id, rawId: b64u(cred.rawId), type: cred.type,
          response: { clientDataJSON: b64u(r.clientDataJSON), authenticatorData: b64u(r.authenticatorData), signature: b64u(r.signature),
                      userHandle: r.userHandle ? b64u(r.userHandle) : null } } });
      }).then(function (fin) { if (!fin.ok) throw fail(fin, "That passkey didn't work."); return fin.j; });
    });
  }

  // Adds a passkey to the signed-in account. ask(errorText) -> Promise<code|null> answers "confirm it's you".
  function create(name, ask) {
    function begin() {
      return post("passkeys/register/begin", {}).then(function (res) {
        if (res.status === 401 && res.j.reauth) {
          return confirm(ask).then(begin);
        }
        if (!res.ok) throw fail(res, "Couldn't start adding a passkey.");
        return res.j;
      });
    }
    return begin().then(function (j) {
      var o = j.publicKey;
      return navigator.credentials.create({ publicKey: {
        challenge: u8(o.challenge), rp: o.rp, user: { id: u8(o.user.id), name: o.user.name, displayName: o.user.displayName },
        pubKeyCredParams: o.pubKeyCredParams, authenticatorSelection: o.authenticatorSelection, attestation: o.attestation, timeout: o.timeout,
        excludeCredentials: (o.excludeCredentials || []).map(function (c) { return { type: "public-key", id: u8(c.id) }; }) } })
        .then(function (cred) {
          return post("passkeys/register/finish", { flow: j.flow, name: name, credential: { id: cred.id, rawId: b64u(cred.rawId), type: cred.type,
            response: { clientDataJSON: b64u(cred.response.clientDataJSON), attestationObject: b64u(cred.response.attestationObject) } } });
        }).then(function (fin) { if (!fin.ok) throw fail(fin, "That passkey couldn't be added."); return fin.j; });
    });
  }

  // "Confirm it's you": a passkey if the account has one (one tap in Bitwarden), else the authenticator code.
  function confirm(ask) {
    return get("reauth").catch(function () {
      return (function loop(errText) {
        return ask(errText).then(function (code) {
          if (!code) throw new Error("Cancelled: nothing was changed.");
          return post("auth/reauth", { code: code }).then(function (res) { if (!res.ok) return loop((res.j && res.j.error) || "That code isn't valid."); });
        });
      })(null);
    });
  }

  window.cipherchatPasskey = { supported: supported, get: get, create: create, confirm: confirm };
})();
