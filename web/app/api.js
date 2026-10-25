// The chat's calls to the portal service. Same rules as portal.js (CSRF header, back to sign-in when the session is
// gone), but self-contained so nothing can wait forever:
//   - every request has a time limit (TIMEOUT) and fails with a readable error instead of hanging;
//   - "confirm it's you" (401 + reauth) is answered through an ask(error) callback that the caller shows INLINE
//     (the gate's own code field, or a terminal dialog), then the request is retried once. 2026-10-23: relying on
//     portal.js's pop-up for this left identity setup stuck on "Publishing your public keys…".
const TIMEOUT = 30000;
let defaultAsk = null;
export function setAsk(fn) { defaultAsk = fn; }

// The same chat runs in two places: the client chat portal (/chat/, its own sign-in and chat-only session) and the
// admin portal (/admin/chat.html). Only the URLs differ.
export const CHAT_PORTAL = location.pathname === "/chat/" || location.pathname.startsWith("/chat/");
function url(path) {                       // "chat/state" | "auth/reauth" -> the right endpoint for this portal
  if (!CHAT_PORTAL) return "/admin/api/" + path;
  return "/chat/api/" + (path.startsWith("chat/") ? path.slice(5) : path);
}
export const SIGN_IN = CHAT_PORTAL ? "/chat/login/" : "/admin/login/";
export const SELFTEST = CHAT_PORTAL ? "/chat/app/selftest.html" : "/admin/chat/selftest.html";
function toSignIn() { location.replace(SIGN_IN + "?next=" + encodeURIComponent(location.pathname)); }

async function call(method, path, body, timeout) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeout || TIMEOUT);
  const o = { method, credentials: "same-origin", cache: "no-store", signal: ctl.signal, headers: { "X-Requested-With": "dcx-portal" } };
  if (body !== undefined) { o.headers["Content-Type"] = "application/json"; o.body = JSON.stringify(body); }
  let r;
  try { r = await fetch(url(path), o); }
  catch (e) {
    const err = new Error(ctl.signal.aborted ? "The server didn't answer within " + Math.round((timeout || TIMEOUT) / 1000) + " seconds. Check your connection and try again."
                                             : "Couldn't reach the server. Check your connection and try again.");
    err.status = 0; err.offline = true;
    throw err;
  } finally { clearTimeout(timer); }
  const data = await r.json().catch(() => ({}));
  if (r.status === 403 && !data.denied) {                      // no valid session any more: back to sign-in
    toSignIn();
    const e = new Error("Your portal session ended. Sign in again.");
    e.status = 403;
    throw e;
  }
  return { status: r.status, data };
}

function fail(res) {
  const e = new Error(res.data.error || ("HTTP " + res.status));
  e.status = res.status; e.data = res.data;
  return e;
}

// A fresh authenticator code for the next few minutes of sensitive actions. ask(errorText) resolves to the code,
// or to null when the person cancels.
export async function reauth(ask) {
  // A passkey (Bitwarden, Windows Hello, a phone) answers with one tap where the portal offers them (passkey.js)
  const pk = window.cipherchatPasskey;
  if (pk && pk.supported()) {
    try { await pk.get("reauth"); return; } catch (e) { /* none saved, or cancelled: the authenticator code instead */ }
  }
  let err = "";
  for (let attempt = 0; attempt < 5; attempt++) {
    const code = await ask(err);
    if (!code) throw new Error("Cancelled: nothing was changed.");
    const res = await call("POST", "auth/reauth", { code });
    if (res.status === 200) return;
    err = res.data.error || "That code isn't valid.";
  }
  throw new Error("Too many wrong codes. Wait a moment and try again.");
}

// GET when body is undefined, else POST. opts.ask overrides the default code prompt for this call.
export async function api(path, body, opts) {
  const chatPath = "chat/" + path;
  let res = await call(body === undefined ? "GET" : "POST", chatPath, body);
  if (res.status === 401 && res.data.reauth) {
    const ask = (opts && opts.ask) || defaultAsk;
    if (!ask) throw fail(res);
    await reauth(ask);
    res = await call(body === undefined ? "GET" : "POST", chatPath, body);
  }
  if (res.status < 200 || res.status >= 300) throw fail(res);
  return res.data;
}

// Encrypted attachment upload (ciphertext only). XMLHttpRequest because fetch can't report upload progress; the time
// limit grows with the size (30 s + 1 s per 256 KB) so a slow line still finishes but a dead one never hangs.
export function uploadBlob(roomId, sealed, onProgress) {
  return new Promise((resolve, reject) => {
    const x = new XMLHttpRequest();
    x.open("POST", url("chat/upload/" + roomId));
    x.setRequestHeader("X-Requested-With", "dcx-portal");
    x.setRequestHeader("Content-Type", "application/octet-stream");
    x.timeout = 30000 + Math.ceil(sealed.length / 262144) * 1000;
    x.upload.onprogress = (e) => { if (e.lengthComputable && onProgress) onProgress(e.loaded, e.total); };
    const fail = (msg, status) => { const e = new Error(msg); e.status = status || 0; reject(e); };
    x.onerror = () => fail("The upload failed. Check your connection and try again.");
    x.ontimeout = () => fail("The upload took too long and was stopped. Try again on a better connection.");
    x.onload = () => {
      let j = {};
      try { j = JSON.parse(x.responseText || "{}"); } catch (e) { j = {}; }
      if (x.status === 403 && !j.denied) { toSignIn(); return fail("Your portal session ended. Sign in again.", 403); }
      if (x.status !== 200) return fail(j.error || ("Upload refused (HTTP " + x.status + ")"), x.status);
      resolve(j);
    };
    x.send(sealed);
  });
}

export async function downloadBlob(roomId, blobId, size) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 30000 + Math.ceil((size || 0) / 262144) * 1000);
  try {
    const r = await fetch(url("chat/blob/" + roomId + "/" + blobId), { credentials: "same-origin", cache: "no-store", signal: ctl.signal,
                                                                             headers: { "X-Requested-With": "dcx-portal" } });
    if (!r.ok) { const e = new Error(r.status === 404 ? "That attachment isn't on the server any more." : "Download failed (HTTP " + r.status + ")"); e.status = r.status; throw e; }
    return new Uint8Array(await r.arrayBuffer());
  } catch (e) {
    if (ctl.signal.aborted) throw new Error("The download took too long and was stopped.");
    throw e;
  } finally { clearTimeout(timer); }
}

// The server holds a poll for up to 25 s; 45 s without an answer means the connection is dead, so give up and retry.
// sig: the last call signal seen (calls.py); signals newer than it come back in `signals`
export async function poll(since, rev, sig) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 45000);
  let r;
  try {
    r = await fetch(url("chat/poll") + "?since=" + encodeURIComponent(since) + "&rev=" + encodeURIComponent(rev) + (sig === undefined ? "" : "&sig=" + encodeURIComponent(sig)),
      { credentials: "same-origin", headers: { "X-Requested-With": "dcx-portal" }, signal: ctl.signal, cache: "no-store" });
  } finally { clearTimeout(timer); }
  const j = await r.json().catch(() => ({}));
  if (r.status === 403 && !j.denied) { toSignIn(); throw new Error("Signed out"); }
  if (!r.ok) { const e = new Error(j.error || "HTTP " + r.status); e.status = r.status; e.data = j; throw e; }
  return j;
}
