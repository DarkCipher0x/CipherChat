// Who to trust. The only root of trust is the owner's identity fingerprint that YOU compared (safety number) and
// pinned in your sealed backup. Everyone else is trusted only through a certificate signed by that identity. The
// server's word counts for nothing here: it can hand out any keys it likes and this file will refuse them.
import * as C from "./crypto.js";

const cache = new Map();          // "user|fp|cert" -> verdict, so the same entry isn't re-verified on every refresh

// directory: the server's list ({user, owner, identity:{b,s,fp}|null, cert:{b,s}|null}); anchorFp: pinned owner fp.
// Returns Map user -> {user, display_name, owner, fp, pub|null, trust: "ok"|"pending"|"none"|"bad", why}
export async function evaluate(directory, ownerUser, anchorFp) {
  const out = new Map();
  const ownerEntry = directory.find((d) => d.user === ownerUser);
  let ownerPub = null, ownerProblem = "";
  if (!anchorFp) ownerProblem = "you haven't verified the owner's identity yet";
  else if (!ownerEntry || !ownerEntry.identity) ownerProblem = "the owner has no chat identity on the server";
  else if (ownerEntry.identity.fp !== anchorFp) ownerProblem = "THE OWNER'S KEY ON THE SERVER IS NOT THE ONE YOU VERIFIED";
  else {
    try { ownerPub = await open(ownerEntry); } catch (e) { ownerProblem = "the owner's identity doesn't verify: " + e.message; }
  }
  for (const d of directory) {
    const base = { user: d.user, display_name: d.display_name, owner: d.owner, addon: !!d.addon, fp: d.identity ? d.identity.fp : null, pub: null };
    if (!d.identity) { out.set(d.user, Object.assign(base, { trust: "none", why: "hasn't set up the chat yet" })); continue; }
    if (d.user === ownerUser) {
      out.set(d.user, Object.assign(base, ownerPub ? { pub: ownerPub, trust: "ok", why: "the owner (you verified this key)" }
                                                   : { trust: "bad", why: ownerProblem }));
      continue;
    }
    if (!ownerPub) { out.set(d.user, Object.assign(base, { trust: "bad", why: "can't check: " + ownerProblem })); continue; }
    let pub;
    try { pub = await open(d); } catch (e) { out.set(d.user, Object.assign(base, { trust: "bad", why: "identity doesn't verify: " + e.message })); continue; }
    if (!d.cert) { out.set(d.user, Object.assign(base, { pub: null, trust: "pending", why: "waiting for the owner to verify and certify" })); continue; }
    const key = d.user + "|" + d.identity.fp + "|" + d.cert.s.slice(0, 64) + "|" + ownerPub.fp;
    let ok = cache.get(key);
    if (ok === undefined) {
      try { ok = await C.verifyCert(d.cert, ownerPub, d.user, d.identity.fp); } catch (e) { ok = false; }
      cache.set(key, ok);
    }
    out.set(d.user, Object.assign(base, ok ? { pub, trust: "ok", why: "certified by the owner" }
                                            : { trust: "bad", why: "the certificate doesn't verify" }));
  }
  return { people: out, ownerPub, ownerProblem };
}

const opened = new Map();
async function open(d) {
  const k = d.user + "|" + d.identity.fp;
  if (!opened.has(k)) opened.set(k, await C.openIdentity(d.identity, d.user));
  return opened.get(k);
}
