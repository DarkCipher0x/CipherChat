// The screens in front of the chat: boot (crypto self-test), first-time setup, unlock, and pinning the owner's
// identity after comparing safety numbers. The passphrase only ever lives in this module's local variables for the
// few seconds a screen needs it; it is never stored or sent.
import * as C from "./crypto.js";
import { api } from "./api.js";
import { el, clear } from "./term.js";

const MIN_PASS = 16;

function card(gate, title, ...kids) {
  const box = gate.querySelector("#gate-card");
  clear(box);
  const c = el("div", { cls: "gate-card" }, [el("h2", { text: title }), ...kids]);
  box.append(c);
  return c;
}
function field(label, attrs) {
  const input = el("input", Object.assign({ cls: "term-field", spellcheck: "false", autocomplete: "off" }, attrs));
  return { input, node: el("label", {}, [el("span", { cls: "gate-label", text: label }), input]) };
}
function busy(btn, text) { btn.disabled = true; btn.dataset.label = btn.textContent; btn.textContent = text; }
function idle(btn) { btn.disabled = false; btn.textContent = btn.dataset.label || btn.textContent; }

// "Confirm it's you" inside the current card (creating or replacing keys needs a fresh authenticator code when the
// portal sign-in is more than a few minutes old). Returns an ask(errorText) for api(): resolves to the code or null.
function inlineAsk(c, prog) {
  const box = el("div", { cls: "reauth-box", hidden: true });
  c.append(box);
  return (errText) => new Promise((resolve) => {
    clear(box);
    const input = el("input", { cls: "term-field code-field", inputmode: "numeric", autocomplete: "one-time-code", maxlength: 6,
                                placeholder: "123456", spellcheck: "false", "aria-label": "Authenticator code" });
    const err = el("p", { cls: "gate-err", role: "alert", text: errText || "" });
    const done = (v) => { box.hidden = true; clear(box); resolve(v); };
    const ok = el("button", { type: "button", cls: "term-btn primary", text: "Confirm", onclick: () => {
      const v = input.value.replace(/\s+/g, "");
      if (!/^\d{6}$/.test(v)) { err.textContent = "Enter the 6 digits from your authenticator app."; input.focus(); return; }
      done(v);
    } });
    input.addEventListener("keydown", (ev) => { if (ev.key === "Enter") { ev.preventDefault(); ok.click(); } });
    box.append(el("span", { cls: "gate-label", text: "Confirm it's you" }),
      el("p", { text: "Enter the current 6-digit code from your authenticator app. The portal asks for it before keys are created or changed if you signed in more than 10 minutes ago." }),
      input, el("div", { cls: "gate-row" }, [ok, el("button", { type: "button", cls: "term-btn", text: "Cancel", onclick: () => done(null) })]), err);
    box.hidden = false;
    if (prog) prog.textContent = "Waiting for your authenticator code…";
    input.focus();
  });
}

export function passProblems(p) {
  if (p.length < MIN_PASS) return "Use at least " + MIN_PASS + " characters (4 or more random words works well).";
  if (new Set(p).size < 8) return "That has too few different characters.";
  return "";
}
function strength(p) {
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((r) => r.test(p)).length;
  return Math.min(100, Math.round(p.length * 3.2 + classes * 8 + new Set(p).size));
}

// ---------------------------------------------------------------------------------------------- boot
export async function boot(gate, write) {
  write("cipherchat 1 // end-to-end encrypted, post-quantum\n", "acc");
  write("suite  " + C.SUITE + "\n\n");
  let results;
  try { results = await C.selfTest(); }
  catch (e) {
    write("[ FAIL ] " + e.message + "\n", "bad");
    write("\nThe crypto self-test failed in this browser, so the chat won't start. Try an up-to-date Chrome, Edge, Firefox or Safari.\n", "bad");
    throw e;
  }
  for (const r of results) write("[  OK  ] " + r.name + "\n", "ok");
  write("\n" + results.length + "/" + results.length + " checks passed\n\n");
  return results;
}

// ---------------------------------------------------------------------------------------------- setup
// First time on any device: make the identity, seal it with the passphrase, publish it.
export function setup(gate, st, reset) {
  return new Promise((resolve) => {
    const p1 = field("Chat passphrase", { type: "password", autocomplete: "new-password", maxlength: 1024 });
    const p2 = field("Type it again", { type: "password", autocomplete: "new-password", maxlength: 1024 });
    const meter = el("div", { cls: "meter" }, el("span"));
    const err = el("p", { cls: "gate-err", role: "alert" });
    const prog = el("p", { cls: "cap progress", "aria-live": "polite" });
    const go = el("button", { type: "submit", cls: "term-btn primary", text: reset ? "Reset my identity" : "Create my identity" });
    const form = el("form", { novalidate: true }, [
      el("p", { text: (reset ? "This replaces your chat identity. Your old one stops working everywhere, your certificate ends and the owner has to verify you again. Messages sent to your old identity can't be read with the new one. "
                             : "Your browser now makes your personal keys. They never leave it unencrypted: the server only gets a copy sealed with this passphrase. ") +
                     "The passphrase is separate from your portal password. Nobody can reset it: if you forget it you have to start a new identity." }),
      p1.node, meter, p2.node,
      el("p", { cls: "cap", text: "Use at least " + MIN_PASS + " characters. Long and unique beats complicated: four or more random words." }),
      el("div", { cls: "gate-row" }, [go]), prog, err]);
    p1.input.addEventListener("input", () => { meter.firstChild.style.width = strength(p1.input.value) + "%"; });
    const c = card(gate, reset ? "Reset your chat identity" : "Set up your chat identity", form);
    const ask = inlineAsk(c, prog);
    p1.input.focus();
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      err.textContent = "";
      const pass = p1.input.value;
      const problem = passProblems(pass);
      if (problem) { err.textContent = problem; return; }
      if (pass !== p2.input.value) { err.textContent = "The two passphrases don't match."; return; }
      busy(go, "Working…");
      try {
        prog.textContent = "Generating ML-KEM-1024, X25519, ML-DSA-87 and Ed25519 keys…";
        const master = C.random(32);
        const id = await C.identityFromMaster(st.me.user, master);
        const pub = await C.publishIdentity(id, Date.now());
        prog.textContent = "Getting the server key share…";
        const pep = await api("pepper");
        const anchor = st.me.owner ? pub.fp : null;            // the owner is the trust anchor; members pin it next
        prog.textContent = "Sealing your keys with Argon2id (64 MiB)…";
        const backup = await C.sealBackup(st.me.user, pass, C.unb64(pep.pepper, 32), pep.pepper_ver,
          { v: 1, master: C.b64(master), anchor_fp: anchor, created: Date.now() });
        prog.textContent = "Publishing your public keys…";
        await api("identity", { bundle: pub.bundle, backup, confirm_reset: !!reset }, { ask });
        prog.textContent = "";
        resolve({ id, fp: pub.fp, anchorFp: anchor, master, pass, pepper: pep });
      } catch (e) {
        idle(go);
        prog.textContent = "";
        err.textContent = e.message || String(e);
      }
    });
  });
}

// ---------------------------------------------------------------------------------------------- unlock
export function unlock(gate, st) {
  return new Promise((resolve) => {
    const p = field("Chat passphrase", { type: "password", autocomplete: "current-password", maxlength: 1024 });
    const err = el("p", { cls: "gate-err", role: "alert" });
    const prog = el("p", { cls: "cap progress", "aria-live": "polite" });
    const go = el("button", { type: "submit", cls: "term-btn primary", text: "Unlock" });
    const form = el("form", { novalidate: true }, [
      el("p", { text: "Your keys are sealed. Enter your chat passphrase to open them in this tab. They're wiped from memory when you lock, leave the page, or after 15 minutes without activity." }),
      p.node, el("div", { cls: "gate-row" }, [go]), prog, err]);
    card(gate, "Unlock " + st.me.user + "@cipherchat", form);
    p.input.focus();
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      err.textContent = "";
      const pass = p.input.value;
      if (!pass) return;
      busy(go, "Unlocking…");
      try {
        prog.textContent = "Fetching your sealed keys…";
        const b = await api("backup/fetch", {});
        prog.textContent = "Deriving the key (Argon2id, 64 MiB)…";
        const payload = await C.openBackup(st.me.user, pass, C.unb64(b.pepper, 32), b.backup);
        const master = C.unb64(payload.master, 32);
        const id = await C.identityFromMaster(st.me.user, master);
        // The identity the server publishes for you must be exactly the one your secret produces
        const { obj } = C.parseSigned(b.bundle.b, 16384);
        const mine = await C.publishIdentity(id, obj.at);
        if (mine.fp !== b.fp) throw new C.CryptoFail("The identity the server shows for you doesn't match your keys. Don't use the chat; tell the owner.");
        p.input.value = "";
        prog.textContent = "";
        resolve({ id, fp: b.fp, anchorFp: payload.anchor_fp || null, master, pass, payload });
      } catch (e) {
        idle(go);
        prog.textContent = "";
        err.textContent = e instanceof C.CryptoFail && e.message === "wrong passphrase" ? "That passphrase isn't right." : (e.message || String(e));
        p.input.select();
      }
    });
  });
}

// ---------------------------------------------------------------------------------------------- pin the owner
// Members compare one safety number with the owner (in person, by phone or video, or another channel you already
// trust). The owner sees the same number when certifying you, so one comparison verifies both directions.
export function verifyOwner(gate, st, me) {
  return new Promise((resolve) => {
    const owner = st.directory.find((d) => d.user === st.owner);
    if (!owner || !owner.identity) {
      card(gate, "Waiting for the owner", el("p", { text: "The owner (" + st.owner + ") hasn't set up their chat identity yet, so there's nobody to verify against. Try again later." }),
        el("div", { cls: "gate-row" }, [el("button", { type: "button", cls: "term-btn", text: "Check again", onclick: () => location.reload() })]));
      return;
    }
    const sn = C.safetyNumber(me.fp, owner.identity.fp);
    const err = el("p", { cls: "gate-err", role: "alert" });
    const chk = el("input", { type: "checkbox", id: "vo-ok" });
    const go = el("button", { type: "button", cls: "term-btn primary", text: "Pin the owner's identity" });
    const c = card(gate, "Verify the owner",
      el("p", { text: "Read this number to " + st.owner + " (or have them read theirs to you) in person, on a call or through a channel you already trust. Not in the chat, and not by email." }),
      el("div", { cls: "safety", "aria-label": "Safety number" }, sn.split(" ").map((g) => el("span", { text: g }))),
      el("p", { cls: "fp", text: "Your fingerprint   " + C.fpGroups(me.fp) }),
      el("p", { cls: "fp", text: "Owner fingerprint  " + C.fpGroups(owner.identity.fp) }),
      el("label", { cls: "gate-check", for: "vo-ok" }, [chk, el("span", { text: "The owner sees exactly the same 60 digits." })]),
      el("div", { cls: "gate-row" }, [go, el("button", { type: "button", cls: "term-btn", text: "Later", onclick: () => resolve(null) })]),
      el("p", { cls: "cap", text: "If the numbers differ, stop: someone may be intercepting. The owner will also certify your identity after the same comparison; until then others can't send you room keys." }),
      err);
    const ask = inlineAsk(c, null);
    go.addEventListener("click", async () => {
      err.textContent = "";
      if (!chk.checked) { err.textContent = "Compare the number first, then tick the box."; return; }
      busy(go, "Pinning…");
      try {
        await C.openIdentity(owner.identity, st.owner);          // must be a valid, self-signed identity
        const pep = await api("pepper");
        const payload = Object.assign({}, me.payload || { v: 1, master: C.b64(me.master), created: Date.now() }, { anchor_fp: owner.identity.fp });
        const backup = await C.sealBackup(st.me.user, me.pass, C.unb64(pep.pepper, 32), pep.pepper_ver, payload);
        await api("backup", { fp: me.fp, backup }, { ask });
        resolve(owner.identity.fp);
      } catch (e) {
        idle(go);
        err.textContent = e.message || String(e);
      }
    });
  });
}

// ---------------------------------------------------------------------------------------------- passphrase change
export async function changePassphrase(st, me, current, next) {
  const problem = passProblems(next);
  if (problem) throw new Error(problem);
  const b = await api("backup/fetch", {});
  const payload = await C.openBackup(st.me.user, current, C.unb64(b.pepper, 32), b.backup);
  const pep = await api("pepper");
  const backup = await C.sealBackup(st.me.user, next, C.unb64(pep.pepper, 32), pep.pepper_ver, payload);
  await api("backup", { fp: me.fp, backup });
}
