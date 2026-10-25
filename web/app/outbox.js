// CipherChat by DarkCipher Systems: the outbox. Messages on their way to the server, the same rules as the apps
// (Outbox.kt, Outbox.cs): a message is sealed once and resent unchanged until the server has it (the server recognises a
// resend by its signed message id, so a send whose answer was lost never turns into two messages); it is re-sealed only
// when the server says the room key changed and it hasn't got it. Offline, timeouts, server errors and rate limits are
// waited out (1 s doubling to 30 s, and at once when the connection comes back); a refusal retrying can't fix marks the
// message failed, with retry and discard. Kept in this tab's memory only (like the keys).

const transient = (e) => e.offline || e.status === 0 || e.status >= 500 || e.status === 429 || e.status === 408;

export class Outbox {
  // h: { seal(R, payload) -> msg, send(R, msg, blobs, burn), upload(R, item, status) -> { file, blobs },
  //      refresh(), changed(o), gone(o), msgId(msg) }
  constructor(h) {
    this.h = h;
    this.items = [];
    this.wakeUp = null;
    this.running = false;
  }

  get pending() { return this.items.filter((o) => o.state !== "sent"); }

  add(R, kind, preview, payload, files) {
    const o = { R, kind, preview, payload, files: files || [], uploaded: [], blobs: [], state: "queued", note: null, attempts: 0,
                msg: null, msgId: null, visible: kind === "text" || kind === "me" || kind === "file" };
    this.items.push(o);
    this.wake();
    if (!this.running) this.run();
    return o;
  }

  wake() { if (this.wakeUp) { const w = this.wakeUp; this.wakeUp = null; w(); } }

  retry(o) {
    if (o.state !== "failed") return;
    o.state = "queued"; o.note = null;
    this.h.changed(o);
    this.wake();
  }

  discard(o) {
    if (o.state === "sending" || o.state === "sent") return false;
    this.items = this.items.filter((x) => x !== o);
    this.h.gone(o);
    return true;
  }

  // The real message arrived from the server: its placeholder goes.
  delivered(msgId) {
    const o = this.items.find((x) => x.msgId === msgId);
    if (!o) return;
    this.items = this.items.filter((x) => x !== o);
    o.state = "sent";
    this.h.gone(o);
  }

  sleep(ms) {
    return new Promise((resolve) => {
      const t = setTimeout(() => { this.wakeUp = null; resolve(); }, ms);
      this.wakeUp = () => { clearTimeout(t); resolve(); };
    });
  }

  async run() {
    this.running = true;
    let backoff = 1000;
    for (;;) {
      const o = this.items.find((x) => x.state === "queued");
      if (!o) { await this.sleep(3600000); continue; }
      const r = await this.attempt(o);
      if (r === "sent") {
        backoff = 1000;
        if (!o.visible) { this.items = this.items.filter((x) => x !== o); this.h.gone(o); }
      } else if (r === "later") {
        o.state = "queued"; o.note = "waiting for the connection";
        this.h.changed(o);
        await this.sleep(backoff);
        backoff = Math.min(30000, backoff * 2);
      } else this.h.changed(o);
    }
  }

  async attempt(o) {
    o.state = "sending"; o.attempts++; o.note = null;
    this.h.changed(o);
    try {
      for (let i = o.uploaded.length; i < o.files.length; i++) {           // each attachment uploaded once
        const up = await this.h.upload(o.R, o.files[i], (t) => { o.note = t; this.h.changed(o); });
        o.uploaded.push(up.file); o.blobs.push(...up.blobs);
      }
      const payload = o.files.length ? Object.assign({}, o.payload, { files: o.uploaded }) : o.payload;
      for (let n = 0; n < 3; n++) {
        if (!o.msg) { o.msg = await this.h.seal(o.R, payload); o.msgId = this.h.msgId(o.msg); }
        try {
          await this.h.send(o.R, o.msg, o.blobs, !!payload.burn);
          o.state = "sent"; this.h.changed(o);
          return "sent";
        } catch (e) {
          if (e.data && e.data.duplicate) { o.state = "sent"; this.h.changed(o); return "sent"; }
          if (e.data && (e.data.rotate || e.data.stale)) { await this.h.refresh(); o.msg = null; o.msgId = null; continue; }   // re-seal under the new key
          throw e;
        }
      }
      return "later";                                                       // the room kept changing: try again shortly
    } catch (e) {
      if (transient(e)) return "later";
      o.state = "failed"; o.note = e.message || "the server refused it";
      return "failed";
    }
  }
}
