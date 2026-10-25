// Getting attachments ready to send: read the file, find out what it really is, make a small preview for pictures and
// videos, then encrypt and upload both (crypto.js sealFile). The server's SHA3-256 of what it stored must equal ours,
// or the send stops. Only references (blob id, key, hash, size) go into the signed, encrypted message.
import * as C from "./crypto.js";
import { uploadBlob } from "./api.js";

export const MAX_FILES = 10;
const THUMB_PX = 360;

export async function prepare(file) {
  if (file.size > C.FILE_MAX) throw new Error(file.name + " is over the 100 MB limit.");
  const bytes = new Uint8Array(await file.arrayBuffer());
  const t = C.sniff(bytes);
  const kind = t.startsWith("image/") ? "image" : t.startsWith("video/") ? "video" : (file.type || "").startsWith("audio/") ? "audio" : "file";
  const out = { name: file.name || "attachment", mime: kind === "file" || kind === "audio" ? (file.type || "application/octet-stream").slice(0, 100) : t,
                kind, bytes, size: bytes.length };
  try {
    if (kind === "image") Object.assign(out, await imageThumb(bytes, t));
    if (kind === "video") Object.assign(out, await videoThumb(bytes, t));
  } catch (e) { /* no preview: the file still sends */ }
  return out;
}

function canvasJpeg(source, w, h) {
  const scale = Math.min(1, THUMB_PX / Math.max(w, h));
  const cw = Math.max(1, Math.round(w * scale)), ch = Math.max(1, Math.round(h * scale));
  const c = document.createElement("canvas");
  c.width = cw; c.height = ch;
  c.getContext("2d").drawImage(source, 0, 0, cw, ch);
  return new Promise((resolve, reject) => c.toBlob((b) => (b ? b.arrayBuffer().then((a) => resolve(new Uint8Array(a))) : reject(new Error("no preview"))), "image/jpeg", 0.75));
}

async function imageThumb(bytes, type) {
  const bmp = await createImageBitmap(new Blob([bytes], { type }));
  try { return { w: bmp.width, h: bmp.height, thumbBytes: await canvasJpeg(bmp, bmp.width, bmp.height) }; }
  finally { bmp.close(); }
}

function videoThumb(bytes, type) {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(new Blob([bytes], { type }));
    const v = document.createElement("video");
    const done = (fn) => { clearTimeout(timer); v.removeAttribute("src"); v.load(); URL.revokeObjectURL(url); fn(); };
    const timer = setTimeout(() => done(() => reject(new Error("no preview"))), 5000);
    v.muted = true; v.preload = "auto"; v.playsInline = true;
    v.addEventListener("loadeddata", () => { v.currentTime = Math.min(0.5, (v.duration || 1) / 10); }, { once: true });
    v.addEventListener("seeked", () => {
      canvasJpeg(v, v.videoWidth, v.videoHeight).then((thumbBytes) =>
        done(() => resolve({ w: v.videoWidth, h: v.videoHeight, dur: Math.round(v.duration || 0), thumbBytes })),
        (e) => done(() => reject(e)));
    }, { once: true });
    v.addEventListener("error", () => done(() => reject(new Error("no preview"))), { once: true });
    v.src = url;
  });
}

async function sealAndUpload(roomId, bytes, onProgress) {
  const s = await C.sealFile(bytes);
  const res = await uploadBlob(roomId, s.sealed, onProgress);
  if (res.sha3 !== s.sha3 || res.size !== s.sealed.length) throw new Error("The server stored something other than what was sent. Not sending.");
  return { blob: res.id, key: s.key, sha3: s.sha3, size: s.size };
}

// Returns {files: [...refs for the payload], blobs: [ids for the server]}.
export async function uploadAll(roomId, items, status) {
  const files = [], blobs = [];
  for (let i = 0; i < items.length; i++) {
    const it = items[i];
    const ref = await sealAndUpload(roomId, it.bytes, (sent, total) =>
      status("Encrypting and sending " + (i + 1) + "/" + items.length + " (" + it.name + ") " + Math.round(100 * sent / total) + "%"));
    const f = Object.assign(ref, { name: it.name.slice(0, 200), mime: it.mime, kind: it.kind });
    for (const k of ["w", "h", "dur"]) if (Number.isSafeInteger(it[k])) f[k] = it[k];
    blobs.push(ref.blob);
    if (it.thumbBytes) {
      f.thumb = await sealAndUpload(roomId, it.thumbBytes, () => {});
      blobs.push(f.thumb.blob);
    }
    files.push(f);
    it.bytes = null;                     // drop the plaintext as soon as it's sealed
  }
  return { files, blobs };
}
