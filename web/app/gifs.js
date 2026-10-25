// GIFs: the GIF picker shows the GIFs of this session (ones you sent, and ones others sent that played in your rooms),
// so sending one back is one click, plus "Choose a GIF" from your files. A GIF goes out like any attachment: encrypted
// on this device, uploaded as ciphertext. Nothing is searched or fetched from a GIF service (they see every search and
// every viewer), and nothing is stored: the list lives in this page's memory and is gone on lock or reload.
import { el, clear } from "./term.js";

const MAX = 30;                       // GIFs kept
const MAX_BYTES = 96 * 1048576;       // and at most this much memory for them
const recent = [];                    // newest first: {name, bytes, url, key}

export function remember(name, bytes) {
  const key = bytes.length + ":" + name;
  const i = recent.findIndex((g) => g.key === key);
  if (i >= 0) { recent.unshift(recent.splice(i, 1)[0]); return; }
  recent.unshift({ name: name || "animation.gif", bytes, key, url: URL.createObjectURL(new Blob([bytes], { type: "image/gif" })) });
  let total = recent.reduce((n, g) => n + g.bytes.length, 0);
  while (recent.length > MAX || (recent.length > 1 && total > MAX_BYTES)) {
    const g = recent.pop();
    total -= g.bytes.length;
    URL.revokeObjectURL(g.url);
  }
}

// A popover above the anchor: recent GIFs, and a button to choose one from files. onPick(File) adds it as an attachment.
export function picker(anchor, onPick, onChoose) {
  document.querySelectorAll(".emoji-pop").forEach((p) => p.remove());
  const grid = el("div", { cls: "gif-grid", role: "listbox", "aria-label": "Recent GIFs" });
  const choose = el("button", { type: "button", cls: "term-btn", text: "choose a GIF…", onclick: () => { close(); onChoose(); } });
  const pop = el("div", { cls: "emoji-pop gif-pop", role: "dialog", "aria-label": "GIFs" }, [
    el("div", { cls: "emoji-cat", text: "GIFs from this session" }), grid,
    el("div", { cls: "gif-foot" }, [choose, el("span", { cls: "gif-note", text: "end-to-end encrypted like any attachment · no GIF service sees you" })]),
  ]);
  clear(grid);
  if (!recent.length) grid.append(el("p", { cls: "gif-empty", text: "None yet. GIFs you send, and GIFs that play in your rooms, show up here so you can send them again. Paste or drop a GIF anywhere in the chat, too." }));
  for (const g of recent) {
    grid.append(el("button", { type: "button", cls: "gif-cell", title: g.name, "aria-label": "Send " + g.name,
      onclick: () => { close(); onPick(new File([g.bytes], g.name, { type: "image/gif" })); } },
      el("img", { src: g.url, alt: g.name, loading: "lazy" })));
  }
  const close = () => { pop.remove(); document.removeEventListener("pointerdown", outside, true); };
  const outside = (ev) => { if (!pop.contains(ev.target) && ev.target !== anchor) close(); };
  pop.addEventListener("keydown", (ev) => { if (ev.key === "Escape") { close(); anchor.focus(); } });
  document.addEventListener("pointerdown", outside, true);
  const r = anchor.getBoundingClientRect();
  pop.style.bottom = (window.innerHeight - r.top + 6) + "px";
  document.body.append(pop);
  pop.style.left = Math.max(8, Math.min(window.innerWidth - pop.offsetWidth - 8, r.left)) + "px";
  choose.focus();
  return close;
}
