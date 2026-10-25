// Emoji picker and quick reactions. A curated set built into the page (no third-party emoji service, nothing fetched):
// the system's own emoji font draws them, the same characters any phone keyboard sends.
import { el, clear } from "./term.js";

export const QUICK = ["👍", "❤️", "😂", "🎉", "😮", "😢", "🔥", "👀", "✅"];

const SETS = [
  ["Smileys", "😀 grin|😃 smile|😄 happy|😁 beam|😆 laugh|😅 sweat|🤣 rofl|😂 joy|🙂 slight|🙃 upside|😉 wink|😊 blush|😇 halo|🥰 love|😍 heart eyes|🤩 star|😘 kiss|😋 yum|😛 tongue|😜 crazy|🤪 zany|🤔 think|🤨 eyebrow|😐 neutral|😑 blank|😶 quiet|🙄 eyeroll|😏 smirk|😬 grimace|😮‍💨 exhale|🤥 lie|😌 relieved|😔 pensive|😪 sleepy|😴 sleep|😷 mask|🤒 ill|🤕 hurt|🤢 sick|🤯 mind blown|🥳 party|😎 cool|🤓 nerd|🧐 monocle|😕 confused|😟 worried|🙁 frown|😮 wow|😲 astonished|😳 flushed|🥺 pleading|😢 cry|😭 sob|😱 scream|😤 huff|😡 angry|🤬 swear|💀 skull|💩 poop|🤡 clown|👻 ghost|👽 alien|🤖 robot|😺 cat"],
  ["Gestures", "👍 thumbs up|👎 thumbs down|👌 ok|🤌 pinch|✌️ peace|🤞 fingers crossed|🤟 love you|🤘 rock|🤙 call|👈 left|👉 right|👆 up|👇 down|☝️ point|✋ hand|🖐️ splayed|🖖 vulcan|👋 wave|👏 clap|🙌 raise|🫶 heart hands|👐 open|🤲 palms|🤝 handshake|🙏 thanks|✍️ write|💪 strong|🫡 salute|🤷 shrug|🤦 facepalm|🙋 me|🙆 ok person|🙅 no|🧠 brain|👀 eyes|👁️ eye"],
  ["Hearts", "❤️ red heart|🧡 orange|💛 yellow|💚 green|💙 blue|💜 purple|🖤 black|🤍 white|🤎 brown|💔 broken|❣️ exclamation|💕 two hearts|💞 revolving|💓 beating|💗 growing|💖 sparkle|💘 arrow|💝 ribbon|💯 hundred|💢 anger|💥 boom|💫 dizzy|💦 drops|💨 dash|🕳️ hole|💬 speech|🗯️ rage|💭 thought|💤 zzz"],
  ["People", "👶 baby|🧒 child|👦 boy|👧 girl|🧑 person|👨 man|👩 woman|🧓 older|👴 old man|👵 old woman|🧔 beard|👱 blond|👮 police|🕵️ detective|💂 guard|👷 builder|🧑‍💻 technologist|🧑‍🔧 mechanic|🧑‍🍳 cook|🧑‍🚀 astronaut|🧑‍🚒 firefighter|🧑‍⚕️ health worker|🧑‍🏫 teacher|🦸 hero|🦹 villain|🧙 mage|🧛 vampire|🧟 zombie|🥷 ninja|🤴 prince|👸 princess|🎅 santa|🏃 run|🚶 walk|💃 dance|🕺 dancer|👯 bunny ears|🧘 yoga|🛌 bed|👫 couple|👪 family|👨‍👩‍👧 family three|👨‍👩‍👧‍👦 family four|🗣️ speaking|👤 silhouette|👥 silhouettes"],
  ["Animals & nature", "🐶 dog|🐱 cat|🐭 mouse face|🐹 hamster|🐰 rabbit|🦊 fox|🐻 bear|🐼 panda|🐨 koala|🐯 tiger|🦁 lion|🐮 cow|🐷 pig|🐸 frog|🐵 monkey|🙈 see no evil|🙉 hear no evil|🙊 speak no evil|🐔 chicken|🐧 penguin|🐦 bird|🦆 duck|🦅 eagle|🦉 owl|🦇 bat|🐺 wolf|🐗 boar|🐴 horse|🦄 unicorn|🐝 bee|🦋 butterfly|🐌 snail|🐢 turtle|🐍 snake|🦖 t-rex|🐙 octopus|🦑 squid|🦀 crab|🐠 fish|🐬 dolphin|🐳 whale|🦈 shark|🐊 crocodile|🐘 elephant|🦒 giraffe|🦔 hedgehog|🐾 paws|🌵 cactus|🎄 tree|🌲 evergreen|🌳 deciduous|🌴 palm|🌱 seedling|🌿 herb|🍀 clover|🍁 maple|🍂 leaves|🍄 mushroom|🌷 tulip|🌹 rose|🌻 sunflower|🌸 blossom|💐 bouquet|🔥 flame|💧 droplet|⛅ partly sunny|⚡ lightning|🌪️ tornado|☃️ snowman"],
  ["Food & drink", "🍏 green apple|🍎 apple|🍐 pear|🍊 orange|🍋 lemon|🍌 banana|🍉 watermelon|🍇 grapes|🍓 strawberry|🫐 blueberries|🍒 cherries|🍑 peach|🥭 mango|🍍 pineapple|🥥 coconut|🥝 kiwi|🍅 tomato|🍆 aubergine|🥑 avocado|🥦 broccoli|🌶️ chilli|🌽 corn|🥕 carrot|🧄 garlic|🧅 onion|🥔 potato|🥐 croissant|🥖 baguette|🍞 bread|🧀 cheese|🥚 egg|🍳 cooking|🥓 bacon|🍔 burger|🍟 fries|🌭 hot dog|🥪 sandwich|🌮 taco|🌯 burrito|🥗 salad|🍝 spaghetti|🍜 noodles|🍲 stew|🍛 curry|🍣 sushi|🍤 prawn|🍦 ice cream|🍩 doughnut|🍪 cookie|🎂 birthday cake|🍰 cake|🧁 cupcake|🍫 chocolate|🍿 popcorn|🍯 honey|🥛 milk|🍵 tea|🧃 juice|🥤 cup|🍾 champagne|🍸 cocktail|🍹 tropical|🍻 cheers|🥂 toast|🥃 whisky|🧉 mate|🧊 ice"],
  ["Travel & places", "🚗 car|🚕 taxi|🚙 suv|🚌 bus|🏎️ racing car|🚓 police car|🚑 ambulance|🚒 fire engine|🚚 lorry|🚜 tractor|🏍️ motorbike|🚲 bicycle|🛴 scooter|🚨 siren|🚦 lights|⛽ fuel|🚂 train|🚆 rail|🚇 metro|✈️ plane|🛫 departure|🛬 arrival|🚁 helicopter|🛸 ufo|⛵ sailboat|🚤 speedboat|🚢 ship|⚓ anchor|🗼 tower|🏰 castle|🏯 japanese castle|🗽 liberty|⛪ church|🕌 mosque|🏠 house|🏡 home|🏢 office|🏭 factory|🏥 hospital|🏦 bank|🏨 hotel|🏪 shop|🏫 school|⛺ tent|🏕️ camping|🏖️ beach|🏝️ island|🏔️ snowy mountain|⛰️ mountain|🌋 volcano|🗻 fuji|🌅 sunrise|🌄 mountain sunrise|🌃 night|🌉 bridge|🎡 ferris wheel|🎢 rollercoaster|🧳 luggage|🗺️ world map|🧭 compass travel"],
  ["Activities", "⚽ football|🏀 basketball|🏈 american football|⚾ baseball|🎾 tennis|🏐 volleyball|🏉 rugby|🎱 pool|🏓 ping pong|🏸 badminton|🏒 hockey|🏏 cricket|⛳ golf|🏹 archery|🎣 fishing|🥊 boxing|🥋 martial arts|⛸️ skate|🎿 ski|🏂 snowboard|🏋️ lift|🤸 cartwheel|🚴 cycling|🏊 swim|🏄 surf|🧗 climb|🏅 medal|🎖️ military medal|🎗️ ribbon|🎟️ ticket|🎫 tickets|🎪 circus|🎭 theatre|🎨 art|🎬 clapper|🎤 mic|🎼 score|🎹 piano|🥁 drum|🎷 sax|🎺 trumpet|🎸 guitar|🎻 violin|🎲 dice|♟️ chess|🧩 puzzle|🎳 bowling|🎰 slots|🪁 kite|🎈 balloon|🎆 fireworks|🎇 sparkler|🧨 firecracker|🎃 pumpkin|🎄 christmas tree|🎀 bow"],
  ["Work & dev", "💻 laptop|🖥️ desktop|⌨️ keyboard|🖱️ mouse|💾 disk|💿 cd|🖨️ printer|📱 phone|☎️ telephone|🔋 battery|🔌 plug|📡 antenna|🛰️ satellite|🔒 lock|🔓 unlocked|🔐 locked key|🔑 key|🗝️ old key|🛡️ shield|⚙️ gear|🔧 wrench|🔨 hammer|🛠️ tools|⛏️ pick|🧰 toolbox|🧪 test|🧬 dna|🔬 microscope|📈 up|📉 down|📊 chart|📋 clipboard|📌 pin|📎 clip|✂️ scissors|🗂️ dividers|📁 folder|📂 open folder|🗃️ box|🗄️ cabinet|🗑️ bin|📝 memo|✏️ pencil|📅 date|⏰ alarm|⏱️ stopwatch|⏳ hourglass|🚀 rocket|🐛 bug|🐞 ladybug|🔥 fire|⚡ zap|🌐 web|🧭 compass|🏗️ building|🚧 wip|🚨 alert|🔔 bell|🔕 mute|📢 loud|📣 megaphone|📦 package|🏷️ tag|💡 idea|🔍 search|🔎 magnify|🧹 broom|♻️ recycle|🧯 extinguisher|🎯 target|🏁 finish|🏆 trophy|🥇 gold|🎉 tada|🎊 confetti|🎁 gift|☕ coffee|🍕 pizza|🍝 pasta|🍺 beer|🍷 wine|🎮 game|🕹️ joystick|🎧 headphones|🎵 music|📷 camera|🎥 movie|📺 tv"],
  ["Symbols", "✅ check|☑️ checkbox|✔️ tick|❌ cross|❎ cross box|⭕ circle|🛑 stop|⛔ no entry|🚫 forbidden|⚠️ warning|❗ exclamation|❓ question|‼️ double|⁉️ interrobang|➕ plus|➖ minus|✖️ times|➗ divide|♾️ infinity|🔁 repeat|🔄 refresh|🔃 reload|⏩ forward|⏪ back|⏸️ pause|▶️ play|⏹️ stop button|🔴 red|🟠 orange circle|🟡 yellow circle|🟢 green circle|🔵 blue circle|🟣 purple circle|⚫ black circle|⚪ white circle|🟥 red square|🟩 green square|🟦 blue square|⬛ black square|⬜ white square|🔺 up triangle|🔻 down triangle|💠 diamond|🔷 blue diamond|🔶 orange diamond|⭐ star|🌟 glow|✨ sparkles|☀️ sun|🌙 moon|☁️ cloud|🌧️ rain|❄️ snow|🌈 rainbow|🌊 wave|🌍 earth|🗺️ map|🏴‍☠️ pirate|🇬🇧 uk|🇺🇸 usa|🇪🇺 eu|🇮🇹 italy"],
];

export const ALL = SETS.flatMap(([cat, s]) => s.split("|").map((x) => {
  const i = x.indexOf(" ");
  return { e: x.slice(0, i), name: x.slice(i + 1), cat };
}));

// A popover grid with search. onPick(emoji) is called per click; the popover closes on Escape or a click outside.
export function picker(anchor, onPick) {
  document.querySelectorAll(".emoji-pop").forEach((p) => p.remove());
  const search = el("input", { cls: "term-field emoji-search", placeholder: "search emoji", "aria-label": "Search emoji", spellcheck: "false" });
  const grid = el("div", { cls: "emoji-grid", role: "listbox", "aria-label": "Emoji" });
  const pop = el("div", { cls: "emoji-pop", role: "dialog", "aria-label": "Emoji picker" }, [search, grid]);
  function render(q) {
    clear(grid);
    let cat = null;
    for (const x of ALL) {
      if (q && !x.name.includes(q)) continue;
      if (!q && x.cat !== cat) { cat = x.cat; grid.append(el("div", { cls: "emoji-cat", text: cat })); }
      grid.append(el("button", { type: "button", cls: "emoji-btn", title: x.name, "aria-label": x.name, text: x.e,
                                 onclick: () => onPick(x.e) }));
    }
  }
  render("");
  search.addEventListener("input", () => render(search.value.trim().toLowerCase()));
  const close = () => { pop.remove(); document.removeEventListener("pointerdown", outside, true); };
  const outside = (ev) => { if (!pop.contains(ev.target) && ev.target !== anchor) close(); };
  pop.addEventListener("keydown", (ev) => { if (ev.key === "Escape") { close(); anchor.focus(); } });
  document.addEventListener("pointerdown", outside, true);
  const r = anchor.getBoundingClientRect();
  pop.style.bottom = (window.innerHeight - r.top + 6) + "px";
  document.body.append(pop);
  pop.style.left = Math.max(8, Math.min(window.innerWidth - pop.offsetWidth - 8, r.left)) + "px";   // its real width: never off-screen
  search.focus();
  return close;
}
