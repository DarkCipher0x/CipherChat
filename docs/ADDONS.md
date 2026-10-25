# CipherChat add-ons and connectors

Add-ons are programs — bots, and **connectors** that bring your other systems into the chat — that take part in
CipherChat with an identity of their own. The first connector is **CommandCentre**: ask `!cc status` in a room and the
fleet status comes back, end-to-end encrypted, from the CommandCentre on your PC. Any system with an MCP server can be
connected the same way with a small JSON file.

Add-ons don't weaken anything about the chat. The rest of this page is how.

## How it's secured

| Layer | What protects it |
|---|---|
| Content | Unchanged end-to-end encryption. An add-on is a chat member with its own hybrid post-quantum identity (ML-DSA-87 + Ed25519 signatures, ML-KEM-1024 + X25519 key wrapping), made **on the add-on's machine**. The server never gets plaintext or private keys, so an add-on can't be used to read the chat through the server either. |
| Trust | The owner certifies the add-on after comparing its 60-digit safety number, exactly like a person. Until then nobody's client wraps a room key for it. The add-on pins the owner from the connector code, which the **owner's own client** stamps with the owner's fingerprint — it never has to believe the server about who the owner is. |
| Visibility | Add-on accounts are always named `addon.<name>` (people can't take such names) and every client shows an **add-on** tag. |
| Requests | No bearer tokens, no cookies. Every request is signed: HMAC-SHA3-256 over the method, path and query, server origin, add-on, time, a one-time 192-bit nonce and the SHA3-256 of the body, with a 256-bit key. A captured request can't be replayed (nonce + 90 s window) or changed (body, query, method, target all signed); uploads are checked against the signed hash as they stream. 256-bit symmetric keys and SHA-3 keep their strength against quantum computers; the connection itself is TLS 1.3 with X25519MLKEM768 only. |
| Key storage | **Server:** the add-on's key isn't stored at all — it's derived (HMAC-SHA3-256) from the server key file, which never goes in the database or its backups; the database holds only a salt and a version, so a stolen database is useless. **Add-on machine:** the connector code and the identity's master secret are sealed together with DPAPI for the Windows account that runs it. |
| Least privilege | Add-ons reach only: directory/state, polling, history and room keys **of rooms they were added to**, sending (`send` scope), attachments (`files`), starting direct messages (`dm`), leaving. Never accounts, devices, backups, certificates, room settings, room-key rotation or calls. An add-on can't be a room admin or inherit a room, can't replace its identity, and can't sign in as a person (no password, authenticator or passkey). |
| Control | Only the owner creates, edits, re-keys, disables or removes add-ons, each after confirming with their authenticator code. Optional IP allowlist, expiry (1–730 days) and per-add-on rate limit. Disable stops it at once; a new key kills the old one at once; removing it takes it out of every room (the rooms get new keys without it). |
| Audit | Every management step and every refused add-on request (bad signature, replay, clock, IP, route, scope) goes to the tamper-evident audit log (`/admin/audit`). The connector also keeps a local log of who asked for what (never the output). |

Tests: `server/tests/test_server.py` (test_13: forgery, replay, tampered body and query, clock skew, cookie mixing,
route isolation, scopes, IP allowlist, disable, rotate, delete, audit), `server/tests/pentest_server.py` (pt_19:
IDOR, cross-add-on and person-name swaps, header injection, oversized and mismatched bodies, privilege escalation),
`windows/tests/CipherChat.Addons.Tests` (connector rules, HMAC-SHA3 test vector shared with Python, code parsing).

## Owner: add an add-on

1. In the web chat type `/addons` → **New add-on**. Give it a name (it becomes `addon.<name>`), what it may do
   (`send` is enough for a connector that answers questions), optionally the addresses it may connect from and how long
   it's valid. Confirm with your authenticator code.
2. Copy the **connector code** (shown once). It's the add-on's key: give it only to the add-on's setup, never to a
   chat or an email. Lost it? `/addons` → **new key** (the old one stops working at once).
3. Set the add-on up (below). It makes its keys and prints its safety number.
4. `/verify addon.<name>` → compare the safety number with the one the add-on printed → **Certify**.
5. Add it to the rooms it should serve (`/invite addon.<name>` in the room, or name it when you create the room). Room
   keys are renewed automatically to include it.

## CommandCentre connector

On the PC that runs CommandCentre (a controller sees the whole mesh):

```
CipherChatConnector setup connectors\commandcentre.json
```

Paste the connector code when asked (input is hidden). It seals the code and the new identity for this Windows account in
`%LOCALAPPDATA%\DarkCipher Systems\CipherChat Connector\commandcentre.key`, publishes the add-on's public keys and
prints the safety number for step 4. Then:

```
CipherChatConnector run connectors\commandcentre.json
```

`check` lists the MCP server's tools and confirms every command maps to one; `forget` deletes this PC's keys.
The connector opens no window, port or listener: it starts `DcxMcp.exe` hidden and talks to it over stdio.

In a room with the add-on (`!cc help` lists what you may use):

| Command | CommandCentre tool | |
|---|---|---|
| `!cc status` | fleet_status | every machine: online, role, OS, CPU, memory, user, locked |
| `!cc mesh` · `!cc monitors` | mesh_status · monitors | the mesh; uptime monitors |
| `!cc node <node>` · `inventory <node>` · `apps <node>` | node_details · node_inventory · installed_apps | one machine |
| `!cc workflows` · `runs [n]` · `audit [n]` | list_workflows · recent_runs · audit_log | |
| `!cc unifi` · `!cc clients` | unifi_devices · unifi_clients | UniFi network |
| `!cc lock <targets…>` · `wake <targets…>` | lock · wake | **actions** |
| `!cc service <op> <name> <targets…>` · `power <op> <targets…>` · `workflow <name>` | service · power · run_workflow | **actions** — CommandCentre still asks you to approve anything disruptive |

The preset is **read-only until you name operators**: look-ups work for any verified member of a room the add-on is in
(`"readers": ["*"]`, or list names); actions only for people listed in `"operators"` (never `*`). Scripts, installs,
file sends, notifications and opening tools are deliberately not wired to chat, and the connector refuses any
configuration that would fill a script, command, code or file path from a chat message.

## Connecting another system

Any program with an MCP server (stdio) can be connected. Copy `connectors\commandcentre.json` and change:

```json
{
  "name": "myservice",                     // also the key file's name
  "prefix": "!ms",
  "mcp": { "command": "C:\\Program Files\\...\\server.exe", "args": [], "timeout_seconds": 200 },
  "rooms": ["ops"],                        // optional: only these rooms (names or ids)
  "readers": ["*"], "operators": ["you"],
  "rate_per_minute": 10, "max_reply_chars": 3500,
  "commands": {
    "status": { "tool": "get_status", "help": "..." },
    "show":   { "tool": "get_item", "args": ["id"] },
    "recent": { "tool": "list_recent", "args": ["limit:int?"] },
    "restart":{ "tool": "restart", "args": ["targets..."], "action": true }
  }
}
```

Arguments: `name` (one word), `name?` (optional), `name:int`, `targets...` (the remaining words as a list),
`text*` (the remaining words as one string). `"fixed": {...}` adds constant arguments. The command path must be a full
path (no PATH lookups). The MCP server's own permission model still applies on top.

## Writing your own add-on (.NET)

`CipherChat.Addons` (windows/src) is the SDK: `ConnectorCode`, `RequestSigner`, `KeyStore` and `AddonHost`, which runs
the full chat engine as the add-on and raises `MessageReceived` only for live messages from verified people (never from
other add-ons):

```csharp
var (codeText, master) = KeyStore.Load("mybot");
var host = new AddonHost(ConnectorCode.Parse(codeText));
host.MessageReceived += m => m.Text == "!ping" ? host.ReplyAsync(m, "pong") : Task.CompletedTask;
await host.StartAsync(master);          // wipes the master once the keys are derived
```

## The signed-request protocol (for other languages)

Headers on every request (no cookies, no `Authorization`):

```
X-CipherChat-Addon:        addon.<name>
X-CipherChat-Time:         unix seconds (within 90 s of the server; a refusal carries server_time)
X-CipherChat-Nonce:        22-64 base64url characters, never reused
X-CipherChat-Content-SHA3: hex SHA3-256 of the exact body bytes (of "" for GET)
X-CipherChat-Signature:    hex HMAC-SHA3-256(key, canonical)

canonical = "CIPHERCHAT-ADDON-V1\n" + origin + "\n" + METHOD + "\n" + path?query + "\n" + addon + "\n"
            + time + "\n" + nonce + "\n" + body_sha3
```

The key is the 32 bytes in the connector code (`ccaddon1.` + base64url JSON `{o, u, k, a}`; `a` is the owner's identity
fingerprint to pin). The routes are the chat's own (`/chat/api/state`, `poll`, `rooms/<id>/items|epochs|send|burn|leave`,
`upload/<room>`, `blob/<room>/<id>`, `dm`, and `identity` once with `{bundle}` only); messages and room keys follow
docs/PROTOCOL.md exactly.

## Verified

Live, against a CipherChat server: an owner created `addon.commandcentre` in the web chat, the connector set itself up
from the code (PQ identity, owner pinned), the owner certified it after matching safety numbers, made a room with it
(room key wrapped to it with ML-KEM-1024 + X25519), and `!cc status`, `!cc node`, `!cc lock` (operator), `!cc help`,
an unknown command and a missing argument were all answered end-to-end encrypted (by a stand-in MCP server, so nothing
touched a real fleet). The CommandCentre preset was checked
against the real DcxMcp.exe: all 16 commands map to its tools.
