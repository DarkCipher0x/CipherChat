// CipherChat admin page. Every action is a request the server checks (role, owner protection, fresh authenticator
// code); this page only shows what the server returns. All text goes in with textContent (it's untrusted input).
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var HDR = { "X-Requested-With": "dcx-portal" };
  var me = null, reqStatus = "new";

  function el(tag, attrs, kids) {
    var e = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      var v = attrs[k];
      if (v === null || v === undefined || v === false) return;
      if (k === "cls") e.className = v;
      else if (k === "text") e.textContent = v;
      else if (k.slice(0, 2) === "on") e.addEventListener(k.slice(2), v);
      else e.setAttribute(k, v === true ? "" : String(v));
    });
    [].concat(kids || []).forEach(function (c) { if (c !== null && c !== undefined) e.append(c instanceof Node ? c : String(c)); });
    return e;
  }
  function showErr(m) { $("err").textContent = m; $("err").hidden = false; }
  function clearErr() { $("err").hidden = true; }

  // ---------------------------------------------------------------- requests, with "confirm it's you"
  function call(path, body) {
    var o = { method: body === undefined ? "GET" : "POST", credentials: "same-origin", cache: "no-store", headers: Object.assign({}, HDR) };
    if (body !== undefined) { o.headers["Content-Type"] = "application/json"; o.body = JSON.stringify(body); }
    return fetch("/chat/api/" + path, o).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) { return { status: r.status, data: j }; });
    });
  }
  function api(path, body) {
    return call(path, body).then(function (res) {
      if (res.status === 401 && res.data.reauth) return reauth().then(function () { return api(path, body); });
      if (res.status === 403 && !res.data.denied) { location.replace("/chat/login/?next=/chat/admin/"); throw new Error("Signed out"); }
      if (res.status < 200 || res.status >= 300) throw new Error(res.data.error || "HTTP " + res.status);
      return res.data;
    });
  }
  function reauth(errText) {
    var pk = window.cipherchatPasskey;
    if (!errText && pk && pk.supported()) return pk.get("reauth").catch(function () { return codeReauth(); });   // one tap with a passkey
    return codeReauth(errText);
  }
  function codeReauth(errText) {
    return dialog("Confirm it's you", function (b) {
      b.append(el("p", { text: "Changing who can use the chat needs the current 6-digit code from your authenticator app." }));
      var input = el("input", { inputmode: "numeric", autocomplete: "one-time-code", maxlength: 6, placeholder: "123456", "aria-label": "Authenticator code" });
      b.append(input);
      if (errText) b.append(el("p", { cls: "cp-err", role: "alert", text: errText }));
      return { focus: input, value: function () { return input.value.replace(/\s+/g, ""); } };
    }, [{ label: "Cancel" }, { label: "Confirm", primary: true, value: function (a) { return /^\d{6}$/.test(a.value()) ? a.value() : false; } }])
      .then(function (code) {
        if (!code) throw new Error("Cancelled: nothing was changed.");
        return call("auth/reauth", { code: code }).then(function (res) { if (res.status !== 200) return codeReauth(res.data.error || "That code isn't valid."); });
      });
  }

  // ---------------------------------------------------------------- dialogs
  function dialog(title, build, buttons) {
    return new Promise(function (resolve) {
      var d = el("dialog", { cls: "adm-dialog", "aria-label": title }, [el("h2", { text: title })]);
      var body = el("div", { cls: "cp-form" });
      d.append(body);
      var a = (build && build(body)) || {};
      var row = el("div", { cls: "btns" });
      buttons.forEach(function (bt) {
        row.append(el("button", { type: "button", cls: "btn btn-sm" + (bt.primary ? " btn-primary" : "") + (bt.danger ? " danger" : ""), text: bt.label,
          onclick: function () {
            var v = bt.value === undefined ? null : (typeof bt.value === "function" ? bt.value(a) : bt.value);
            if (v === false) return;
            d.close(); d.remove(); resolve(v);
          } }));
      });
      d.append(row);
      d.addEventListener("cancel", function () { d.remove(); resolve(null); });
      document.body.append(d);
      d.showModal();
      if (a.focus) a.focus.focus();
    });
  }
  function field(label, input) { return el("label", {}, [label, input]); }
  function showLink(title, link, note) {
    return dialog(title, function (b) {
      b.append(el("p", { text: note }));
      var copy = el("button", { type: "button", cls: "btn btn-sm", text: "Copy",
        onclick: function () { if (navigator.clipboard) navigator.clipboard.writeText(link.url).then(function () { copy.textContent = "Copied"; }); } });
      b.append(el("div", { cls: "link-box" }, [el("code", { text: link.url }), copy]));
      b.append(el("p", { cls: "cp-small", text: "Shown once. It works for " + link.expires_hours + " hours, only once. Send it privately." }));
    }, [{ label: "Done", primary: true, value: true }]);
  }
  function emailNote(j, fallback) {
    if (!j.email) return fallback;
    if (j.email.sent) return "Emailed to " + j.email.to.join(", ") + ". It's also shown here, once.";
    return "The email was NOT sent (" + j.email.error + "). " + fallback;
  }

  // ---------------------------------------------------------------- tabs
  // each tab shows only for people holding one of its permissions (the server checks again on every request)
  var TABS = { requests: ["admin.requests.review"], people: ["admin.users.view"], roles: ["admin.users.view", "admin.roles.manage"],
               settings: ["admin.settings.manage"], mail: ["admin.mail.manage"], audit: ["admin.audit.view"] };
  var tabs = Object.keys(TABS);
  function has(p) { return !!me && (me.owner || (me.permissions || []).indexOf(p) >= 0); }
  function allowed(t) { return TABS[t].some(has); }
  tabs.forEach(function (t) {
    $("tab-" + t).addEventListener("click", function () { select(t); });
  });
  function select(t) {
    tabs.forEach(function (x) {
      $("tab-" + x).setAttribute("aria-selected", x === t ? "true" : "false");
      $("panel-" + x).hidden = x !== t;
    });
    clearErr();
    ({ requests: loadRequests, people: loadPeople, roles: loadRoles, settings: loadSettings, mail: loadMail, audit: loadAudit })[t]()
      .catch(function (e) { showErr(e.message); });
  }

  // ---------------------------------------------------------------- requests
  document.querySelectorAll("[data-status]").forEach(function (b) {
    b.addEventListener("click", function () {
      document.querySelectorAll("[data-status]").forEach(function (x) { x.classList.remove("active"); x.setAttribute("aria-pressed", "false"); });
      b.classList.add("active"); b.setAttribute("aria-pressed", "true");
      reqStatus = b.getAttribute("data-status");
      loadRequests().catch(function (e) { showErr(e.message); });
    });
  });
  function suggest(name) {
    var s = String(name || "").toLowerCase().normalize("NFKD").replace(/[^a-z0-9]+/g, ".").replace(/^\.+|\.+$/g, "");
    return s.length >= 3 ? s.slice(0, 32) : "";
  }
  function loadRequests() {
    return api("admin/requests?status=" + encodeURIComponent(reqStatus)).then(function (j) {
      var list = $("req-list"); list.textContent = "";
      $("req-count").textContent = j.counts && j.counts["new"] ? String(j.counts["new"]) : "";
      $("req-empty").hidden = (j.requests || []).length > 0;
      (j.requests || []).forEach(function (r) {
        var acts = el("div", { cls: "adm-actions" });
        if (r.status === "new") {
          acts.append(el("button", { type: "button", cls: "btn btn-sm btn-primary", text: "Approve and invite", onclick: function () { approve(r); } }),
            el("button", { type: "button", cls: "btn btn-sm", text: "Decline", onclick: function () { decideReq(r, "decline"); } }));
        }
        acts.append(el("button", { type: "button", cls: "btn btn-sm danger", text: "Delete", onclick: function () { decideReq(r, "delete"); } }));
        list.append(el("article", { cls: "adm-card" }, [
          el("h2", { text: r.name }),
          el("div", { cls: "meta", text: "#" + r.id + " · " + r.email + " · " + new Date(r.created * 1000).toLocaleString() + " · " + r.status +
            (r.decided_by ? " by " + r.decided_by : "") + (r.username ? " (account " + r.username + ")" : "") }),
          el("pre", { text: r.message }), acts]));
      });
    });
  }
  function approve(r) {
    dialog("Approve " + r.name, function (b) {
      b.append(el("p", { text: "Creates an invitation for " + r.email + ". They choose a password and authenticator, then a chat passphrase." }));
      var u = el("input", { maxlength: 32, spellcheck: "false", autocomplete: "off", value: suggest(r.name) });
      var send = el("input", { type: "checkbox", checked: true });
      b.append(field("Username (3-32: a-z 0-9 . _ -)", u), el("label", { cls: "check" }, [send, el("span", { text: "Email the link (if email is set up)" })]));
      return { focus: u, value: function () { return { action: "approve", username: u.value.trim().toLowerCase(), send_email: send.checked }; } };
    }, [{ label: "Cancel" }, { label: "Approve and invite", primary: true, value: function (a) { return a.value(); } }])
      .then(function (body) {
        if (!body) return;
        return api("admin/requests/" + r.id, body).then(function (j) {
          loadRequests();
          if (j.link) return showLink("Invitation for " + j.username, j.link, emailNote(j, "Send this link to " + r.name + " privately."));
        });
      }).catch(function (e) { showErr(e.message); });
  }
  function decideReq(r, action) {
    var text = action === "decline" ? "No account is created. The request stays in the list for 90 days." : "The request (name, email, message) is removed now.";
    dialog((action === "decline" ? "Decline" : "Delete") + " request #" + r.id + "?", function (b) { b.append(el("p", { text: text })); },
      [{ label: "Cancel" }, { label: action === "decline" ? "Decline" : "Delete", danger: action === "delete", primary: action === "decline", value: true }])
      .then(function (ok) { if (ok) return api("admin/requests/" + r.id, { action: action }).then(loadRequests); })
      .catch(function (e) { showErr(e.message); });
  }

  // ---------------------------------------------------------------- people
  function statusTag(u) {
    var cls = u.status === "active" ? "ok" : u.status === "pending" ? "warn" : "bad";
    return el("span", { cls: "tag " + cls, text: u.status + (u.locked ? ", locked" : "") });
  }
  var people = null, catalog = null;
  function loadCatalog() {
    return catalog ? Promise.resolve(catalog) : api("admin/roles").then(function (r) { catalog = r; return r; });
  }
  function loadPeople() {
    return Promise.all([api("admin/users"), loadCatalog()]).then(function (res) {
      var j = res[0];
      people = j;
      $("owner-name").textContent = j.owner;
      var tb = $("people-list"); tb.textContent = "";
      j.users.forEach(function (u) {
        var isOwner = u.username === j.owner, mine = u.username === j.me;
        var actions = el("td");
        if (u.manageable || mine || (me && me.owner)) {
          actions.append(el("button", { type: "button", cls: "btn btn-sm", text: "Manage", onclick: function () { manage(u, j); } }));
        }
        tb.append(el("tr", {}, [
          el("td", {}, [el("b", { text: u.username + (mine ? " (you)" : "") }), u.display_name ? el("div", { cls: "mute", text: u.display_name }) : null]),
          el("td", {}, [el("span", { text: isOwner ? "owner" : u.role }),
            (u.grants.length || u.denies.length) ? el("div", { cls: "mute", text: (u.grants.length ? "+" + u.grants.length : "") + (u.denies.length ? " -" + u.denies.length : "") + " custom" }) : null]),
          el("td", {}, statusTag(u)),
          el("td", {}, el("span", { cls: "tag " + (u.certified ? "ok" : u.chat_identity ? "warn" : ""), text: u.certified ? "verified" : u.chat_identity ? "awaiting the owner" : "not set up" })),
          el("td", { cls: "mono", text: u.last_login ? u.last_login.replace("T", " ").replace("Z", "") : "-" }),
          actions]));
      });
    });
  }
  function manage(u, j) {
    var isOwner = u.username === j.owner;
    var opts = [{ label: "Close" }];
    dialog("Manage " + u.username, function (b) {
      b.append(el("p", { cls: "dim", text: "Role " + (isOwner ? "owner" : u.role) + " · " + u.status + " · " + u.sessions + " active session(s)" }));
      var sel = null, editor = null;
      var canRoles = !isOwner && u.username !== j.me && u.manageable && has("admin.users.roles");
      if (canRoles) {
        sel = el("select", {}, j.roles.map(function (r) { return el("option", { value: r, selected: r === u.role, text: r }); }));
        b.append(field("Role", sel));
        editor = permEditor(u, j);
        b.append(editor.node);
      }
      var row = el("div", { cls: "adm-actions" });
      function act(label, action, danger, body, perm) {
        if (perm && !has(perm)) return;
        row.append(el("button", { type: "button", cls: "btn btn-sm" + (danger ? " danger" : ""), text: label, onclick: function (ev) {
          ev.target.closest("dialog").close(); ev.target.closest("dialog").remove();
          runAction(u, action, body ? body() : {});
        } }));
      }
      if (sel) act("Save role", "role", false, function () { return { role: sel.value }; });
      if (editor) act("Save permissions", "permissions", false, function () { return editor.value(); });
      if (!u.manageable && u.username !== j.me && !isOwner) b.append(el("p", { cls: "cp-small", text: "You can only change accounts with fewer permissions than you have." }));
      if (!u.manageable && !(me && me.owner) && u.username !== j.me) { b.append(row); return; }
      if (u.status === "pending") act("New invite link", "new_invite", false, null, "admin.users.update");
      if (u.status === "active" && u.username !== j.me) act("Suspend", "suspend", true, null, "admin.users.update");
      if (u.status === "suspended") act("Re-activate", "activate", false, null, "admin.users.update");
      if (u.status === "active") { act("Password reset link", "reset_password", false, null, "admin.users.update"); act("Authenticator reset link", "reset_mfa", false, null, "admin.users.update"); }
      act("Sign out everywhere", "sign_out", false, null, "admin.users.update");
      if (!isOwner && u.username !== j.me) act("Remove account", "delete", true, null, "admin.users.delete");
      b.append(row);
      b.append(el("p", { cls: "cp-small", text: "Removing an account deletes its chat identity and memberships. Its old messages stay unreadable to everyone else's new keys." }));
    }, opts);
  }
  function runAction(u, action, body) {
    var confirmText = { suspend: "They're signed out at once and can't sign in until re-activated.",
                        delete: "This can't be undone. They lose access, their identity and their room memberships." }[action];
    var go = confirmText ? dialog(action === "delete" ? "Remove " + u.username + "?" : "Suspend " + u.username + "?",
      function (b) { b.append(el("p", { text: confirmText })); }, [{ label: "Cancel" }, { label: action === "delete" ? "Remove" : "Suspend", danger: true, value: true }])
      : Promise.resolve(true);
    go.then(function (ok) {
      if (!ok) return;
      return api("admin/users/" + encodeURIComponent(u.username) + "/" + action, Object.assign({ send_email: true }, body)).then(function (j) {
        loadPeople();
        if (j.link) return showLink("Link for " + u.username, j.link, emailNote(j, "Send this link to " + u.username + " privately."));
      });
    }).catch(function (e) { showErr(e.message); });
  }
  $("invite-btn").addEventListener("click", function () {
    dialog("Invite someone", function (b) {
      var u = el("input", { maxlength: 32, spellcheck: "false", autocomplete: "off" });
      var n = el("input", { maxlength: 80, autocomplete: "off" });
      var e = el("input", { type: "email", maxlength: 120, autocomplete: "off" });
      var r = el("select", {}, invitableRoles().map(function (x) { return el("option", { value: x, selected: x === "member", text: x }); }));
      var send = el("input", { type: "checkbox", checked: true });
      b.append(field("Username (3-32: a-z 0-9 . _ -)", u), field("Display name (optional)", n), field("Email (optional; to email the link)", e),
        field("Role", r), el("label", { cls: "check" }, [send, el("span", { text: "Email the link to that address" })]));
      return { focus: u, value: function () { return { username: u.value.trim().toLowerCase(), display_name: n.value, email: e.value.trim(), role: r.value,
                                                        send_email: send.checked && !!e.value.trim() }; } };
    }, [{ label: "Cancel" }, { label: "Create invitation", primary: true, value: function (a) { return a.value(); } }])
      .then(function (body) {
        if (!body) return;
        return api("admin/users/invite", body).then(function (j) {
          loadPeople();
          return showLink("Invitation for " + j.username, j.link, emailNote(j, "Send this link privately. It sets up a password and an authenticator app."));
        });
      }).catch(function (e) { showErr(e.message); });
  });

  // ---------------------------------------------------------------- permissions
  function mine() { return me && me.owner ? catalog.permissions.map(function (p) { return p.id; }) : (people && people.mine) || catalog.mine || []; }
  function rolePerms(name) { var r = (catalog.roles || []).filter(function (x) { return x.name === name; })[0]; return r ? r.perms : []; }
  function strictlyBelow(perms) {
    if (me && me.owner) return true;
    var m = mine();
    return perms.every(function (p) { return m.indexOf(p) >= 0; }) && perms.length < m.length;
  }
  function invitableRoles() {
    return (people ? people.roles : []).filter(function (r) { return strictlyBelow(rolePerms(r)); });
  }
  function groups() {
    var g = {};
    catalog.permissions.forEach(function (p) { (g[p.group] = g[p.group] || []).push(p); });
    return g;
  }
  // one row per permission: from the role / always / never. Permissions the editor doesn't hold can't be given.
  function permEditor(u, j) {
    var node = el("fieldset", { cls: "perm-editor" }, [el("legend", { text: "Permissions on top of the role" })]);
    var selects = {};
    var m = mine();
    var g = groups();
    Object.keys(g).forEach(function (name) {
      node.append(el("div", { cls: "perm-group", text: name }));
      g[name].forEach(function (p) {
        var cur = u.grants.indexOf(p.id) >= 0 ? "grant" : u.denies.indexOf(p.id) >= 0 ? "deny" : "role";
        var s = el("select", { "aria-label": p.label }, [
          el("option", { value: "role", text: "as the role", selected: cur === "role" }),
          el("option", { value: "grant", text: "always", selected: cur === "grant", disabled: !(me && me.owner) && m.indexOf(p.id) < 0 }),
          el("option", { value: "deny", text: "never", selected: cur === "deny" })]);
        selects[p.id] = s;
        node.append(el("label", { cls: "perm-row" }, [el("span", { text: p.label }), el("code", { text: p.id }), s]));
      });
    });
    return { node: node, value: function () {
      var out = { grants: [], denies: [] };
      Object.keys(selects).forEach(function (id) {
        if (selects[id].value === "grant") out.grants.push(id);
        if (selects[id].value === "deny") out.denies.push(id);
      });
      return out;
    } };
  }

  // ---------------------------------------------------------------- roles
  function loadRoles() {
    catalog = null;
    return loadCatalog().then(function (j) {
      var list = $("role-list"); list.textContent = "";
      $("role-new").hidden = !j.can_manage;
      var labels = {};
      j.permissions.forEach(function (p) { labels[p.id] = p.label; });
      j.roles.forEach(function (r) {
        var acts = el("div", { cls: "adm-actions" });
        var editable = j.can_manage && r.perms.every(function (p) { return j.mine.indexOf(p) >= 0; });
        if (editable) {
          acts.append(el("button", { type: "button", cls: "btn btn-sm", text: "Edit", onclick: function () { editRole(r); } }));
          if (!r.builtin) acts.append(el("button", { type: "button", cls: "btn btn-sm danger", text: "Delete", onclick: function () { deleteRole(r); } }));
        }
        list.append(el("article", { cls: "adm-card" }, [
          el("h2", { text: r.label + (r.label !== r.name ? " (" + r.name + ")" : "") }),
          el("div", { cls: "meta", text: (r.builtin ? "built-in · " : "") + r.people + " account(s) · changed " + r.updated.replace("T", " ").replace("Z", "") + (r.updated_by ? " by " + r.updated_by : "") }),
          el("div", { cls: "chips" }, r.perms.length ? r.perms.map(function (p) { return el("span", { cls: "tag", title: p, text: labels[p] || p }); }) : el("span", { cls: "mute", text: "no permissions" })),
          acts]));
      });
    });
  }
  function roleForm(r) {
    return function (b) {
      var name = null;
      if (!r) {
        name = el("input", { maxlength: 24, spellcheck: "false", autocomplete: "off", placeholder: "moderator" });
        b.append(field("Name (2-24: a-z 0-9 -, starting with a letter)", name));
      }
      var label = el("input", { maxlength: 40, value: r ? r.label : "" });
      b.append(field("Label", label));
      var boxes = {};
      var g = groups();
      Object.keys(g).forEach(function (gn) {
        b.append(el("div", { cls: "perm-group", text: gn }));
        g[gn].forEach(function (p) {
          var c = el("input", { type: "checkbox", checked: r ? r.perms.indexOf(p.id) >= 0 : false, disabled: catalog.mine.indexOf(p.id) < 0 });
          boxes[p.id] = c;
          b.append(el("label", { cls: "check" }, [c, el("span", { text: p.label })]));
        });
      });
      b.append(el("p", { cls: "cp-small", text: "You can only include permissions you hold yourself. Changing a role changes it for everyone who has it." }));
      return { focus: name || label, value: function () {
        var perms = Object.keys(boxes).filter(function (k) { return boxes[k].checked; });
        var out = { label: label.value.trim(), perms: perms };
        if (name) out.name = name.value.trim().toLowerCase();
        return out;
      } };
    };
  }
  function editRole(r) {
    dialog("Role: " + r.label, roleForm(r), [{ label: "Cancel" }, { label: "Save", primary: true, value: function (a) { return a.value(); } }])
      .then(function (body) { if (body) return api("admin/roles/" + r.name, body).then(loadRoles); })
      .catch(function (e) { showErr(e.message); });
  }
  function deleteRole(r) {
    dialog("Delete the role " + r.label + "?", function (b) { b.append(el("p", { text: "Only possible when nobody has it." })); },
      [{ label: "Cancel" }, { label: "Delete", danger: true, value: true }])
      .then(function (ok) { if (ok) return api("admin/roles/" + r.name + "/delete", {}).then(loadRoles); })
      .catch(function (e) { showErr(e.message); });
  }
  $("role-new").addEventListener("click", function () {
    dialog("New role", roleForm(null), [{ label: "Cancel" }, { label: "Create", primary: true, value: function (a) { return a.value(); } }])
      .then(function (body) { if (body) return api("admin/roles", body).then(loadRoles); })
      .catch(function (e) { showErr(e.message); });
  });

  // ---------------------------------------------------------------- settings
  var SETTING_GROUPS = [
    ["General", [["name", "Server name (titles, emails, authenticator apps; empty = the installer's)"]]],
    ["Sign-up", [["access_requests", "Take access requests from the public page"], ["request_role", "Role given when a request is approved"]]],
    ["Security", [["password_min", "Shortest password allowed (characters)"], ["reauth_minutes", "\"Confirm it's you\" lasts (minutes)"],
                  ["session_hours", "Sign-ins last at most (hours)"], ["session_idle_minutes", "Signed out after being idle for (minutes)"],
                  ["lockout_attempts", "Lock an account after this many failed sign-ins"], ["lockout_minutes", "Locked for (minutes)"],
                  ["invite_hours", "Invite and reset links work for (hours)"]]],
    ["Chat", [["upload_max_mb", "Largest attachment (MB, up to 100)"]]],
  ];
  function loadSettings() {
    return api("admin/settings").then(function (j) {
      var f = $("settings-form"); f.textContent = "";
      var inputs = {};
      SETTING_GROUPS.forEach(function (grp) {
        var fs = el("fieldset", { cls: "adm-fieldset" }, [el("legend", { text: grp[0] })]);
        grp[1].forEach(function (pair) {
          var k = pair[0], sc = j.schema[k], v = j.settings[k], input;
          if (sc.kind === "bool") {
            input = el("input", { type: "checkbox", checked: !!v });
            fs.append(el("label", { cls: "check" }, [input, el("span", { text: pair[1] })]));
          } else {
            if (k === "request_role") input = el("select", {}, j.roles.map(function (r) { return el("option", { value: r, text: r, selected: r === v }); }));
            else if (sc.kind === "int") input = el("input", { type: "number", min: sc.min, max: sc.max, value: v, required: true });
            else input = el("input", { maxlength: sc.max, value: v, placeholder: k === "name" ? j.env_name : "" });
            fs.append(field(pair[1] + (sc.kind === "int" ? " · " + sc.min + "-" + sc.max : ""), input));
          }
          inputs[k] = input;
        });
        f.append(fs);
      });
      var save = el("button", { type: "submit", cls: "btn btn-primary", text: "Save settings" });
      f.append(el("div", { cls: "adm-row" }, save));
      f.onsubmit = function (ev) {
        ev.preventDefault();
        var changes = {};
        Object.keys(inputs).forEach(function (k) {
          var sc = j.schema[k], i = inputs[k];
          var v = sc.kind === "bool" ? i.checked : sc.kind === "int" ? parseInt(i.value, 10) : i.value.trim();
          if (v !== j.settings[k]) changes[k] = v;
        });
        if (!Object.keys(changes).length) { showErr("Nothing changed."); return; }
        api("admin/settings", changes).then(function () { clearErr(); return loadSettings(); })
          .then(function () { flash(save, "Saved"); }).catch(function (e) { showErr(e.message); });
      };
    });
  }
  function flash(btn, text) { var t = btn.textContent; btn.textContent = text; setTimeout(function () { btn.textContent = t; }, 1600); }

  // ---------------------------------------------------------------- email and notifications
  function loadMail() {
    return api("admin/settings").then(function (j) {
      var box = $("mail-box"); box.textContent = "";
      var m = j.mail;
      // SMTP
      var f = el("form", { cls: "adm-form", autocomplete: "off" });
      var fs = el("fieldset", { cls: "adm-fieldset" }, [el("legend", { text: "SMTP server" })]);
      var host = el("input", { maxlength: 253, value: m.host, placeholder: "smtp.example.com", spellcheck: "false" });
      var port = el("input", { type: "number", min: 1, max: 65535, value: m.port });
      var sec = el("select", {}, [el("option", { value: "starttls", text: "STARTTLS (usually port 587)", selected: m.security === "starttls" }),
                                  el("option", { value: "tls", text: "TLS (usually port 465)", selected: m.security === "tls" })]);
      var user = el("input", { maxlength: 200, value: m.user, autocomplete: "off", spellcheck: "false" });
      var pw = el("input", { type: "password", maxlength: 512, autocomplete: "new-password", placeholder: m.has_password ? "saved (leave empty to keep it)" : "" });
      var clearPw = el("input", { type: "checkbox" });
      var from = el("input", { type: "email", maxlength: 200, value: m.from, placeholder: "chat@example.com" });
      var fromName = el("input", { maxlength: 60, value: m.from_name || "" });
      var reply = el("input", { type: "email", maxlength: 200, value: m.reply_to || "" });
      fs.append(field("Server", host), field("Port", port), field("Security (plain SMTP is never used)", sec), field("Username", user),
        field("Password (stored sealed; never shown again)", pw));
      if (m.has_password) fs.append(el("label", { cls: "check" }, [clearPw, el("span", { text: "Remove the saved password" })]));
      fs.append(field("From address", from), field("From name (optional)", fromName), field("Reply-to (optional)", reply));
      fs.append(el("p", { cls: "cp-small", text: "Settings in force: " + (m.source === "settings" ? "saved here" : m.source === "environment" ? "from the server's environment file" : "none") +
        ". Certificates are always verified. " + (j.allow_private ? "" : "The server must have a public address.") }));
      var save = el("button", { type: "submit", cls: "btn btn-primary", text: "Save email settings" });
      var testTo = el("input", { type: "email", maxlength: 200, placeholder: "your account's address" });
      var test = el("button", { type: "button", cls: "btn", text: "Send a test email" });
      fs.append(el("div", { cls: "adm-row" }, [save]), el("div", { cls: "adm-row" }, [testTo, test]));
      f.append(fs);
      f.onsubmit = function (ev) {
        ev.preventDefault();
        var body = { host: host.value.trim(), port: parseInt(port.value, 10), security: sec.value, user: user.value.trim(), from: from.value.trim(),
                     from_name: fromName.value.trim(), reply_to: reply.value.trim() };
        if (pw.value) body.password = pw.value;
        if (clearPw.checked) body.clear_password = true;
        api("admin/mail", body).then(function () { pw.value = ""; clearErr(); return loadMail(); }).catch(function (e) { showErr(e.message); });
      };
      test.onclick = function () {
        api("admin/mail/test", testTo.value.trim() ? { to: testTo.value.trim() } : {})
          .then(function (r) { flash(test, "Queued for " + r.to); setTimeout(loadMail, 6000); }).catch(function (e) { showErr(e.message); });
      };
      box.append(f);
      // notifications
      var nf = el("form", { cls: "adm-form" });
      var ns = el("fieldset", { cls: "adm-fieldset" }, [el("legend", { text: "Notifications" })]);
      var rows = {};
      var tbl = el("table", { cls: "adm-table" }, [el("thead", {}, el("tr", {}, ["Event", "On", "To admins", "To the person", "Also to (comma separated)"].map(function (h) { return el("th", { scope: "col", text: h }); })))]);
      var tb = el("tbody");
      Object.keys(j.events).forEach(function (ev) {
        var n = j.notify[ev];
        var r = { enabled: el("input", { type: "checkbox", checked: n.enabled, "aria-label": "On" }), admins: el("input", { type: "checkbox", checked: n.admins, "aria-label": "To admins" }),
                  user: el("input", { type: "checkbox", checked: n.user, "aria-label": "To the person" }), extra: el("input", { maxlength: 600, value: n.extra.join(", "), "aria-label": "Also to" }) };
        rows[ev] = r;
        tb.append(el("tr", {}, [el("td", { text: j.events[ev] }), el("td", {}, r.enabled), el("td", {}, r.admins), el("td", {}, r.user), el("td", {}, r.extra)]));
      });
      tbl.append(tb);
      ns.append(el("div", { cls: "adm-table-wrap" }, tbl),
        el("p", { cls: "cp-small", text: "\"Admins\" are people with the permission that event is about (for example, access requests go to people who review them) and an email address on their account. Notifications never contain messages." }));
      var nsave = el("button", { type: "submit", cls: "btn btn-primary", text: "Save notifications" });
      ns.append(el("div", { cls: "adm-row" }, nsave));
      nf.append(ns);
      nf.onsubmit = function (ev) {
        ev.preventDefault();
        var body = {};
        Object.keys(rows).forEach(function (k) {
          var r = rows[k];
          body[k] = { enabled: r.enabled.checked, admins: r.admins.checked, user: r.user.checked,
                      extra: r.extra.value.split(",").map(function (s) { return s.trim(); }).filter(Boolean) };
        });
        api("admin/notify", body).then(function () { flash(nsave, "Saved"); clearErr(); }).catch(function (e) { showErr(e.message); });
      };
      box.append(nf);
      // delivery log
      var lt = el("tbody");
      j.log.forEach(function (l) {
        lt.append(el("tr", {}, [el("td", { cls: "mono", text: new Date(l.at * 1000).toLocaleString() }), el("td", { cls: "mono", text: l.kind }),
          el("td", { text: l.to_masked }), el("td", {}, el("span", { cls: "tag " + (l.outcome === "sent" ? "ok" : l.outcome === "retrying" ? "warn" : "bad"), text: l.outcome })),
          el("td", { text: l.detail })]));
      });
      box.append(el("fieldset", { cls: "adm-fieldset" }, [el("legend", { text: "Delivery (" + j.queue + " waiting)" }),
        j.log.length ? el("div", { cls: "adm-table-wrap" }, el("table", { cls: "adm-table" }, [el("thead", {}, el("tr", {}, ["When", "What", "To", "Result", "Detail"].map(function (h) { return el("th", { scope: "col", text: h }); }))), lt]))
                     : el("p", { cls: "mute", text: "Nothing sent yet." })]));
    });
  }

  // ---------------------------------------------------------------- audit
  function loadAudit() {
    return api("admin/audit").then(function (j) {
      var tb = $("audit-list"); tb.textContent = "";
      j.events.forEach(function (ev) {
        tb.append(el("tr", {}, [el("td", { cls: "mono", text: ev.at.replace("T", " ").replace("Z", "") }), el("td", { text: ev.actor }),
          el("td", { cls: "mono", text: ev.action }), el("td", { text: ev.target_id }),
          el("td", {}, el("span", { cls: "tag " + (ev.outcome === "ok" ? "ok" : "bad"), text: ev.outcome })), el("td", { cls: "mono", text: ev.ip || "-" })]));
      });
    });
  }

  // ---------------------------------------------------------------- start
  $("signout").addEventListener("click", function () {
    call("auth/logout", {}).finally(function () { location.replace("/chat/login/"); });
  });
  call("auth/status").then(function (res) {
    var s = res.data;
    if (!s.signed_in) { location.replace("/chat/login/?next=/chat/admin/"); return; }
    me = s;
    $("who").textContent = s.user;
    if (!s.admin) { showErr("Your account doesn't manage this server. Ask its owner."); return; }
    tabs.forEach(function (t) { $("tab-" + t).hidden = !allowed(t); });
    $("invite-btn").hidden = !has("admin.users.create");
    var first = tabs.filter(allowed)[0];
    if (first) select(first);
  });
})();
