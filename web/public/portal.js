// Portal bootstrap for the chat page: gives the shared chat code (/chat/app/app.js) the one thing it needs from the page,
// who is signed in, and shows the Admin link to owners and admins (the server enforces every admin action itself).
(function () {
  "use strict";
  var hdr = { "X-Requested-With": "dcx-portal" };
  var who = document.getElementById("who");
  var me = fetch("/chat/api/auth/status", { credentials: "same-origin", headers: hdr, cache: "no-store" })
    .then(function (r) { return r.ok ? r.json() : { signed_in: false }; })
    .then(function (s) {
      if (!s.signed_in) {
        location.replace("/chat/login/?next=" + encodeURIComponent(location.pathname));
        throw new Error("Signed out");
      }
      if (who) who.textContent = s.user;
      var adm = document.getElementById("admin-link");
      if (adm && s.admin) adm.hidden = false;
      return s;
    });
  me.catch(function () {});
  window.dcx = { me: function () { return me; } };

  var out = document.getElementById("signout");
  if (out) out.addEventListener("click", function () {
    fetch("/chat/api/auth/logout", { method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-Requested-With": "dcx-portal" }, body: "{}" })
      .finally(function () { location.replace("/chat/login/"); });
  });
})();
