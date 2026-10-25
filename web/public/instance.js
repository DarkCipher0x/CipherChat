// Shows this server's name (CIPHERCHAT_NAME) on the public pages. Text only (textContent), never markup.
(function () {
  "use strict";
  fetch("/chat/api/auth/status", { credentials: "same-origin", headers: { "X-Requested-With": "dcx-portal" }, cache: "no-store" })
    .then(function (r) { return r.ok ? r.json() : {}; })
    .then(function (s) {
      if (!s.name || s.name === "CipherChat") return;
      document.querySelectorAll("[data-name-text]").forEach(function (el) { el.textContent = s.name; });
      document.title = document.title.replace("CipherChat", s.name);
    })
    .catch(function () {});
})();
