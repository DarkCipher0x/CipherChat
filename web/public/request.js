// "Request access" form: sent to /chat/api/request, read by an admin in the portal. A hidden field and the time taken
// to fill the form filter out bots (they get a fake success). Text only via textContent.
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var started = Date.now();
  var form = $("req"), err = $("err"), ok = $("ok"), go = $("go");
  function fail(m, field) { err.textContent = m; err.hidden = false; go.disabled = false; if (field && $(field)) $(field).focus(); }
  form.addEventListener("submit", function (e) {
    e.preventDefault();
    err.hidden = true;
    var body = { name: $("name").value.trim(), email: $("email").value.trim(), message: $("message").value.trim(),
                 agree: $("agree").checked, website: $("website").value, elapsed: Date.now() - started };
    if (body.name.length < 2) return fail("Please tell us your name.", "name");
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]{2,}$/.test(body.email)) return fail("That email address doesn't look right.", "email");
    if (body.message.length < 10) return fail("Please add a short note about who you are and why you'd like access.", "message");
    if (!body.agree) return fail("Please read the privacy & security statement and tick the box.", "agree");
    go.disabled = true;
    fetch("/chat/api/request", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
      .then(function (r) {
        return r.json().catch(function () { return {}; }).then(function (j) {
          if (r.status === 201) { form.querySelectorAll("input, textarea").forEach(function (x) { x.disabled = true; }); go.hidden = true; ok.hidden = false; return; }
          fail(r.status === 429 ? "Too many requests from this connection. Try again in a few minutes." : (j.error || "That didn't work. Please try again."), j.field);
        });
      })
      .catch(function () { fail("Couldn't reach the server. Check your connection."); });
  });
})();
