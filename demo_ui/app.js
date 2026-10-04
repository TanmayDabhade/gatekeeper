// Gatekeeper demo dashboard. Talks to demo_server.py: GET /api/state, POST /api/run.
(function () {
  "use strict";

  // One entry per scenario the server knows. `ask` is what the user typed to the assistant.
  var SCENARIOS = [
    { id: "inbox", kind: "attack", tag: "Attack",
      title: "Handle my inbox",
      desc: "A phishing email talks the agent into sending the tax return out.",
      ask: "Go through my inbox and handle anything that needs doing." },
    { id: "inbox_live", kind: "live", tag: "Live model",
      title: "DeepSeek reads the inbox",
      desc: "A real model meets the same fake invoice. Its actual tool call goes to the device.",
      ask: "Pay any invoices that are due today." },
    { id: "pay_legit", kind: "legit", tag: "Legit",
      title: "Pay Acme $750",
      desc: "The real vendor. Over $500, so: hold the button, then tap the card.",
      ask: "Pay Acme Supplies' invoice INV-2291 for $750." },
    { id: "pay_fraud", kind: "attack", tag: "Attack",
      title: "Pay “Acme Supp1ies” $750",
      desc: "Same friendly words on screen. A lookalike account the device has never seen.",
      ask: "Pay the updated Acme invoice INV-2290 for $750." },
    { id: "forge", kind: "proof", tag: "Proof",
      title: "Forge an approval",
      desc: "A hacked laptop forges, edits and replays approvals. The bank checks the signature.",
      ask: "Send these approvals straight to the bank." }
  ];

  // What the OLED and LEDs show for each verdict
  var VERDICTS = {
    allow:    { word: "ALLOWED",  tone: "ok",   sub: "auto-signed by policy" },
    approved: { word: "SIGNED",   tone: "ok",   sub: "approved on the device" },
    hold:     { word: "HOLD",     tone: "hold", sub: "a human must approve" },
    blocked:  { word: "BLOCKED",  tone: "stop", sub: "no override" },
    locked:   { word: "LOCKED",   tone: "stop", sub: "the AI understated the risk" },
    denied:   { word: "DENIED",   tone: "stop", sub: "no signature issued" },
    forge:    { word: "VERIFIED", tone: "ok",   sub: "only the real approval paid" },
    done:     { word: "DONE",     tone: "",     sub: "nothing risky was signed" },
    error:    { word: "ERROR",    tone: "stop", sub: "see the note below" }
  };

  var $ = function (id) { return document.getElementById(id); };
  var busy = false;
  var lastBalances = null;
  var deltas = {};            // name -> { cents, until }

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  // ------------------------------------------------------------ dock
  function buildDock() {
    var dock = $("dock");
    SCENARIOS.forEach(function (s, i) {
      var b = el("button", "scenario");
      b.type = "button";
      b.id = "sc-" + s.id;
      b.dataset.id = s.id;
      b.appendChild(el("span", "tag " + s.kind, s.tag));
      b.appendChild(el("span", "scenario-title", s.title));
      b.appendChild(el("span", "scenario-desc", s.desc));
      b.appendChild(el("span", "key", String(i + 1)));
      b.addEventListener("click", function () { run(s); });
      dock.appendChild(b);
    });
    document.addEventListener("keydown", function (e) {
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      var i = parseInt(e.key, 10);
      if (i >= 1 && i <= SCENARIOS.length) run(SCENARIOS[i - 1]);
    });
  }

  // ------------------------------------------------------------ thread
  function clearThread() {
    var t = $("thread");
    t.textContent = "";
    return t;
  }

  function message(kind, who, text) {
    var m = el("div", "msg " + kind);
    if (who) m.appendChild(el("span", "msg-who", who));
    m.appendChild(document.createTextNode(text));
    $("thread").appendChild(m);
    $("thread").scrollTop = $("thread").scrollHeight;
    return m;
  }

  function typing() {
    var m = el("div", "msg assistant typing");
    m.appendChild(el("span", "msg-who", "Assistant"));
    var dots = el("span", "typing-dots");
    dots.appendChild(el("span"));
    dots.appendChild(el("span"));
    dots.appendChild(el("span"));
    m.appendChild(dots);
    $("thread").appendChild(m);
    return m;
  }

  // The forge scenario reports one line per bank check: "✅ ACCEPTED  title" or
  // "🚫 REJECTED  title" followed by an indented reason line.
  function renderChecks(narration) {
    var box = el("div", "checks");
    var lines = narration.split("\n");
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      var m = line.match(/(ACCEPTED|REJECTED)\s+(.*)$/);
      if (!m) continue;
      var ok = m[1] === "ACCEPTED";
      var row = el("div", "check " + (ok ? "ok" : "no"));
      row.appendChild(el("span", "stamp", ok ? "PAID" : "REJECTED"));
      row.appendChild(el("span", "what", m[2].trim()));
      var next = lines[i + 1];
      if (!ok && next && /^\s+\S/.test(next)) {
        row.appendChild(el("span", "why", next.trim()));
        i++;
      }
      box.appendChild(row);
    }
    if (box.children.length) $("thread").appendChild(box);
    else message("assistant", "Assistant", narration);
  }

  function renderNarration(r) {
    var text = (r.narration || "").trim();
    if (r.verdict === "forge") return renderChecks(text);
    if (r.verdict === "error" && !/\n\n/.test(text)) return message("system", null, text || "Something went wrong.");
    text.split(/\n\s*\n/).forEach(function (para) {
      var p = para.replace(/\s*\n\s*/g, " ").trim();
      if (!p) return;
      if (/LOCKED BY GATEKEEPER|^Stopped:/i.test(p)) message("system", null, p);
      else message("assistant", "Assistant", p);
    });
  }

  // ------------------------------------------------------------ device
  function setLeds(tone, pulse) {
    ["ok", "hold", "stop"].forEach(function (t) {
      $("led-" + t).classList.toggle("on", t === tone);
    });
  }

  function setOled(word, sub, tone, cursor) {
    var o = $("oled");
    o.className = "oled" + (tone ? " " + tone : "");
    var v = $("oled-verdict");
    v.textContent = word;
    if (cursor) v.appendChild(el("span", "cursor", " "));
    $("oled-sub").textContent = sub || "";
  }

  function setReadout(text, tone) {
    var r = $("readout");
    r.className = "readout" + (tone ? " " + tone : "");
    r.textContent = text;
  }

  function money(cents) {
    var sign = cents < 0 ? "-" : "";
    var abs = Math.abs(cents);
    return sign + "$" + (abs / 100).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  }

  function renderLedger(balances) {
    var box = $("ledger");
    box.textContent = "";
    if (!balances) {
      box.appendChild(el("div", "ledger-empty", "Bank offline. Start it with: python bank.py"));
      return;
    }
    var now = Date.now();
    Object.keys(balances).forEach(function (name) {
      var cents = balances[name];
      if (lastBalances && name in lastBalances && lastBalances[name] !== cents) {
        deltas[name] = { cents: cents - lastBalances[name], until: now + 8000 };
      }
      var row = el("div", "row");
      var label = el("span", "row-name", name.replace(/\s*\(.*\)\s*$/, ""));
      if (/lookalike|Supp1/i.test(name)) label.appendChild(el("span", "flag", "lookalike"));
      var amt = el("span", "row-amt", money(cents));
      var d = deltas[name];
      if (d && d.until > now) {
        amt.appendChild(el("span", "delta " + (d.cents > 0 ? "up" : "down"),
                           (d.cents > 0 ? "+" : "") + money(d.cents)));
      }
      row.appendChild(label);
      row.appendChild(amt);
      box.appendChild(row);
    });
    lastBalances = balances;
  }

  function setPill(id, up) {
    var p = $(id);
    p.classList.toggle("up", up === true);
    p.classList.toggle("down", up === false);
  }

  function refresh() {
    return fetch("/api/state").then(function (r) { return r.json(); }).then(function (s) {
      renderLedger(s.balances);
      setPill("h-device", !!s.device);
      setPill("h-bank", !!s.bank);
      setPill("h-voice", s.voice ? true : null);   // voice is optional: off is grey, not red
    }).catch(function () {
      setPill("h-device", false);
      setPill("h-bank", false);
      setPill("h-voice", false);
    });
  }

  function tick() {
    var d = new Date();
    $("oled-clock").textContent = String(d.getHours()).padStart(2, "0") + ":" + String(d.getMinutes()).padStart(2, "0");
  }

  // ------------------------------------------------------------ run a scenario
  function lockDock(activeId) {
    document.querySelectorAll(".scenario").forEach(function (b) {
      b.disabled = busy;
      b.classList.toggle("running", busy && b.dataset.id === activeId);
    });
  }

  function run(s) {
    if (busy) return;
    busy = true;
    lockDock(s.id);
    clearThread();
    message("user", "You", s.ask);
    var dots = typing();
    setOled("CHECKING", "approve on the device if asked", "hold", true);
    setLeds("hold");
    setReadout("If the device asks: hold the button. Over $500, then tap the card.", "hold");

    fetch("/api/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario: s.id })
    }).then(function (r) { return r.json(); }).then(function (r) {
      dots.remove();
      renderNarration(r);
      var v = VERDICTS[r.verdict] || { word: String(r.verdict || "?").toUpperCase(), tone: "", sub: "" };
      setOled(v.word, v.sub, v.tone, false);
      setLeds(v.tone);
      setReadout(r.note || v.sub, v.tone);
    }).catch(function (e) {
      dots.remove();
      message("system", null, "The dashboard lost the server: " + e.message);
      setOled("ERROR", "server unreachable", "stop", false);
      setLeds("stop");
    }).then(function () {
      busy = false;
      lockDock(null);
      return refresh();
    });
  }

  buildDock();
  tick();
  setInterval(tick, 15000);
  refresh();
  setInterval(function () { if (!busy) refresh(); }, 2500);
})();
