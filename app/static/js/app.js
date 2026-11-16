/* Progressive enhancement. Every form on the site works without JavaScript (the server then
 * encrypts and signs on the user's behalf). With JavaScript and unlocked keys, the same
 * forms are intercepted: content is encrypted and signed in the browser and sent to the
 * JSON API, and chat switches to the Double Ratchet over a WebSocket.
 *
 * Uses the Alpine.js CSP build: directives may only reference properties and methods, and
 * x-model is unavailable (it compiles to an assignment). Inputs are read via x-ref instead. */
(function () {
  "use strict";
  const $ = (sel, root) => (root || document).querySelector(sel);
  const userData = () => document.body.dataset;
  const hasKeys = () => !!userData().signingPubkey;

  const TOAST_KIND = { ok: "success", err: "error", warn: "warning", info: "info" };
  const TOAST_ICON = { success: "check_circle", error: "error", warning: "warning", info: "info" };
  const MAX_TOASTS = 4;

  function icon(name) {
    const el = document.createElement("span");
    el.className = "material-symbols-rounded icon-sm";
    el.setAttribute("aria-hidden", "true");
    el.textContent = name;
    return el;
  }

  function dismiss(el) {
    if (el.classList.contains("removing")) return;
    el.classList.add("removing");
    el.addEventListener("animationend", () => el.remove(), { once: true });
    setTimeout(() => el.remove(), 400); // reduced motion: no animationend
  }

  function toast(text, kind) {
    const box = $("#toasts");
    if (!box) return;
    const variant = TOAST_KIND[kind] || kind || "success";
    const el = document.createElement("div");
    el.className = "toast toast-" + variant;
    el.setAttribute("role", variant === "error" ? "alert" : "status");
    const body = document.createElement("div");
    body.className = "toast-content";
    const msg = document.createElement("p");
    msg.className = "toast-message";
    msg.textContent = text;
    body.appendChild(msg);
    const close = document.createElement("button");
    close.type = "button";
    close.className = "toast-close";
    close.setAttribute("aria-label", "Dismiss");
    close.appendChild(icon("close"));
    close.addEventListener("click", () => dismiss(el));
    el.append(icon(TOAST_ICON[variant] || "info"), body, close);
    box.appendChild(el);
    while (box.children.length > MAX_TOASTS) box.firstElementChild.remove();
    setTimeout(() => dismiss(el), variant === "error" ? 9000 : 5000);
  }

  // Account menu (<details>): close on outside click or Escape. Without JS it still
  // opens and closes from its own summary.
  document.addEventListener("click", (ev) => {
    document.querySelectorAll("details.nav-menu[open]").forEach((d) => {
      if (!d.contains(ev.target)) d.open = false;
    });
  });
  document.addEventListener("keydown", (ev) => {
    if (ev.key !== "Escape") return;
    document.querySelectorAll("details.nav-menu[open]").forEach((d) => {
      d.open = false;
      d.querySelector("summary").focus();
    });
  });

  // --- Unlock dialog -------------------------------------------------------------------

  let unlocking = null;
  async function requireIdentity() {
    await D1.ready;
    const cached = D1.loadIdentity();
    if (cached && D1.matchesAccount(cached)) return cached;
    if (!hasKeys()) return null;
    if (unlocking) return unlocking;
    const dialog = $("#unlock-dialog");
    if (!dialog) return null;
    unlocking = new Promise((resolve) => {
      const form = $("form", dialog), input = $("input[type=password]", dialog), err = $(".error", dialog);
      err.textContent = "";
      const finish = (ident) => {
        form.removeEventListener("submit", onSubmit);
        dialog.removeEventListener("close", onClose);
        if (dialog.open) dialog.close();
        unlocking = null;
        resolve(ident);
      };
      const onClose = () => finish(null);
      const onSubmit = (ev) => {
        ev.preventDefault();
        if (ev.submitter && ev.submitter.value === "cancel") return finish(null);
        err.textContent = "Deriving keys…";
        setTimeout(() => {
          const ident = D1.deriveIdentity(userData().userEmail, input.value);
          if (!D1.matchesAccount(ident)) {
            err.textContent = "That passphrase does not match your account keys.";
            return;
          }
          D1.storeIdentity(ident);
          input.value = "";
          finish(ident);
        }, 30);
      };
      form.addEventListener("submit", onSubmit);
      dialog.addEventListener("close", onClose);
      dialog.showModal();
      input.focus();
    });
    return unlocking;
  }

  // --- Builders for each signed object type -------------------------------------------

  const num = (v) => Math.round(parseFloat(v || "0") * 100);
  const MONEY_SYMBOLS = { USD: "$", EUR: "€", GBP: "£", SGD: "S$", PHP: "₱" };
  const money = (cents, currency) => {
    const cur = (currency || "").toUpperCase();
    const amount = (cents / 100).toLocaleString("en-US", {
      minimumFractionDigits: 2, maximumFractionDigits: 2,
    });
    return MONEY_SYMBOLS[cur] ? MONEY_SYMBOLS[cur] + amount : amount + " " + cur;
  };
  const dateOrNull = (v) => (v ? v : null);

  async function encryptImages(form) {
    const input = form.querySelector("input[type=file]");
    const files = input ? Array.from(input.files || []) : [];
    const out = [];
    for (const f of files.slice(0, 8)) {
      const key = D1.sodium.randombytes_buf(32);
      const blob = D1.seal(new Uint8Array(await f.arrayBuffer()), key);
      const fd = new FormData();
      fd.append("file", new Blob([blob], { type: "application/octet-stream" }), "blob");
      const { cid } = await D1.api("POST", "/api/ipfs/upload", fd, true);
      out.push({ cid, key: D1.b64e(key), mime: f.type });
    }
    return out;
  }

  const builders = {
    async listing(form, fd) {
      let images = [];
      if (form.dataset.ct) { // editing: keep the existing images the user did not remove
        const old = await D1.openJson(D1.b64d(form.dataset.ct));
        const removed = new Set(fd.getAll("remove_images").map(Number));
        images = (old.images || []).filter((_, i) => !removed.has(i));
      }
      images = images.concat(await encryptImages(form)).slice(0, 8);
      const plain = {
        title: fd.get("title").trim(), desc: (fd.get("desc") || "").trim(),
        price_cents: num(fd.get("price")), currency: fd.get("currency"),
        category: fd.get("category"), condition: fd.get("condition"), images,
        location_approx: (fd.get("location_approx") || "").trim(),
        expires_at: dateOrNull(fd.get("expires_at")),
      };
      return { context: "listing", ct: await D1.sealJson(plain),
        body: (ct, sig) => ({ ct, sig }) };
    },
    async offer(form, fd) {
      const plain = {
        amount_cents: num(fd.get("amount")), currency: fd.get("currency"),
        message: (fd.get("message") || "").trim(), expires_at: dateOrNull(fd.get("expires_at")),
        payment_method: fd.get("payment_method"),
      };
      return { context: "offer", ct: await D1.sealJson(plain),
        body: (ct, sig) => ({ listing_id: form.dataset.listingId, offer_ct: ct, sig }) };
    },
    async rating(form, fd) {
      const plain = { score: parseInt(fd.get("score"), 10), note: (fd.get("note") || "").trim(),
        listing_id: form.dataset.listingId, offer_id: form.dataset.offerId };
      return { context: "rating", ct: await D1.sealJson(plain),
        body: (ct, sig) => ({ offer_id: form.dataset.offerId, rating_ct: ct, sig }) };
    },
    async report(form, fd) {
      const details = (fd.get("details") || "").trim();
      const detailsCt = details ? await D1.sealJson({ text: details }) : new Uint8Array(0);
      const t = fd.get("target_type"), id = fd.get("target_id"), reason = fd.get("reason");
      const zero = new Uint8Array([0]);
      const payload = D1.concat(D1.utf8(t), zero, D1.utf8(id), zero, D1.utf8(reason), zero, detailsCt);
      return { context: "report", ct: payload, body: (_, sig) => ({
        target_type: t, target_id: id, reason, sig,
        details_ct: details ? D1.b64e(detailsCt) : null }) };
    },
  };

  // --- Alpine components --------------------------------------------------------------

  document.addEventListener("alpine:init", () => {
    /* <form x-data="signedForm" data-kind="listing|offer|rating|report" data-api="/api/..."
     *       data-method="POST" data-next="/redirect">. Falls back to a normal POST. */
    Alpine.data("signedForm", () => ({
      busy: false,
      status: "",
      init() {
        this.$el.addEventListener("submit", (ev) => this.submit(ev));
      },
      async submit(ev) {
        const form = this.$el;
        if (form.dataset.native === "1") return; // explicit fallback, let it POST
        ev.preventDefault();
        this.busy = true;
        this.status = "Encrypting and signing in your browser…";
        try {
          const ident = await requireIdentity();
          if (!ident) { // no keys, or user cancelled: server encrypts and signs instead
            form.dataset.native = "1";
            this.status = "";
            // Defer: requestSubmit() inside a submit handler is ignored (re-entrant submit).
            setTimeout(() => (form.requestSubmit ? form.requestSubmit() : form.submit()), 0);
            return;
          }
          const fd = new FormData(form);
          const built = await builders[form.dataset.kind](form, fd);
          const sig = D1.sign(built.context, built.ct, ident.signingSk);
          const res = await D1.api(form.dataset.method || "POST", form.dataset.api,
            built.body(D1.b64e(built.ct), D1.b64e(sig)));
          const next = (form.dataset.next || "/").replace("{id}", res.id || "");
          window.location.assign(next);
        } catch (e) {
          this.status = "";
          this.busy = false;
          toast(e.message || String(e), "err");
        }
      },
    }));

    /* <span x-data="sigBadge" data-context data-ct data-sig data-pk data-name> */
    Alpine.data("sigBadge", () => ({
      label: "",
      cls: "badge",
      async init() {
        const d = this.$el.dataset;
        this.label = this.$el.textContent.trim();
        try {
          await D1.ready;
          const origin = await D1.sigOrigin(d.context, D1.b64d(d.ct), D1.b64d(d.sig),
            d.pk ? D1.b64d(d.pk) : null);
          if (origin === "user") {
            this.label = "✓ Signed by @" + d.name + ". Verified in your browser";
            this.cls = "badge badge-ok";
          } else if (origin === "server") {
            this.label = "✓ Server-signed (posted without JavaScript). Verified";
            this.cls = "badge badge-muted";
          } else {
            this.label = "✗ Signature INVALID. Content may have been tampered with";
            this.cls = "badge badge-err";
          }
        } catch (e) { /* keep the server-rendered label */ }
      },
    }));

    /* Settings: create/unlock/change passphrase keys, reveal or restore the backup seed. */
    Alpine.data("keySetup", () => ({
      seedHex: "", status: "", busy: false,
      unlocked: false, hasKeys: hasKeys(),
      async init() {
        await D1.ready;
        const id = D1.loadIdentity();
        this.unlocked = !!(id && D1.matchesAccount(id));
      },
      get locked() { return this.hasKeys && !this.unlocked; },
      async upload(ident) {
        const uid = userData().userId;
        const payload = D1.concat(D1.utf8(uid), ident.signingPk, ident.exchangePk, ident.profilePk);
        await D1.api("PUT", "/api/users/me/keys", {
          signing_pubkey: D1.b64e(ident.signingPk), exchange_pubkey: D1.b64e(ident.exchangePk),
          profile_enc_key: D1.b64e(ident.profilePk),
          proof: D1.b64e(D1.sign("keys", payload, ident.signingSk)),
        });
        D1.storeIdentity(ident);
        window.location.assign("/settings?m=keys_saved");
      },
      async create() {
        const pass1 = this.$refs.pass1 ? this.$refs.pass1.value : "";
        const pass2 = this.$refs.pass2 ? this.$refs.pass2.value : "";
        if (pass1.length < 12) { this.status = "Use at least 12 characters (a few random words is best)."; return; }
        if (pass1 !== pass2) { this.status = "Passphrases do not match."; return; }
        if (this.hasKeys && !confirm("Changing your passphrase creates new keys. Existing end-to-end encrypted chats will become unreadable on this device. Continue?")) return;
        this.busy = true; this.status = "Deriving keys (this takes a second)…";
        await D1.ready;
        setTimeout(async () => {
          try { await this.upload(D1.deriveIdentity(userData().userEmail, pass1)); }
          catch (e) { this.status = e.message; this.busy = false; }
        }, 30);
      },
      async unlock() {
        const id = await requireIdentity();
        this.unlocked = !!id;
      },
      lock() { D1.forget(); this.unlocked = false; this.seedHex = ""; },
      async reveal() {
        const id = await requireIdentity();
        if (id) { this.unlocked = true; this.seedHex = D1.sodium.to_hex(id.seed); }
      },
      async restore() {
        await D1.ready;
        try {
          const id = D1.identityFromSeed(D1.sodium.from_hex(this.$refs.seedInput.value.trim()));
          if (!D1.matchesAccount(id)) { this.status = "That seed does not match this account."; return; }
          D1.storeIdentity(id); this.unlocked = true; this.$refs.seedInput.value = ""; this.status = "Keys restored for this session.";
        } catch (e) { this.status = "Seed must be 64 hex characters."; }
      },
    }));

    /* Listings: client-side fuzzy search over the decrypted index. */
    Alpine.data("search", () => ({
      query: "", count: 0, active: false, loading: false, note: "",
      index: null, fuse: null, timer: null,
      async load() {
        if (this.index || this.loading) return;
        this.loading = true;
        await D1.ready;
        const { listings } = await D1.api("GET", "/api/listings");
        this.index = [];
        for (const l of listings) {
          try {
            const p = await D1.openJson(D1.b64d(l.listing_ct));
            const origin = await D1.sigOrigin("listing", D1.b64d(l.listing_ct), D1.b64d(l.sig),
              l.seller_signing_pubkey ? D1.b64d(l.seller_signing_pubkey) : null);
            if (origin) this.index.push({ ...p, id: l.id, seller: l.seller_handle });
          } catch (e) { /* skip unreadable */ }
        }
        this.fuse = new Fuse(this.index, { keys: ["title", "desc", "category", "seller"], threshold: 0.35, ignoreLocation: true });
        this.loading = false;
        this.note = "Searching " + this.index.length + " listings in your browser. Your query never leaves this device.";
        this.run();
      },
      onInput() {
        this.query = this.$refs.q.value;
        clearTimeout(this.timer);
        this.timer = setTimeout(() => (this.index ? this.run() : this.load()), 150);
      },
      run() {
        const q = this.query.trim();
        this.active = q.length > 0;
        const out = $("#search-results");
        out.replaceChildren();
        if (!this.active || !this.fuse) return;
        const hits = this.fuse.search(q).slice(0, 60).map((r) => r.item);
        this.count = hits.length;
        const tpl = $("#card-tpl");
        for (const l of hits) {
          const card = tpl.content.firstElementChild.cloneNode(true);
          card.href = "/listings/" + l.id;
          $("[data-f=title]", card).textContent = l.title;
          $("[data-f=price]", card).textContent = money(l.price_cents, l.currency);
          $("[data-f=meta]", card).textContent = "@" + l.seller + " · " + l.category;
          const img = $("img", card);
          if (l.images && l.images.length) img.src = "/media/" + l.id + "/0"; else img.remove();
          out.appendChild(card);
        }
      },
      get inactive() { return !this.active; },
    }));

    /* Conversation: Double Ratchet over WebSocket, REST fallback, local decrypted cache. */
    Alpine.data("chat", () => ({
      status: "", e2e: false, e2eDisabled: false, locked: false, ws: null, lastId: 0,
      ident: null, store: null, pending: {}, chain: Promise.resolve(), pollTimer: null,
      async init() {
        await D1.ready;
        const cfg = this.$el.dataset;
        this.convId = cfg.convId;
        this.isAlice = cfg.isAlice === "1";
        this.otherPk = cfg.otherPk;
        this.lastId = Number(cfg.lastId || 0);
        this.e2e = cfg.e2e === "1";
        this.e2eDisabled = cfg.e2eDisabled === "1";
        if (!this.e2e) { this.status = "Not end-to-end encrypted: " + (cfg.reason || "keys missing"); this.connect(); return; }
        this.ident = D1.loadIdentity();
        if (!this.ident || !D1.matchesAccount(this.ident)) { this.locked = true; this.status = "Unlock your keys to read and send encrypted messages."; this.connect(); return; }
        this.start();
      },
      async unlock() {
        this.ident = await requireIdentity();
        if (this.ident) { this.locked = false; this.start(); }
      },
      start() {
        const key = "dr." + this.convId;
        this.store = D1.localGet(this.ident, key) || {
          state: D1Ratchet.init({ convId: this.convId, isAlice: this.isAlice,
            myExchangeSk: this.ident.exchangeSk, myExchangePk: this.ident.exchangePk,
            theirExchangePk: D1.b64d(this.otherPk) }),
          cache: {},
        };
        this.storeKey = key;
        this.status = "🔒 End-to-end encrypted (Double Ratchet). The server only relays ciphertext.";
        document.querySelectorAll("#chat-log [data-mode=ratchet]").forEach((el) =>
          this.enqueue({ id: Number(el.dataset.id), sender_id: el.dataset.sender, header: el.dataset.header, ciphertext: el.dataset.ct, mode: "ratchet" }, el));
        this.connect();
      },
      save() { D1.localSet(this.ident, this.storeKey, this.store); },
      enqueue(msg, el) { this.chain = this.chain.then(() => this.process(msg, el)).catch(() => {}); },
      process(msg, el) {
        if (msg.mode !== "ratchet" || !this.ident) return;
        const body = $(".message-bubble-text", el);
        let text = this.store.cache[msg.id];
        if (text === undefined && msg.sender_id === userData().userId) {
          text = this.pending[msg.header];
          delete this.pending[msg.header];
          if (text === undefined) { body.textContent = "(sent from another device, not readable here)"; return; }
        } else if (text === undefined) {
          try {
            let pt;
            [this.store.state, pt] = D1Ratchet.decrypt(this.store.state, D1.b64d(msg.header), D1.b64d(msg.ciphertext));
            text = D1.dec.decode(pt);
          } catch (e) { body.textContent = "⚠ Could not decrypt this message."; return; }
        }
        this.store.cache[msg.id] = text;
        this.save();
        body.textContent = text;
        el.classList.add("decrypted");
        const ev = el.querySelector("textarea[name=details]");
        if (ev) ev.value = "Reported message (disclosed by me): " + text;
      },
      append(msg) {
        if (msg.id <= this.lastId || $("#msg-" + msg.id)) return;
        this.lastId = msg.id;
        const tpl = $("#bubble-tpl");
        const el = tpl.content.firstElementChild.cloneNode(true);
        el.id = "msg-" + msg.id;
        el.dataset.id = msg.id;
        el.classList.add(msg.sender_id === userData().userId ? "message-bubble-mine" : "message-bubble-theirs");
        $(".message-bubble-text", el).textContent = msg.mode === "server" ? msg.plaintext : "🔒 Encrypted message";
        $(".msg-meta", el).textContent = msg.mode === "server" ? "not end-to-end encrypted" : "end-to-end encrypted";
        const tid = el.querySelector("input[name=target_id]");
        if (tid) tid.value = msg.id;
        if (msg.sender_id === userData().userId) { const r = el.querySelector(".report"); if (r) r.remove(); }
        $("#chat-log").appendChild(el);
        el.scrollIntoView({ block: "end" });
        if (msg.mode === "ratchet") this.enqueue(msg, el);
      },
      connect() {
        const url = (location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/ws/conversations/" + this.convId;
        try { this.ws = new WebSocket(url); } catch (e) { return this.poll(); }
        this.ws.onmessage = (ev) => { const m = JSON.parse(ev.data); if (m.id) this.append(m); };
        this.ws.onclose = () => { this.ws = null; this.poll(); };
      },
      poll() {
        if (this.pollTimer) return;
        this.pollTimer = setInterval(async () => {
          try {
            const { messages } = await D1.api("GET", "/api/conversations/" + this.convId + "/messages?after_id=" + this.lastId);
            messages.forEach((m) => this.append(m));
          } catch (e) { /* offline; try again */ }
        }, 5000);
      },
      async send(ev) {
        if (!this.e2e || this.locked) return; // native POST: server-mode message
        ev.preventDefault();
        const input = this.$refs.input;
        const text = input.value.trim();
        if (!text) return;
        this.chain = this.chain.then(async () => {
          let hb, ct;
          [this.store.state, hb, ct] = D1Ratchet.encrypt(this.store.state, D1.utf8(text));
          this.save();
          const msg = { header: D1.b64e(hb), ciphertext: D1.b64e(ct) };
          this.pending[msg.header] = text;
          if (this.ws && this.ws.readyState === 1) this.ws.send(JSON.stringify(msg));
          else this.append(await D1.api("POST", "/api/conversations/" + this.convId + "/messages", msg));
          input.value = "";
        }).catch((e) => toast(e.message || String(e), "err"));
      },
    }));
  });

  // Expose for debugging in the console.
  self.D1App = { requireIdentity, toast };
})();
