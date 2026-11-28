// Minimal ES/EN i18n. Strings tagged with data-i18n / data-i18n-ph /
// data-i18n-aria / data-i18n-rich are filled in with DOM nodes; dynamic strings
// are read via VT.t(). The language is the one picked in the footer (kept in
// localStorage), else the browser's: Spanish for es-*, English for the rest.
// ?lang=es|en still pins it, as links made before v1.1 carry it.
const _langQP = new URLSearchParams(location.search).get("lang");
function _storedLang() {
  try { const v = localStorage.getItem("vt_lang"); return v === "es" || v === "en" ? v : null; }
  catch (_) { return null; }
}
function _browserLang() {
  const l = typeof navigator !== "undefined" && navigator.language ? navigator.language : "es";
  return l.toLowerCase().startsWith("es") ? "es" : "en";
}
const _initialLang = (_langQP === "es" || _langQP === "en") ? _langQP : (_storedLang() || _browserLang());

const DICT = {
  es: {
    doc_title: "SecretShare · VT Security",
    theme_toggle: "Cambiar entre tema claro y oscuro",
    lang_label: "Idioma",
    footer_by: "VT Security · código abierto, Apache 2.0",

    // create page
    pill_new: "Nuevo:",
    pill_text: "compartí desde la terminal con vtss",
    compose_title: "Compartí un secreto, una sola vez.",
    compose_lede: "Se cifra en tu navegador. El link se abre una vez y después no existe más.",
    label_secret: "Secreto",
    ph_secret: "Pegá una contraseña, un token o una API key",
    ttl_legend: "Vence en",
    ttl_10m: "10 min",
    ttl_1h: "1 hora",
    ttl_1d: "1 día",
    ttl_7d: "7 días",
    btn_create: "Crear link",
    btn_create_busy: "Cifrando…",
    done_title: "Link listo.",
    done_lede: "Mandalo por donde quieras. Lo ve quien lo abra primero, y nadie más.",
    label_link: "Link de un solo uso",
    btn_copy: "Copiar link",
    copied: "Copiado",
    copy_failed: "No se pudo copiar",
    copy_line: "Copiar comando",
    expires_pre: "Vence el ",
    expires_post: " si nadie lo abre antes.",
    btn_new: "Crear otro",
    err_empty: "Pegá o escribí un secreto primero.",
    err_too_large: "El secreto es demasiado grande. El máximo ronda los 190 KB.",
    err_rate: "Demasiados links seguidos. Probá de nuevo en {s} segundos.",
    err_create: "No se pudo crear el link ({m}). Probá de nuevo.",
    err_insecure: "Este sitio necesita HTTPS para poder cifrar en tu navegador.",
    cli_title: "Desde la terminal",
    cli_lede: "El mismo cifrado sin abrir el navegador, para scripts y agentes.",
    cli_docs: "Ver los comandos",
    cli_li3: "Binarios para macOS, Linux y Windows.",
    flow_eyebrow: "cómo funciona",
    flow_title: "El servidor nunca ve el secreto",
    flow1_step: "01 · tu navegador",
    flow1_title: "Se cifra antes de salir",
    flow1_text: "AES-256-GCM con WebCrypto, con una clave nueva para cada secreto.",
    flow1_data: "texto → cifrado",
    flow2_step: "02 · el servidor",
    flow2_title: "Guarda solo el cifrado",
    flow2_text: "Sin la clave no lo puede leer. Si nadie lo abre, lo borra cuando vence.",
    flow2_data: "cifrado · vence en 1 día",
    flow3_step: "03 · el link",
    flow3_title: "La clave va en el link",
    flow4_step: "04 · quien lo abre",
    flow4_title: "Se lee una sola vez",
    flow4_text: "Al mostrarlo se borra. Si alguien lo abrió antes, el link avisa que ya no existe.",
    flow4_data: "abierto → borrado",
    faq_eyebrow: "preguntas",
    faq_title: "Lo que suelen preguntar",
    faq1_q: "¿El servidor puede leer mi secreto?",
    faq1_a: "No. Le llega cifrado, y la clave nunca llega al servidor: va en la parte del link después del #, que los navegadores no mandan.",
    faq2_q: "¿Qué pasa si nadie lo abre?",
    faq2_a: "Se borra solo cuando vence: a los 10 minutos, a la hora, al día o a los 7 días, según lo que elijas.",
    faq3_q: "¿Y si alguien abre el link antes?",
    faq3_a: "Se borra igual. Quien tenía que recibirlo ve que ya no existe, y así sabés que hay que cambiar esa clave.",
    faq4_q: "¿Lo puedo correr en mi servidor?",
    faq4_a: "Sí. Es código abierto, con licencia Apache 2.0: un servidor en Go con Redis que se levanta con Docker Compose.",

    // view page
    ready_title: "Te compartieron un secreto.",
    ready_lede: "Se puede abrir una sola vez. Al mostrarlo se borra del servidor.",
    ready_hint: "Tené a mano dónde guardarlo antes de abrirlo.",
    btn_reveal: "Mostrar secreto",
    btn_reveal_busy: "Descifrando…",
    revealed_title: "Este es el secreto.",
    revealed_lede: "Ya se borró del servidor. Copialo antes de cerrar esta pestaña: el link no vuelve a funcionar.",
    revealed_note: "Descifrado en tu navegador.",
    btn_copy_secret: "Copiar",
    btn_create_own: "Crear un secreto",
    gone_title: "Este secreto ya no existe.",
    gone_lede: "Ya lo abrieron, venció o el link no es el correcto. Pedile a quien te lo mandó que cree uno nuevo.",
    badlink_title: "A este link le falta la clave.",
    badlink_lede: "La clave es lo que va después del # y se cortó al copiarlo. El secreto sigue intacto: pedí el link completo.",
    wrongkey_title: "La clave del link no coincide.",
    wrongkey_lede: "El secreto no se abrió y sigue intacto. Revisá que hayas copiado el link completo.",
    undecryptable_title: "No se pudo descifrar.",
    undecryptable_lede: "El link no traía la clave correcta y el secreto ya se borró del servidor. Pedí uno nuevo.",
    err_retry_later: "Demasiados intentos. El secreto sigue intacto: probá de nuevo en {s} segundos.",
    err_reveal: "No se pudo abrir el secreto ({m}). Probá de nuevo.",
    err_network: "No se pudo conectar con el servidor. Probá de nuevo.",
  },
  en: {
    doc_title: "SecretShare · VT Security",
    theme_toggle: "Switch between light and dark theme",
    lang_label: "Language",
    footer_by: "VT Security · open source, Apache 2.0",

    pill_new: "New:",
    pill_text: "share from the terminal with vtss",
    compose_title: "Share a secret, once.",
    compose_lede: "It is encrypted in your browser. The link opens once and then it is gone.",
    label_secret: "Secret",
    ph_secret: "Paste a password, a token or an API key",
    ttl_legend: "Expires in",
    ttl_10m: "10 min",
    ttl_1h: "1 hour",
    ttl_1d: "1 day",
    ttl_7d: "7 days",
    btn_create: "Create link",
    btn_create_busy: "Encrypting…",
    done_title: "Your link is ready.",
    done_lede: "Send it any way you like. Whoever opens it first sees the secret, and nobody else.",
    label_link: "One-time link",
    btn_copy: "Copy link",
    copied: "Copied",
    copy_failed: "Could not copy",
    copy_line: "Copy command",
    expires_pre: "Expires ",
    expires_post: " if nobody opens it first.",
    btn_new: "Create another",
    err_empty: "Paste or type a secret first.",
    err_too_large: "The secret is too large. The limit is about 190 KB.",
    err_rate: "Too many links in a row. Try again in {s} seconds.",
    err_create: "Could not create the link ({m}). Try again.",
    err_insecure: "This site needs HTTPS to encrypt in your browser.",
    cli_title: "From the terminal",
    cli_lede: "The same encryption without a browser, for scripts and agents.",
    cli_docs: "See the commands",
    cli_li3: "Binaries for macOS, Linux and Windows.",
    flow_eyebrow: "how it works",
    flow_title: "The server never sees the secret",
    flow1_step: "01 · your browser",
    flow1_title: "Encrypted before it leaves",
    flow1_text: "AES-256-GCM with WebCrypto, with a fresh key for every secret.",
    flow1_data: "text → ciphertext",
    flow2_step: "02 · the server",
    flow2_title: "Keeps only the ciphertext",
    flow2_text: "Without the key it cannot read it. If nobody opens it, it is deleted when it expires.",
    flow2_data: "ciphertext · expires in 1 day",
    flow3_step: "03 · the link",
    flow3_title: "The key travels in the link",
    flow4_step: "04 · whoever opens it",
    flow4_title: "Read once",
    flow4_text: "Showing it deletes it. If someone opened it first, the link says it is gone.",
    flow4_data: "opened → deleted",
    faq_eyebrow: "questions",
    faq_title: "What people ask",
    faq1_q: "Can the server read my secret?",
    faq1_a: "No. It only gets ciphertext, and the key never reaches it: it sits in the part of the link after the #, which browsers do not send.",
    faq2_q: "What if nobody opens it?",
    faq2_a: "It is deleted when it expires: after 10 minutes, an hour, a day or 7 days, whichever you pick.",
    faq3_q: "What if someone opens the link first?",
    faq3_a: "It is deleted all the same. The person it was meant for sees it is gone, so you know to change that key.",
    faq4_q: "Can I run it on my own server?",
    faq4_a: "Yes. It is open source under Apache 2.0: a Go server with Redis that starts with Docker Compose.",

    ready_title: "Someone shared a secret with you.",
    ready_lede: "It can be opened only once. Showing it deletes it from the server.",
    ready_hint: "Have somewhere to keep it before you open it.",
    btn_reveal: "Show secret",
    btn_reveal_busy: "Decrypting…",
    revealed_title: "Here is the secret.",
    revealed_lede: "It is already deleted from the server. Copy it before closing this tab: the link will not work again.",
    revealed_note: "Decrypted in your browser.",
    btn_copy_secret: "Copy",
    btn_create_own: "Create a secret",
    gone_title: "This secret no longer exists.",
    gone_lede: "It was already opened, it expired, or the link is not the right one. Ask the sender for a new one.",
    badlink_title: "This link is missing its key.",
    badlink_lede: "The key is the part after the # and it was cut off when the link was copied. The secret is still intact: ask for the full link.",
    wrongkey_title: "The key in this link does not match.",
    wrongkey_lede: "The secret was not opened and is still intact. Check that you copied the whole link.",
    undecryptable_title: "Could not decrypt.",
    undecryptable_lede: "The link did not carry the right key and the secret is already deleted from the server. Ask for a new one.",
    err_retry_later: "Too many attempts. The secret is still intact: try again in {s} seconds.",
    err_reveal: "Could not open the secret ({m}). Try again.",
    err_network: "Could not reach the server. Try again.",
  },
};

// Rich strings (data-i18n-rich) are lists of text and [tag, text] pairs, built
// as DOM nodes so no HTML sink is involved.
const RICH = {
  es: {
    flow3_text: ["Va después del ", ["span", "#"], ", la parte del link que los navegadores no mandan."],
    flow3_data: ["/s/k2Lq…", ["span", "#Xa9f…"]],
    cli_li1: [["span", 'echo "$KEY" | vtss'], " te da el link."],
    cli_li2: [["span", "vtss open '<link>' -o .env"], " lo guarda en un archivo que solo vos podés leer, sin mostrarlo."],
  },
  en: {
    flow3_text: ["It sits after the ", ["span", "#"], ", the part of the link browsers never send."],
    flow3_data: ["/s/k2Lq…", ["span", "#Xa9f…"]],
    cli_li1: [["span", 'echo "$KEY" | vtss'], " gives you the link."],
    cli_li2: [["span", "vtss open '<link>' -o .env"], " writes it to a file only you can read, without showing it."],
  },
};

// Only these elements can come out of RICH, and never with attributes (the
// span gets a fixed class), so even an edited dictionary cannot inject markup.
const RICH_TAGS = new Set(["b", "span", "br"]);
function richNode(part) {
  if (typeof part === "string") return document.createTextNode(part);
  if (!Array.isArray(part) || !RICH_TAGS.has(part[0])) return document.createTextNode(Array.isArray(part) ? String(part[1] ?? "") : "");
  const node = document.createElement(part[0]);
  if (part[0] === "span") node.className = "c";
  if (part[1]) node.textContent = part[1];
  return node;
}

const VT = {
  lang: _initialLang,
  listeners: [],
  t(k) { return (DICT[this.lang] && DICT[this.lang][k]) ?? DICT.es[k] ?? k; },
  // Locale for dates: the UI language, with the browser's region when it matches.
  get locale() {
    const l = typeof navigator !== "undefined" && navigator.language ? navigator.language : "";
    return l.toLowerCase().startsWith(this.lang) ? l : this.lang;
  },
  apply() {
    document.querySelectorAll("[data-i18n]").forEach((el) => { el.textContent = this.t(el.dataset.i18n); });
    document.querySelectorAll("[data-i18n-rich]").forEach((el) => {
      const parts = RICH[this.lang]?.[el.dataset.i18nRich] ?? RICH.es[el.dataset.i18nRich] ?? [];
      el.replaceChildren(...parts.map(richNode));
    });
    document.querySelectorAll("[data-i18n-ph]").forEach((el) => { el.placeholder = this.t(el.dataset.i18nPh); });
    document.querySelectorAll("[data-i18n-aria]").forEach((el) => { el.setAttribute("aria-label", this.t(el.dataset.i18nAria)); });
    document.documentElement.lang = this.lang;
    document.querySelectorAll("[data-lang]").forEach((b) => {
      b.classList.toggle("on", b.dataset.lang === this.lang);
      b.setAttribute("aria-pressed", String(b.dataset.lang === this.lang));
    });
    this.listeners.forEach((fn) => fn(this.lang));
  },
  set(lang) {
    this.lang = lang;
    try { localStorage.setItem("vt_lang", lang); } catch (_) {}
    this.apply();
  },
  onChange(fn) { this.listeners.push(fn); },
};
window.VT = VT;

document.querySelectorAll("[data-lang]").forEach((b) =>
  b.addEventListener("click", () => VT.set(b.dataset.lang))
);
VT.apply();
