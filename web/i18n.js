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
    footer_by: "VT Security · «.env no es seguridad»",

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
    fact1_title: "Se cifra en tu navegador",
    fact1_text: "AES-256-GCM con WebCrypto. Al servidor solo llega texto cifrado.",
    fact2_title: "La clave viaja en el link",
    fact3_title: "Se lee una sola vez",
    fact3_text: "Al abrirlo se borra en el mismo paso. Si nadie lo abre, vence solo.",
    cli_title: "Desde la terminal",
    cli_lede: "El mismo cifrado sin abrir el navegador, para scripts y agentes. ",
    cli_docs: "Ver los comandos",

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
    footer_by: "VT Security · “.env is not security”",

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
    fact1_title: "Encrypted in your browser",
    fact1_text: "AES-256-GCM with WebCrypto. The server only receives ciphertext.",
    fact2_title: "The key travels in the link",
    fact3_title: "Read once",
    fact3_text: "Opening it deletes it in the same step. Unopened, it expires on its own.",
    cli_title: "From the terminal",
    cli_lede: "The same encryption without a browser, for scripts and agents. ",
    cli_docs: "See the commands",

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
    fact2_text: ["Va después del ", ["span", "#"], ", la parte que el navegador nunca envía."],
  },
  en: {
    fact2_text: ["It sits after the ", ["span", "#"], ", the part browsers never send."],
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
