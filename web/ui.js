// Shared by both pages: element lookup, the page state, expiry text and the
// feedback of the copy buttons.
const $ = (s) => document.querySelector(s);

// A page is always in one named state, kept in data-state on <main>. Elements
// list the states they belong to in data-show; the headline and the paragraph
// under it read "<state>_title" and "<state>_lede" from the dictionary.
function setState(state) {
  currentError = null; // an error belongs to the state it happened in
  $("#app").dataset.state = state;
  document.querySelectorAll("[data-show]").forEach((el) => {
    el.hidden = !el.dataset.show.split(" ").includes(state);
  });
  $("#title").dataset.i18n = state + "_title";
  $("#lede").dataset.i18n = state + "_lede";
  VT.apply();
}
function getState() { return $("#app").dataset.state; }

// The error under the card, kept as a dictionary key plus its {placeholders}
// so it follows the language switch. setError() with no key clears it.
let currentError = null;
function renderError() {
  let text = "";
  if (currentError) {
    text = VT.t(currentError.key);
    for (const [name, value] of Object.entries(currentError.values)) text = text.replace("{" + name + "}", value);
  }
  $("#err").textContent = text;
  $("#err-row").hidden = !text;
}
function setError(key, values) {
  currentError = key ? { key, values: values || {} } : null;
  renderError();
}
VT.onChange(renderError);

// A button's label lives in a child <span data-i18n>, so swapping the key
// keeps it right when the language changes while it is busy.
function setLabel(button, key) {
  const label = button.querySelector("[data-i18n]");
  label.dataset.i18n = key;
  label.textContent = VT.t(key);
}

// "Vence el <time>…" as nodes, in the UI language. after is an optional
// dictionary key for the text that follows the date. Spanish gets a 24-hour
// clock: some es-* locales default to "03:05 p. m.", which reads badly here.
function expiryNodes(iso, after) {
  const when = document.createElement("time");
  when.dateTime = iso;
  const format = { day: "numeric", month: "short", hour: "numeric", minute: "2-digit" };
  if (VT.lang === "es") format.hourCycle = "h23";
  when.textContent = new Intl.DateTimeFormat(VT.locale, format).format(new Date(iso));
  return after ? [VT.t("expires_pre"), when, VT.t(after)] : [VT.t("expires_pre"), when];
}

// Copies text and says so on the button for a moment: buttons with a label
// change it, icon-only ones swap their icon through the "ok" class.
async function copyWithFeedback(button, text) {
  let ok = true;
  try { await vtCopyText(text); } catch (_) { ok = false; }
  const label = button.querySelector("[data-i18n]");
  if (label) label.textContent = VT.t(ok ? "copied" : "copy_failed");
  button.classList.toggle("ok", ok);
  clearTimeout(button._reset);
  button._reset = setTimeout(() => {
    button.classList.remove("ok");
    if (label) label.textContent = VT.t(label.dataset.i18n);
  }, 1400);
}

document.querySelectorAll("[data-copy]").forEach((button) =>
  button.addEventListener("click", () => copyWithFeedback(button, $(button.dataset.copy).textContent))
);
