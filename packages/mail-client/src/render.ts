/**
 * Rendering a body for the one sandboxed frame (contracts/mail-client-v1.md
 * "Rendering a body"; spec D3 as amended; domain-model G17, G18).
 *
 * The HTML goes through DOMPurify into a detached document, is tightened
 * further by the hooks and the pass below (no remote content of any kind,
 * links in a new tab, `cid:` images as `data:` URLs, sanitised CSS stamped
 * with the page's nonce), and is serialised into a complete document for
 * `srcdoc`. The result becomes a TrustedHTML through the ONE Trusted Types
 * policy of this package, `proprietor-mail#srcdoc`, whose createHTML accepts
 * nothing but the string renderBody is about to hand it. showInFrame refuses
 * a frame whose sandbox is missing or wider than popups, then assigns it.
 */
import DOMPurify, { type Config } from "dompurify";
import { base64 } from "./bytes";
import { UnsafeFrame, UnsupportedBrowser } from "./errors";
import type { BodyAttachment, MailBody, RenderedBody, TrustedHtml } from "./types";

export const POLICY_NAME = "proprietor-mail#srcdoc";
/** The only sandbox tokens a frame may carry: a link may open in a new tab, nothing else (D3 as amended). */
const ALLOWED_SANDBOX_TOKENS = new Set(["allow-popups", "allow-popups-to-escape-sandbox"]);
/** Raster images only; never SVG (it can carry script and styles). */
const RASTER = new Set(["image/png", "image/jpeg", "image/gif", "image/webp"]);
const DATA_IMAGE = /^data:(image\/(?:png|jpeg|gif|webp));base64,[a-z0-9+/=\s]*$/i;
/** A CSP nonce is base64 (or base64url); anything else cannot be a nonce and must not reach the markup. */
const NONCE = /^[A-Za-z0-9+/=_-]{16,}$/;

const FORBID_TAGS = [
  "script", "noscript", "iframe", "frame", "frameset", "object", "embed", "applet", "portal",
  "form", "input", "button", "select", "textarea", "option", "optgroup", "fieldset", "legend", "datalist", "output", "label", "keygen",
  "link", "meta", "base", "template", "slot", "dialog", "canvas", "map", "area",
  "audio", "video", "source", "track", "picture", "svg", "math",
];
/** Attributes that fetch, navigate, or name things we set ourselves. */
const FORBID_ATTR = [
  "srcset", "sizes", "background", "poster", "ping", "target", "rel", "action", "formaction", "nonce", "usemap", "ismap",
  "loading", "fetchpriority", "referrerpolicy", "crossorigin", "integrity", "autofocus", "contenteditable", "draggable", "tabindex",
  "longdesc", "lowsrc", "dynsrc", "manifest", "codebase", "data", "icon", "cite",
];
/** Attributes whose removal counts as a blocked remote resource. */
const FETCHING_ATTRS = new Set(["src", "srcset", "background", "poster", "lowsrc", "dynsrc"]);

const BASE_CSS =
  "html,body{margin:0;padding:0}" +
  "body{padding:12px;font:15px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;color:#222;background:#fff;overflow-wrap:anywhere}" +
  "img{max-width:100%;height:auto}" +
  "table{max-width:100%}" +
  "pre.plain{white-space:pre-wrap;font:inherit;margin:0}";

interface RenderContext {
  attachments: BodyAttachment[];
  remoteImagesBlocked: number;
  inlineImages: number;
}

// ---- Trusted Types -----------------------------------------------------------

interface PolicyLike {
  createHTML(input: string): TrustedHtml;
  createScriptURL(input: string): unknown;
}
interface TrustedTypesLike {
  createPolicy(name: string, rules: { createHTML: (input: string) => string; createScriptURL: (input: string) => string }): PolicyLike;
}

let policy: PolicyLike | null | undefined;
/**
 * The one string the policy accepts right now, or null: renderBody sets it
 * around each of its two createHTML uses and clears it after. Under
 * enforcement DOMParser.parseFromString is a sink too, so DOMPurify gets the
 * message's HTML through this policy as well: that string only ever reaches
 * DOMPurify's detached parse document, never a live one. The final document
 * is the only TrustedHTML that reaches a live sink, the frame's srcdoc.
 */
let expected: string | null = null;

function policyFor(): PolicyLike | null {
  if (policy !== undefined) return policy;
  const tt = (globalThis as { trustedTypes?: TrustedTypesLike }).trustedTypes;
  if (!tt) {
    policy = null;
    return policy;
  }
  policy = tt.createPolicy(POLICY_NAME, {
    createHTML(input: string): string {
      // DOMPurify also asks for an empty TrustedHTML when it is configured; harmless, and only while renderBody runs.
      if (expected === null || (input !== expected && input !== "")) throw new TypeError(`${POLICY_NAME} accepts only what renderBody hands it, while it runs`);
      return input;
    },
    createScriptURL(): string {
      throw new TypeError(`${POLICY_NAME} creates no script URLs`);
    },
  });
  return policy;
}

/** Runs `use` while the policy accepts exactly `html`, and nothing else before or after. */
function accepting<T>(html: string, use: () => T): T {
  expected = html;
  try {
    return use();
  } finally {
    expected = null;
  }
}

function trust(html: string): TrustedHtml | string {
  const p = policyFor();
  if (p === null) return html;
  return accepting(html, () => p.createHTML(html));
}

// ---- CSS ---------------------------------------------------------------------

function allowedCssUrl(url: string): boolean {
  return DATA_IMAGE.test(url.trim());
}

/**
 * Sanitised CSS: no @import, no url() other than data: raster images, no
 * image-set(), no expression()/behavior/-moz-binding, and never a `<`, so the
 * text cannot close its <style> element. Counts what it removed.
 */
export function scrubCss(css: string, ctx: RenderContext): string {
  let out = css.replace(/\/\*[\s\S]*?\*\//g, "").replace(/<!--|-->/g, "");
  out = out.replace(/@import\b[^;{]*(?:;|(?=[}]))/gi, () => {
    ctx.remoteImagesBlocked += 1;
    return "";
  });
  out = out.replace(/@(?:namespace|charset)\b[^;{]*;?/gi, "");
  out = out.replace(/url\(\s*(['"]?)([\s\S]*?)\1\s*\)/gi, (match, _q: string, target: string) => {
    if (allowedCssUrl(target)) return match;
    ctx.remoteImagesBlocked += 1;
    return "none";
  });
  out = out.replace(/(?:-webkit-)?image-set\([^)]*\)/gi, () => {
    ctx.remoteImagesBlocked += 1;
    return "none";
  });
  out = out.replace(/expression\s*\(/gi, "none(").replace(/-moz-binding\s*:[^;}]*/gi, "").replace(/\bbehavior\s*:[^;}]*/gi, "");
  return out.replace(/</g, "");
}

// ---- DOMPurify ---------------------------------------------------------------

let purifier: ReturnType<typeof DOMPurify> | null = null;
let current: RenderContext | null = null;

function imageSource(value: string, ctx: RenderContext): string | null {
  const v = value.trim();
  if (/^cid:/i.test(v)) {
    const id = v.slice(4).replace(/^<|>$/g, "");
    const attachment = ctx.attachments.find((a) => a.contentId === id && RASTER.has(a.mimeType.toLowerCase()));
    if (!attachment) return null;
    ctx.inlineImages += 1;
    return `data:${attachment.mimeType.toLowerCase()};base64,${base64(attachment.content)}`;
  }
  if (DATA_IMAGE.test(v)) return v;
  ctx.remoteImagesBlocked += 1;
  return null;
}

function purifierFor(): ReturnType<typeof DOMPurify> {
  if (purifier !== null) return purifier;
  const win = (globalThis as { window?: Window & typeof globalThis }).window;
  if (!win || typeof win.document === "undefined") throw new UnsupportedBrowser("renderBody needs a browser document");
  const p = DOMPurify(win);
  if (!p.isSupported) throw new UnsupportedBrowser("this browser cannot sanitise HTML");
  p.addHook("uponSanitizeAttribute", (node, data) => {
    const ctx = current!;
    const name = data.attrName;
    if (FETCHING_ATTRS.has(name)) {
      const tag = node.nodeName.toLowerCase();
      if (name === "src" && tag === "img") {
        const resolved = imageSource(data.attrValue, ctx);
        if (resolved === null) data.keepAttr = false;
        else data.attrValue = resolved;
      } else {
        if (data.attrValue.trim().length > 0) ctx.remoteImagesBlocked += 1;
        data.keepAttr = false;
      }
    } else if (name === "style") {
      const scrubbed = scrubCss(data.attrValue, ctx).replace(/[{}]/g, "");
      if (scrubbed.trim().length === 0) data.keepAttr = false;
      else data.attrValue = scrubbed;
    }
  });
  p.addHook("afterSanitizeAttributes", (node) => {
    if (node.nodeName.toLowerCase() === "a" && node.hasAttribute("href")) {
      node.setAttribute("target", "_blank");
      node.setAttribute("rel", "noopener noreferrer");
    }
  });
  purifier = p;
  return p;
}

function escapeHtml(text: string): string {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

/** Sanitised body markup (inside <html>, as DOMPurify returned it) and the sanitised CSS of its <style> elements. */
function sanitise(html: string, ctx: RenderContext): { markup: string; styles: string[] } {
  const p = purifierFor();
  const tt = policyFor();
  current = ctx;
  let root: Node | null;
  try {
    // DOMPurify parses through DOMParser.parseFromString, a Trusted Types sink: it gets this
    // package's policy (never its own `dompurify` one), which accepts the message's HTML for this
    // call only. The parse document is detached; nothing in it runs.
    root = accepting(html, () =>
      p.sanitize(html, {
        USE_PROFILES: { html: true },
        WHOLE_DOCUMENT: true,
        RETURN_DOM: true,
        FORBID_TAGS,
        FORBID_ATTR,
        ALLOWED_URI_REGEXP: /^(?:https?|mailto):/i,
        ALLOW_DATA_ATTR: false,
        ALLOW_UNKNOWN_PROTOCOLS: false,
        TRUSTED_TYPES_POLICY: tt as unknown as Config["TRUSTED_TYPES_POLICY"],
      }),
    );
  } finally {
    current = null;
  }
  const element = root as Element | null;
  if (!element || typeof element.querySelectorAll !== "function") return { markup: "", styles: [] };
  const styles: string[] = [];
  for (const style of Array.from(element.querySelectorAll("style"))) {
    const css = scrubCss(style.textContent ?? "", ctx);
    if (css.trim().length > 0) styles.push(css);
    style.remove();
  }
  // Inline `style` attributes would be refused by the inherited policy (style-src-attr has no
  // nonce), so each becomes a class rule in the nonce-stamped stylesheet; the hook above already
  // scrubbed their declarations.
  const inline: string[] = [];
  let n = 0;
  for (const el of Array.from(element.querySelectorAll("[style]"))) {
    const css = el.getAttribute("style") ?? "";
    el.removeAttribute("style");
    if (css.trim().length === 0) continue;
    n += 1;
    const name = `pm-inline-${n}`;
    el.setAttribute("class", `${el.getAttribute("class") ?? ""} ${name}`.trim());
    inline.push(`.${name}{${css}}`);
  }
  if (inline.length > 0) styles.push(inline.join("\n"));
  return { markup: element.outerHTML, styles };
}

function styleElement(nonce: string, css: string): string {
  return `<style nonce="${nonce}">${css}</style>`;
}

/** A complete document for srcdoc: our head (charset, base style, the email's styles, all nonce-stamped) and the sanitised markup. */
function assemble(markup: string, styles: string[], nonce: string): string {
  const head = `<meta charset="utf-8">${styleElement(nonce, BASE_CSS)}${styles.map((css) => styleElement(nonce, css)).join("")}`;
  const withHead = /<head(?:\s[^>]*)?>/i.test(markup)
    ? markup.replace(/<head(?:\s[^>]*)?>/i, (m) => `${m}${head}`)
    : `<html><head>${head}</head><body>${markup}</body></html>`;
  return `<!DOCTYPE html>${withHead}`;
}

const live = new WeakSet<RenderedBody>();

class Rendered implements RenderedBody {
  private trusted: TrustedHtml | string | null;
  readonly remoteImagesBlocked: number;
  readonly inlineImages: number;

  constructor(html: TrustedHtml | string, ctx: RenderContext) {
    this.trusted = html;
    this.remoteImagesBlocked = ctx.remoteImagesBlocked;
    this.inlineImages = ctx.inlineImages;
    live.add(this);
  }

  get html(): TrustedHtml | string {
    if (this.trusted === null) throw new TypeError("this rendered body was disposed");
    return this.trusted;
  }

  dispose(): void {
    this.trusted = null;
    live.delete(this);
  }
}

export function renderBody(body: MailBody, options: { nonce: string }): RenderedBody {
  const nonce = options?.nonce;
  if (typeof nonce !== "string" || !NONCE.test(nonce)) {
    throw new TypeError("renderBody needs the page's script nonce (pageNonce()); without it no style would apply");
  }
  const ctx: RenderContext = { attachments: body.attachments ?? [], remoteImagesBlocked: 0, inlineImages: 0 };
  let document: string;
  if (typeof body.html === "string") {
    const { markup, styles } = sanitise(body.html, ctx);
    document = assemble(markup, styles, nonce);
  } else {
    document = assemble(`<html><head></head><body><pre class="plain">${escapeHtml(body.text ?? "")}</pre></body></html>`, [], nonce);
  }
  return new Rendered(trust(document), ctx);
}

function sandboxOf(frame: HTMLIFrameElement): string[] {
  const attr = frame.getAttribute("sandbox");
  if (attr === null) throw new UnsafeFrame("the frame has no sandbox attribute");
  return attr.split(/\s+/).filter((t) => t.length > 0).map((t) => t.toLowerCase());
}

/** Refuses a frame without the allowed sandbox; sets srcdoc through the policy `proprietor-mail#srcdoc`. */
export function showInFrame(frame: HTMLIFrameElement, rendered: RenderedBody): void {
  if (!live.has(rendered)) throw new TypeError("not a live RenderedBody from renderBody");
  if (!frame || typeof frame !== "object" || String(frame.nodeName).toLowerCase() !== "iframe" || typeof frame.getAttribute !== "function") {
    throw new TypeError("showInFrame takes an <iframe>");
  }
  for (const token of sandboxOf(frame)) {
    if (!ALLOWED_SANDBOX_TOKENS.has(token)) throw new UnsafeFrame(`the frame's sandbox grants ${token}`);
  }
  frame.setAttribute("referrerpolicy", "no-referrer");
  // The one DOM sink of this package (contract rule 2): a TrustedHTML from the policy, or the string where Trusted Types do not exist.
  frame.srcdoc = rendered.html as string;
}

/** The page's own script nonce, read at run time from `.nonce`; null when there is none. */
export function pageNonce(doc?: Document): string | null {
  const d = doc ?? (globalThis as { document?: Document }).document;
  if (!d) return null;
  for (const script of Array.from(d.scripts)) {
    const nonce = script.nonce;
    if (typeof nonce === "string" && nonce.length > 0) return nonce;
  }
  return null;
}
