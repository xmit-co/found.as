#!/usr/bin/env node
// Records GENUINE footage of the real editor building a page from scratch — as
// a mobile touch session (the editor is designed for mobile). Emulates a phone
// (touch + 9:16), taps with visible ripples, smooth-scrolls to reveal the UI,
// picks a real loaded font, and publishes — then encodes recording/reel-live.mp4.
//
//   nix develop
//   npm run dev                                  # in another shell (note the port)
//   EDITOR_URL=https://localhost:5173/ npm run record:live
//
// It publishes a throwaway page for the QR finale and DELETES it afterward.
// Env: EDITOR_URL, BROWSER, REEL_ADDR, REEL_PW, REEL_FONT.

import puppeteer from "puppeteer-core";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { rmSync, writeFileSync } from "node:fs";
import { encode } from "cbor-x";
import nacl from "tweetnacl";

const HERE = dirname(fileURLToPath(import.meta.url));
const EDITOR_URL = process.env.EDITOR_URL || "https://localhost:5173/";
const BROWSER =
  process.env.BROWSER ||
  "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser";
const ADDR = process.env.REEL_ADDR || "adareel";
const PW = process.env.REEL_PW || "reel-demo-key";
const FONT = process.env.REEL_FONT || "Space Grotesk";

const webm = join(HERE, "reel-live.webm"); // build segment
const introWebm = join(HERE, "reel-intro.webm"); // cold open, recorded last
const mp4 = join(HERE, "reel-live.mp4");
const WANT_VO = process.env.REEL_VO !== "0";
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

// Native 1080×1920 capture: the 540-CSS-px viewport recorded at scale 2, with
// a low VP9 CRF (puppeteer's default of 30 is visibly soft). 60fps so the
// smooth scrolls survive the 0.55× retime without judder.
const CAST = { scale: 2, quality: 10, fps: 60 };

// SPEED (<1 = faster) trims the real-time session to a Reel-length cut while
// keeping the deliberate scrolls followable.
const SPEED = Number(process.env.REEL_SPEED) || 0.44;

// Injected once: a tap ripple, a caption pill (above the sticky Publish bar), a
// smooth window-scroller, a brand end card, and a Publish guard.
function chrome() {
  for (const id of ["__style", "__cap", "__end"]) document.getElementById(id)?.remove();
  const s = document.createElement("style");
  s.id = "__style";
  s.textContent = `
    #__cap{position:fixed;left:50%;bottom:15%;transform:translateX(-50%);max-width:88%;
      z-index:2147483646;text-align:center;font:850 36px/1.15 ui-sans-serif,system-ui,sans-serif;
      color:#fff;letter-spacing:0;background:rgba(12,18,16,.92);padding:16px 24px;
      border:1px solid rgba(115,231,181,.36);border-radius:8px;box-shadow:0 14px 40px rgba(0,0,0,.45);pointer-events:none;
      opacity:0;transition:opacity .28s ease}
    #__cap b{color:#73e7b5}
    #__end{position:fixed;inset:0;z-index:2147483647;background:#f4f2ea;color:#101713;
      display:flex;flex-direction:column;align-items:flex-start;justify-content:center;gap:22px;padding:0 46px;
      opacity:0;pointer-events:none;transition:opacity .45s ease;
      overflow:hidden}
    #__end:after{content:"";position:absolute;top:-120px;right:-100px;width:180px;height:1200px;
      transform:rotate(12deg);background:#ff775c}
    #__end .kicker{font:850 16px/1 ui-sans-serif;color:#078b78;letter-spacing:0}
    #__end .wm{font:870 76px/1 ui-sans-serif,system-ui;letter-spacing:0;color:#078b78}
    #__end .headline{font:870 58px/.98 ui-sans-serif,system-ui;letter-spacing:0;color:#101713}
    #__end .headline b{color:#ff775c}
    #__end .cta{display:flex;width:360px;align-items:center;justify-content:space-between;
      font:800 24px/1 ui-sans-serif;color:#fff;background:#101713;padding:20px 22px;border-radius:8px}
    #__end .cta b{font-size:34px;color:#73e7b5}
    #__end .trust{font:680 17px/1.2 ui-sans-serif;color:#586059}`;
  document.head.appendChild(s);

  const cap = document.createElement("div");
  cap.id = "__cap";
  document.body.appendChild(cap);
  const end = document.createElement("div");
  end.id = "__end";
  end.innerHTML =
    '<div class="kicker">CONTACT PAGE · DIGITAL BUSINESS CARD</div><div class="wm">👋 found.as</div><div class="headline">Just your<br><b>page.</b></div><div class="cta">Make yours — it’s free <b>→</b></div><div class="trust">No account · No app · No tracking</div>';
  document.body.appendChild(end);

  window.__ui = {
    // Native popovers render in the top layer, above any z-index. To stay
    // visible over an open menu, overlays must live inside that popover.
    host() {
      return document.querySelector(":popover-open") ?? document.body;
    },
    // A finger lands and holds (visible even when the tap dismisses a dialog)…
    press(x, y) {
      document.getElementById("__press")?.remove();
      // Keep the caption riding above whatever is topmost right now.
      this.host().appendChild(document.getElementById("__cap"));
      const p = document.createElement("div");
      p.id = "__press";
      p.style.cssText = `position:fixed;left:${x}px;top:${y}px;z-index:2147483645;width:66px;height:66px;border-radius:50%;background:rgba(124,224,140,.5);border:3px solid #7ce08c;box-shadow:0 0 0 6px rgba(124,224,140,.18);pointer-events:none;transform:translate(-50%,-50%) scale(.4);opacity:0;transition:transform .16s ease,opacity .16s ease`;
      this.host().appendChild(p);
      requestAnimationFrame(() => {
        p.style.transform = "translate(-50%,-50%) scale(1)";
        p.style.opacity = "0.9";
      });
    },
    // …then lifts with a ripple as the action fires.
    release(x, y) {
      document.getElementById("__press")?.remove();
      const r = document.createElement("div");
      r.style.cssText = `position:fixed;left:${x}px;top:${y}px;z-index:2147483645;width:66px;height:66px;border-radius:50%;border:3px solid rgba(124,224,140,.95);pointer-events:none;transform:translate(-50%,-50%) scale(.85)`;
      this.host().appendChild(r);
      r.animate(
        [{ opacity: 0.9, transform: "translate(-50%,-50%) scale(.85)" },
         { opacity: 0, transform: "translate(-50%,-50%) scale(1.7)" }],
        { duration: 440, easing: "ease-out" },
      ).onfinish = () => r.remove();
    },
    scrollTo(y, dur = 680) {
      return new Promise((res) => {
        const s0 = window.scrollY, t0 = performance.now();
        const step = (now) => {
          let p = Math.min(1, (now - t0) / dur);
          p = 1 - Math.pow(1 - p, 3);
          window.scrollTo(0, s0 + (y - s0) * p);
          if (p < 1) requestAnimationFrame(step);
          else res();
        };
        requestAnimationFrame(step);
      });
    },
    cap(h) {
      const c = document.getElementById("__cap");
      if (!h) { c.style.opacity = 0; return; }
      // Re-host on every call so captions ride above an open popover too.
      this.host().appendChild(c);
      c.innerHTML = h;
      c.style.opacity = 1;
    },
    endcard() {
      document.getElementById("__cap").style.opacity = 0;
      document.getElementById("__end").style.opacity = 1;
    },
  };

  window.__blockPublish = true;
  document.addEventListener("click", (e) => {
    if (!window.__blockPublish) return;
    const b = e.target.closest && e.target.closest("button");
    if (b && b.textContent.trim().startsWith("Publish")) {
      e.preventDefault();
      e.stopImmediatePropagation();
    }
  }, true);
}

async function deleteDemo(path, pw) {
  const enc = new TextEncoder();
  const material = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: enc.encode(`found.as/${path}`), iterations: 100000 }, material, 256);
  const kp = nacl.sign.keyPair.fromSeed(new Uint8Array(bits));
  const body = encode([9, kp.publicKey, nacl.sign(encode([Date.now() / 1000, path]), kp.secretKey)]);
  const r = await fetch("https://be.found.as/api", { method: "POST", headers: { Origin: "https://be.found.as" }, body });
  return r.status;
}

const browser = await puppeteer.launch({
  executablePath: BROWSER,
  headless: "new",
  acceptInsecureCerts: true,
  args: ["--ignore-certificate-errors", "--force-color-profile=srgb", "--hide-scrollbars", "--no-sandbox"],
  defaultViewport: { width: 540, height: 960, deviceScaleFactor: 2, isMobile: true, hasTouch: true },
});
const UA =
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";
const page = await browser.newPage();
await page.setUserAgent(UA);

// Re-inject the overlay if a reload wiped it (Vite can full-reload on connect).
async function ensureUi() {
  if (!(await page.evaluate(() => !!window.__ui))) await page.evaluate(chrome);
}
async function cap(h) {
  await ensureUi();
  await page.evaluate((h) => window.__ui.cap(h), h);
}
async function scroll(y) {
  await ensureUi();
  await page.evaluate((y) => window.__ui.scrollTo(y), y);
}
const scrollTop = () => scroll(0);
async function scrollBottom() {
  await ensureUi();
  await page.evaluate(() => window.__ui.scrollTo(document.body.scrollHeight));
}

// Smooth-scroll a target to the vertical centre (clear of the sticky Publish
// bar), ripple, then tap it as a real touch.
async function tap(elOrSel) {
  await ensureUi();
  const el = typeof elOrSel === "string" ? await page.$(elOrSel) : elOrSel;
  if (!el) throw new Error(`missing: ${elOrSel}`);
  await el.evaluate((e) => {
    // An open popover is viewport-fixed (top layer): scrolling the document
    // wouldn't move the target, only slide the page behind the pane.
    if (e.closest(":popover-open")) return;
    const r = e.getBoundingClientRect();
    const y = window.scrollY + r.top + r.height / 2 - window.innerHeight / 2;
    return window.__ui.scrollTo(Math.max(0, y));
  });
  await wait(140);
  const b = await el.boundingBox();
  if (!b) throw new Error("no box");
  const x = b.x + b.width / 2, y = b.y + b.height / 2;
  // A real touch: finger down (visible press), a beat of hold, then lift —
  // the action fires on touchend, in sync with what the viewer sees.
  await page.evaluate((x, y) => window.__ui.press(x, y), x, y);
  await page.touchscreen.touchStart(x, y);
  await wait(380);
  await page.touchscreen.touchEnd();
  await page.evaluate((x, y) => window.__ui.release(x, y), x, y);
}
async function typeInto(sel, text, delay = 55) {
  await tap(sel);
  await page.type(sel, text, { delay });
}
async function tapText(sel, text) {
  const h = await page.evaluateHandle(
    (sel, text) => [...document.querySelectorAll(sel)].find((e) => e.textContent.trim().includes(text)),
    sel, text);
  const el = h.asElement();
  if (!el) throw new Error(`no ${sel} :"${text}"`);
  await tap(el);
}
async function addLink(label, placeholder, value) {
  try {
    await tap(".add-open");
    await wait(550);
    await tapText(".add-link-item", label);
    await wait(700);
    await typeInto(`input[placeholder="${placeholder}"]`, value, 42);
    await wait(500);
  } catch (e) {
    console.warn(`  (skipped ${label}: ${e.message})`);
  }
}

console.log("Loading editor…");
await page.goto(EDITOR_URL, { waitUntil: "networkidle2" });
await page.waitForSelector('input[aria-label="Page path"]');
await page.evaluate(chrome);
await wait(700); // let any Vite full-reload settle, then re-inject if needed
await ensureUi();
await page.evaluate(async () => { await document.fonts.ready; });

const recorder = await page.screencast({ path: webm, ...CAST });
await wait(500);

// Beat clock: wall time since the build cast started, written to beats.json so
// vo.mjs can place voiceover lines on the real cut instead of guessed offsets.
const t0 = Date.now();
const beats = {};
const mark = (n) => (beats[n] = Date.now() - t0);

// 1 — address + password
mark("address");
await cap("Claim found.as/<b>you</b>.");
await typeInto('input[aria-label="Page path"]', ADDR, 95);
await wait(300);
await typeInto('input[type="password"]', PW, 45);
await wait(1500);
await tapText("button", "Create page");
await page.waitForSelector(".live-name", { timeout: 15000 });
await wait(700);

// 2 — name + bio
mark("name");
await cap("Add your <b>name.</b>");
await typeInto(".live-name", "Ada Lovelace", 70);
await wait(400);
await typeInto(".live-bio", "Mathematician · first programmer", 32);
await wait(700);

// 3 — links → buttons (each tap scrolls down to the add area)
mark("links");
await cap("Drop in your <b>links.</b>");
await addLink("Instagram", "@found", "@ada");
await addLink("Email", "hello@example.com", "ada@ada.dev");
await wait(400);

// scroll back up to admire the built profile
await scrollTop();
mark("admire");
await cap("One page. <b>Already.</b>");
await wait(900);

// 4 — colour
mark("color");
await cap("Make it <b>yours.</b>");
try {
  await tapText(".design-nav button", "Colors");
  await wait(700);
  const swatches = await page.$$(".accent-choice");
  // Ada's favourite colour — the blue swatch (order: teal, blue, purple, …).
  if (swatches[1]) await tap(swatches[1]);
  await wait(1200);
} catch (e) { console.warn(`  (colour skipped: ${e.message})`); }

// 5 — a real loaded font
mark("font");
await cap("Colour. Type. <b>Done.</b>");
try {
  await tapText(".design-nav button", "Style");
  await wait(700);
  await typeInto(".font-name", FONT, 60);
  await wait(2400); // fetch from cc.me + re-render the preview
} catch (e) { console.warn(`  (font skipped: ${e.message})`); }

// 6 — publish → the live page + QR
mark("publish");
await cap("Publish. <b>You're live.</b>");
await wait(300);
await page.evaluate(() => { window.__blockPublish = false; });
let published = false;
try {
  await scrollBottom();
  await wait(300);
  await tapText("button", "Publish");
  await page.waitForSelector(".publish-success", { timeout: 15000 });
  published = true;
  mark("qr");
  await wait(2600);
} catch (e) { console.warn(`  (publish: ${e.message})`); }

// 7 — tap Open and visit the real published page
if (published) {
  try {
    // Keep the recorded tab on the journey: navigate here, not a new tab.
    await page.evaluate(() =>
      document
        .querySelector(".publish-success a.button-link")
        ?.removeAttribute("target"),
    );
    const a = await page.$(".publish-success a.button-link");
    const b = await a.boundingBox();
    const x = b.x + b.width / 2, y = b.y + b.height / 2;
    await page.evaluate((x, y) => window.__ui.press(x, y), x, y);
    await page.touchscreen.touchStart(x, y);
    await wait(380);
    await page.touchscreen.touchEnd();
    // Navigation destroys the page context — skip the release ripple and
    // re-inject the overlay on the live page.
    await page
      .waitForNavigation({ waitUntil: "networkidle2", timeout: 20000 })
      .catch(() => {});
    await ensureUi();
    mark("open");
    await cap("No account. No app.<br><b>Just your page.</b>");
    await wait(2200);
  } catch (e) { console.warn(`  (open step: ${e.message})`); }
}

// 8 — brand end card
await ensureUi();
mark("endcard");
await page.evaluate(() => window.__ui.endcard());
await wait(3200);

await recorder.stop();

// Cold open, recorded LAST but cut in FIRST: the finished page, live, under
// "Let's build this." — the payoff up front, then the build pays it off again.
// A fresh tab, with the screencast started only once the page is ready, so no
// leftover frames or navigation flash leak into the cut.
let haveIntro = false;
let introMs = 0;
if (published) {
  try {
    console.log("Recording intro…");
    const ip = await browser.newPage();
    await ip.setUserAgent(UA);
    await ip.goto(`https://found.as/${encodeURIComponent(ADDR)}`, {
      waitUntil: "networkidle2",
    });
    await ip.evaluate(chrome);
    await ip.evaluate(async () => { await document.fonts.ready; });
    await ip.bringToFront();
    // On a static page the caption fade is compositor-only and yields no new
    // screencast frames (the encoder repeats the pre-caption frame). A
    // near-invisible 3px heartbeat dirties paint every frame so the cast rolls.
    await ip.evaluate(() => {
      const b = document.createElement("div");
      b.style.cssText =
        "position:fixed;left:0;top:0;width:3px;height:3px;pointer-events:none;z-index:2147483647";
      document.body.appendChild(b);
      let i = 0;
      (function tick() {
        b.style.backgroundColor = i++ % 2 ? "rgba(13,15,14,.02)" : "rgba(13,15,14,.05)";
        requestAnimationFrame(tick);
      })();
    });
    const introRec = await ip.screencast({ path: introWebm, ...CAST });
    const introStart = Date.now();
    await wait(500);
    await ip.evaluate(
      (h) => window.__ui.cap(h),
      "No account. No app.<br><b>Just your page.</b>",
    );
    await wait(2400);
    introMs = Date.now() - introStart;
    await introRec.stop();
    await ip.close();
    haveIntro = true;
  } catch (e) { console.warn(`  (intro skipped: ${e.message})`); }
}
await browser.close();

// The measured cut: vo.mjs places voiceover lines on these beats (all ms of
// real session time; final-timeline time = (introMs + beat) * speed).
writeFileSync(
  join(HERE, "beats.json"),
  JSON.stringify({ speed: SPEED, introMs, beats }, null, 2),
);

if (published) {
  try {
    const st = await deleteDemo(ADDR, PW);
    console.log(`Cleaned up demo page /${ADDR} (delete ${st}).`);
  } catch (e) { console.warn(`  (cleanup failed for /${ADDR}: ${e.message} — delete manually)`); }
}

console.log("Encoding…");
rmSync(mp4, { force: true });
const vf = `setpts=${SPEED}*PTS,scale=1080:1920:flags=lanczos,setsar=1`;
const enc = ["-r", "60", "-c:v", "libx264", "-preset", "slow", "-crf", "17",
  "-profile:v", "high", "-pix_fmt", "yuv420p", "-movflags", "+faststart"];
const ff = spawnSync("ffmpeg",
  haveIntro
    ? ["-y", "-i", introWebm, "-i", webm,
        "-filter_complex", `[0:v]${vf}[v0];[1:v]${vf}[v1];[v0][v1]concat=n=2:v=1:a=0[v]`,
        "-map", "[v]", ...enc, mp4]
    : ["-y", "-i", webm, "-vf", vf, ...enc, mp4],
  { stdio: ["ignore", "ignore", "inherit"] });
if (ff.status !== 0) { console.error("✗ ffmpeg failed"); process.exit(1); }
console.log(`✓ ${mp4}`);

// Voiceover: vo.mjs renders beat-timed lines (OpenAI TTS when OPENAI_API_KEY
// is set, macOS `say` otherwise) and muxes reel-live-vo.mp4. Also runnable
// standalone (npm run record:vo) to iterate on the voice without re-recording.
if (WANT_VO) {
  const vo = spawnSync(process.execPath, [join(HERE, "vo.mjs")], {
    stdio: ["ignore", "inherit", "inherit"],
  });
  if (vo.status !== 0) console.warn("  (voiceover step failed — see above)");
}
