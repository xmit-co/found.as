#!/usr/bin/env node
// Records the polished 18-second Instagram ad in recording/reel.html with
// Chromium's continuous screencast, then normalises it with ffmpeg.
//
// Uses the local Brave via puppeteer-core (no Chromium download). Override with
// BROWSER=/path/to/chrome. Tune with FPS=30.

import puppeteer from "puppeteer-core";
import { spawnSync } from "node:child_process";
import { rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const FPS = Number(process.env.FPS) || 30;
const BROWSER =
  process.env.BROWSER ||
  "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser";

const webm = join(HERE, "reel.webm");
rmSync(webm, { force: true });

const browser = await puppeteer.launch({
  executablePath: BROWSER,
  headless: "new",
  args: [
    "--force-color-profile=srgb",
    "--hide-scrollbars",
    "--no-sandbox",
  ],
  defaultViewport: { width: 1080, height: 1920, deviceScaleFactor: 1 },
});
const page = await browser.newPage();
const reelUrl = `file://${join(HERE, "reel.html")}`;
await page.goto(`${reelUrl}?record=1#t=0`, { waitUntil: "load" });
await page.evaluate(async () => {
  await document.fonts.ready;
});

const duration = await page.evaluate(() => window.__duration);
console.log(`Recording ${duration / 1000}s @ ${FPS}fps…`);
const recorder = await page.screencast({
  path: webm,
  fps: FPS,
  quality: 10,
  scale: 1,
});
await page.evaluate(
  (durationMs) =>
    new Promise((resolve) => {
      const started = performance.now();
      function tick(now) {
        const elapsed = Math.min(now - started, durationMs);
        window.__renderAt(elapsed);
        if (elapsed < durationMs) requestAnimationFrame(tick);
        else resolve();
      }
      requestAnimationFrame(tick);
    }),
  duration,
);
await new Promise((resolve) => setTimeout(resolve, 200));
await recorder.stop();
await browser.close();

const out = join(HERE, "reel.mp4");
const ff = spawnSync(
  "ffmpeg",
  [
    "-y",
    "-i", webm,
    "-t", String(duration / 1000),
    "-vf", `fps=${FPS},setpts=PTS-STARTPTS,setparams=color_primaries=bt709:color_trc=bt709:colorspace=bt709`,
    "-c:v", "libx264",
    "-preset", "slow",
    "-crf", "17",
    "-x264-params", "colorprim=bt709:transfer=bt709:colormatrix=bt709",
    "-profile:v", "high",
    "-pix_fmt", "yuv420p",
    "-movflags", "+faststart",
    "-color_primaries", "bt709",
    "-color_trc", "bt709",
    "-colorspace", "bt709",
    "-r", String(FPS),
    out,
  ],
  { stdio: ["ignore", "ignore", "inherit"] },
);
if (ff.status !== 0) {
  console.error("✗ ffmpeg failed");
  process.exit(1);
}
rmSync(webm, { force: true });
console.log(`✓ ${out}`);
