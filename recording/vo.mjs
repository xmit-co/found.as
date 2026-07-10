#!/usr/bin/env node
// Voiceover for the reel: renders each line with OpenAI TTS (gpt-4o-mini-tts,
// instruction-steered for warmth) when OPENAI_API_KEY is set — falling back to
// macOS `say` — mixes the clips at their beat timestamps, and muxes the track
// over recording/reel-live.mp4 into recording/reel-live-vo.mp4.
//
// Runs standalone (`npm run record:vo`) so the voice can be iterated without
// re-recording the video; record-live.mjs invokes it after each encode.
//
// Env: OPENAI_API_KEY, REEL_TTS_VOICE (default coral), REEL_VOICE (say voice).

import { spawnSync } from "node:child_process";
import { rmSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const mp4 = join(HERE, "reel-live.mp4");
const mp4vo = join(HERE, "reel-live-vo.mp4");
const voWav = join(HERE, "reel-vo.wav");
const voAiff = join(HERE, "reel-vo.aiff");

// Lines anchored to named beats from beats.json (written by record-live.mjs
// from the measured session), plus a per-line offset in final-cut ms.
const LINES = [
  ["intro", 200, "No account. No app. No tracking. Just your page."],
  ["address", 200, "Claim your found dot as address."],
  ["name", 100, "Add your name."],
  ["links", 200, "Drop in your links."],
  ["color", 100, "Make it yours."],
  ["font", 100, "Color. Type. Done."],
  ["publish", 0, "Publish."],
  ["qr", 200, "Now you're live."],
  ["endcard", 200, "Make yours. It's free. found as."],
];

// Resolve each beat to final-timeline ms: the intro segment plays first, then
// the build; both are retimed by `speed`.
function resolveLines() {
  const b = JSON.parse(readFileSync(join(HERE, "beats.json"), "utf8"));
  return LINES.map(([beat, off, text]) => {
    if (beat === "intro") return [off, text];
    if (!(beat in b.beats)) return null;
    return [Math.round((b.introMs + b.beats[beat]) * b.speed) + off, text];
  }).filter(Boolean);
}

const TTS_VOICE = process.env.REEL_TTS_VOICE || "coral";
const TTS_INSTRUCTIONS =
  process.env.REEL_TTS_INSTRUCTIONS ||
  "Fast, bright, and warm — a friend excitedly showing you something cool. " +
  "Snappy conversational pace: no drawn-out words, no dramatic pauses, " +
  "no announcer polish. Keep the smile; let only the final line relax.";

async function openaiTrack() {
  const key = process.env.OPENAI_API_KEY;
  if (!key) return false;
  console.log(`Voiceover via OpenAI TTS (${TTS_VOICE})…`);
  const timed = resolveLines();
  const parts = [];
  for (let i = 0; i < timed.length; i++) {
    const [at, text] = timed[i];
    const res = await fetch("https://api.openai.com/v1/audio/speech", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "gpt-4o-mini-tts",
        voice: TTS_VOICE,
        input: text,
        instructions: TTS_INSTRUCTIONS,
        response_format: "wav",
      }),
    });
    if (!res.ok) {
      console.warn(`  (TTS ${res.status}: ${(await res.text()).slice(0, 140)})`);
      return false;
    }
    const f = join(HERE, `reel-vo-${i}.wav`);
    writeFileSync(f, Buffer.from(await res.arrayBuffer()));
    parts.push([at, f]);
  }
  // One track: every clip delayed to its beat, mixed without normalization
  // (the lines never overlap; normalize would duck them).
  const inputs = parts.flatMap(([, f]) => ["-i", f]);
  // TTS clips end with dead air; trim trailing silence (reverse → trim leading
  // → reverse) so beat placement reflects speech, not padding.
  const trim =
    "areverse,silenceremove=start_periods=1:start_duration=0.12:start_threshold=-45dB,areverse";
  const chains = parts
    .map(([at], i) => `[${i}:a]${trim},adelay=${at}:all=1[a${i}]`)
    .join(";");
  const pads = parts.map((_, i) => `[a${i}]`).join("");
  const mx = spawnSync(
    "ffmpeg",
    ["-y", ...inputs, "-filter_complex",
      `${chains};${pads}amix=inputs=${parts.length}:normalize=0[ao]`,
      "-map", "[ao]", voWav],
    { stdio: ["ignore", "ignore", "inherit"] },
  );
  for (const [, f] of parts) rmSync(f, { force: true });
  return mx.status === 0;
}

function sayTrack() {
  const text = LINES.map(([, , t]) => t).join(" [[slnc 1400]] ");
  rmSync(voAiff, { force: true });
  const voice = process.env.REEL_VOICE || "Samantha";
  let sr = spawnSync("say", ["-v", voice, "-r", "180", "-o", voAiff, text]);
  if (sr.status !== 0) sr = spawnSync("say", ["-r", "180", "-o", voAiff, text]);
  if (sr.status !== 0) return false;
  console.log("Voiceover via macOS `say` (fallback).");
  return true;
}

if (!existsSync(mp4)) {
  console.error(`✗ ${mp4} not found — record first (npm run record:live).`);
  process.exit(1);
}
const track = (await openaiTrack()) ? voWav : sayTrack() ? voAiff : null;
if (!track) {
  console.error("✗ no voiceover source (set OPENAI_API_KEY, or install `say`)");
  process.exit(1);
}
const mux = spawnSync(
  "ffmpeg",
  ["-y", "-i", mp4, "-i", track, "-c:v", "copy",
    "-af", "apad", "-c:a", "aac", "-b:a", "160k", "-shortest", mp4vo],
  { stdio: ["ignore", "ignore", "inherit"] },
);
if (mux.status !== 0) {
  console.error("✗ voiceover mux failed");
  process.exit(1);
}
console.log(`✓ ${mp4vo}`);
