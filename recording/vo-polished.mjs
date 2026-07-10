#!/usr/bin/env node
// Beat-locked AI voiceover for the polished 18-second reel. Each short cue is
// generated separately, trimmed, fitted to its visual window, and mixed at an
// explicit timestamp before the finished audio is muxed with reel.mp4.

import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const source = join(HERE, "reel.mp4");
const target = join(HERE, "reel-vo.mp4");
const voiceTrack = join(HERE, "reel-vo.wav");
const localDir = join(HERE, ".reel-polished-vo-mlx");

// Scene-level phrases preserve a natural read. Their entrances follow the
// visible actions, with enough room for breaths and complete word tails.
const CUES = [
  {
    at: 100,
    maxMs: 2550,
    speed: 1.1,
    text: "No cookies. No analytics. No ads. Private by default.",
  },
  {
    at: 2780,
    maxMs: 2400,
    speed: 0.95,
    text: "No account. No personal data. Just your page.",
  },
  {
    at: 5720,
    maxMs: 2500,
    speed: 0.95,
    text: "Add your links. Share one simple address.",
  },
  {
    at: 8950,
    maxMs: 2200,
    speed: 0.95,
    text: "One link and one QR code, ready to share.",
  },
  {
    at: 12000,
    maxMs: 2200,
    speed: 0.95,
    text: "No trackers means no cookie banner.",
  },
  {
    at: 15350,
    maxMs: 2450,
    speed: 0.95,
    text: "Make yours. One hundred percent free. Found as.",
  },
];

const trim =
  "silenceremove=start_periods=1:start_duration=0.08:start_threshold=-60dB," +
  "areverse," +
  "silenceremove=start_periods=1:start_duration=0.12:start_threshold=-60dB," +
  "areverse," +
  "apad=pad_dur=0.14";

function command(name, args, options = {}) {
  const result = spawnSync(name, args, {
    stdio: ["ignore", "ignore", "inherit"],
    ...options,
  });
  return result.status === 0;
}

function durationSeconds(file) {
  const result = spawnSync(
    "ffprobe",
    [
      "-v",
      "error",
      "-show_entries",
      "format=duration",
      "-of",
      "default=noprint_wrappers=1:nokey=1",
      file,
    ],
    { encoding: "utf8" },
  );
  return result.status === 0 ? Number.parseFloat(result.stdout) : Number.NaN;
}

function fitClip(raw, index, maxMs) {
  const trimmed = join(HERE, `.reel-polished-vo-${index}-trim.wav`);
  const fitted = join(HERE, `.reel-polished-vo-${index}-fit.wav`);
  rmSync(trimmed, { force: true });
  rmSync(fitted, { force: true });

  if (
    !command("ffmpeg", ["-v", "error", "-y", "-i", raw, "-af", trim, trimmed])
  ) {
    return null;
  }

  const duration = durationSeconds(trimmed);
  if (!Number.isFinite(duration)) return null;
  const tempo = (duration * 1000) / maxMs;
  if (tempo > 1.001) {
    if (
      !command("ffmpeg", [
        "-v",
        "error",
        "-y",
        "-i",
        trimmed,
        "-af",
        `atempo=${tempo.toFixed(5)}`,
        fitted,
      ])
    ) {
      return null;
    }
    rmSync(trimmed, { force: true });
  } else {
    renameSync(trimmed, fitted);
  }
  return fitted;
}

function mixParts(parts) {
  const fitted = parts.map(([at, raw, maxMs], index) => [
    at,
    fitClip(raw, index, maxMs),
  ]);
  if (fitted.some(([, file]) => !file)) return false;

  const inputs = fitted.flatMap(([, file]) => ["-i", file]);
  const delays = fitted
    .map(([at], index) => `[${index}:a]adelay=${at}:all=1[a${index}]`)
    .join(";");
  const pads = fitted.map((_, index) => `[a${index}]`).join("");
  const filter =
    `${delays};${pads}amix=inputs=${fitted.length}:normalize=0,` +
    "loudnorm=I=-16:TP=-1.5:LRA=7[voice]";
  const ok = command("ffmpeg", [
    "-v",
    "error",
    "-y",
    ...inputs,
    "-filter_complex",
    filter,
    "-map",
    "[voice]",
    "-ar",
    "48000",
    "-ac",
    "1",
    "-c:a",
    "pcm_s16le",
    voiceTrack,
  ]);
  for (const [, file] of fitted) rmSync(file, { force: true });
  return ok;
}

async function openaiVoice() {
  const key = process.env.OPENAI_API_KEY;
  if (!key) return false;
  const voice = process.env.REEL_TTS_VOICE || "coral";
  const instructions =
    process.env.REEL_TTS_INSTRUCTIONS ||
    "Warm, bright, and conversational. Fast and precise, like a friend " +
      "showing you something useful. No announcer voice or dramatic pauses.";
  const parts = [];
  console.log(`Polished voiceover via OpenAI TTS (${voice})...`);

  for (let index = 0; index < CUES.length; index++) {
    const cue = CUES[index];
    const response = await fetch("https://api.openai.com/v1/audio/speech", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "gpt-4o-mini-tts",
        voice,
        input: cue.text,
        instructions,
        response_format: "wav",
      }),
    });
    if (!response.ok) {
      console.warn(
        `TTS ${response.status}: ${(await response.text()).slice(0, 160)}`,
      );
      return false;
    }
    const file = join(HERE, `.reel-polished-vo-${index}-raw.wav`);
    writeFileSync(file, Buffer.from(await response.arrayBuffer()));
    parts.push([cue.at, file, cue.maxMs]);
  }

  const ok = mixParts(parts);
  for (const [, file] of parts) rmSync(file, { force: true });
  return ok;
}

function localMlxVoice() {
  const python = process.env.REEL_MLX_PYTHON;
  if (!python || !existsSync(python)) return false;
  const model = process.env.REEL_MLX_MODEL || "mlx-community/Kokoro-82M-8bit";
  const voice = process.env.REEL_MLX_VOICE || "af_heart";
  rmSync(localDir, { force: true, recursive: true });
  mkdirSync(localDir, { recursive: true });
  const parts = [];
  console.log(`Polished voiceover via local MLX (${voice})...`);

  for (let index = 0; index < CUES.length; index++) {
    const cue = CUES[index];
    const prefix = `cue-${index}`;
    if (
      !command(python, [
        "-m",
        "mlx_audio.tts.generate",
        "--model",
        model,
        "--text",
        cue.text,
        "--voice",
        voice,
        "--speed",
        String(cue.speed),
        "--lang_code",
        "a",
        "--output_path",
        localDir,
        "--file_prefix",
        prefix,
      ])
    ) {
      return false;
    }
    const file = join(localDir, `${prefix}_000.wav`);
    if (!existsSync(file)) return false;
    parts.push([cue.at, file, cue.maxMs]);
  }

  const ok = mixParts(parts);
  rmSync(localDir, { force: true, recursive: true });
  return ok;
}

if (!existsSync(source)) {
  console.error(`Missing ${source}; render the polished reel first.`);
  process.exit(1);
}

const haveVoice = (await openaiVoice()) || localMlxVoice();
if (!haveVoice) {
  console.error(
    "No AI voice source. Set OPENAI_API_KEY or REEL_MLX_PYTHON to an " +
      "mlx-audio Python environment.",
  );
  process.exit(1);
}

if (
  !command("ffmpeg", [
    "-v",
    "error",
    "-y",
    "-i",
    source,
    "-i",
    voiceTrack,
    "-map",
    "0:v:0",
    "-map",
    "1:a:0",
    "-c:v",
    "copy",
    "-af",
    "apad",
    "-c:a",
    "aac",
    "-b:a",
    "192k",
    "-ac",
    "2",
    "-shortest",
    "-movflags",
    "+faststart",
    target,
  ])
) {
  console.error("Voiceover mux failed.");
  process.exit(1);
}

console.log(`Voiceover track: ${voiceTrack}`);
console.log(`Finished reel: ${target}`);
