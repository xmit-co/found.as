# found.as — Instagram reel

Two 9:16 cuts, both exported as 1080×1920 H.264.

## `npm run record` — polished 18s ad (recommended)

The primary Instagram cut is a self-contained animation. It opens on the
finished product and the landing-page promise, then moves through five beats:
privacy → no account → links → sharing → no cookie banner, followed by a
direct end-card CTA. EU hosting and renewable energy appear as supporting proof.

```sh
nix develop
npm run record        # → recording/reel.mp4
```

`reel.html` contains the stage, `reel.css` the art direction, and `reel.js` the
deterministic timeline (`window.__renderAt(ms)`). `record.mjs` plays that
timeline into a continuous Chromium screencast and exports a 30fps, CRF 17,
BT.709 master. It needs no backend and never publishes a page.

The important copy and product UI remain inside the Reels safe area. The silent
master is meant for an Instagram music track; every beat also works sound-off.
`recording/reel-vo.mp4` adds the beat-locked AI voiceover while preserving
`recording/reel.mp4` as the silent master.

## `npm run record:live` — real editor proof cut

Drives the **actual editor** (dev server) as a mobile touch session — visible
press-and-hold taps, smooth scrolling, burned-in captions — and encodes:

- `recording/reel-live.mp4` — the silent master (1080×1920, 60fps, CRF 17)
- `recording/reel-live-vo.mp4` — same cut with a draft macOS `say` voiceover

```sh
nix develop
npm run dev                        # in another shell (note the https://localhost:PORT)
EDITOR_URL=https://localhost:5173/ npm run record:live
```

This longer alternate proves the same promise in the real product: finished
page → address → name → links → colour/type → publish/QR → live page → CTA. The
intro is recorded last and concatenated first.

- **It publishes a demo page and deletes it afterward.** The finale needs a real
  publish; the script removes `found.as/<REEL_ADDR>` when done. If a run dies
  mid-way, delete the page from the editor (or it 404s harmlessly).
- Publish is guarded during the build so a stray tap can't fire it early.
- Env: `EDITOR_URL`, `BROWSER`, `REEL_ADDR` (default `adareel`), `REEL_PW`,
  `REEL_FONT` (default `Space Grotesk`), `REEL_SPEED` (retime factor, 0.44),
  `REEL_VO=0` to skip the voiceover, `REEL_VOICE` (default `Samantha`).
- Captured natively at 1080×1920 (540-CSS-px mobile viewport at scale 2). The
  `say` VO uses `[[slnc n]]` pauses to track the beats — a draft; re-record a
  human read (see `VOICEOVER.md`) for the final.

## Feed crops (either output)

```sh
ffmpeg -i reel.mp4 -vf "crop=1080:1080:0:420" out-1x1.mp4   # square
ffmpeg -i reel.mp4 -vf "crop=1080:1350:0:285" out-4x5.mp4   # portrait feed
```

## Notes for the edit

- Add music in Instagram; the publish/QR reveal is the natural beat hit.
- Regenerate the polished AI read with `npm run record:vo:polished`. It uses
  OpenAI TTS when `OPENAI_API_KEY` is set, or local MLX Audio when
  `REEL_MLX_PYTHON` points to that environment's Python executable.
- The real-editor cut can add its beat-timed VO with `npm run record:vo`.
- Keep any added Instagram stickers out of the central product area.
