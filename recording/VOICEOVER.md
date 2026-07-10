# Reel voiceover & framing

Timed from `beats.json` for the real-editor proof cut (default
`REEL_SPEED=0.44`). Captions carry the story sound-off; the VO adds pace without
narrating every field.

## Direction

- **Voice:** warm, bright, and conversational — someone showing a friend, not an
  announcer. Keep each sentence short and clean.
- **Music:** ~112–120 bpm, minimal percussion, building. One hit on **Publish**,
  then let it thin out under the last two lines. Prefer Instagram
  in-app audio for reach; duck it −12 dB under VO.
- **Mix:** VO leads, music under, no SFX needed — the tap ripples do that work
  visually.
- Leave small pockets of air; `vo.mjs` anchors each clip to the measured beat.

## Script (≈40 words)

| Beat    | On screen            | VO                                                 |
| ------- | -------------------- | -------------------------------------------------- |
| Intro   | finished page        | “No account. No app. No tracking. Just your page.” |
| Address | address typing       | “Claim your found dot as address.”                 |
| Name    | name and bio         | “Add your name.”                                   |
| Links   | links become buttons | “Drop in your links.”                              |
| Colour  | accent changes       | “Make it yours.”                                   |
| Type    | font changes         | “Colour. Type. Done.”                              |
| Publish | publish tap          | “Publish.”                                         |
| QR      | success and QR       | “Now you’re live.”                                 |
| End     | campaign CTA         | “Make yours. It’s free. found as.”                 |

Leave the final line dry — music nearly out, no reverb tail.

The polished `reel-vo.mp4` uses six scene-level reads focused on privacy,
simplicity, and the free offer. EU hosting and renewable energy remain visible
as supporting proof rather than spoken headline claims. `vo-polished.mjs`
preserves quiet word tails, adds a short pocket of air after each phrase, and
places each read at an explicit scene timestamp. `reel.mp4` remains the silent
master.

## Sound-off note

Do not soften the burned-in captions to make room for VO — most viewers never
hear it. The VO mirrors the captions on purpose; they must each stand alone.
