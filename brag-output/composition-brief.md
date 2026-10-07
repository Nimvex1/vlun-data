# Hyperframes Composition Brief: VLUN

## Objective
Create a short launch-style brag video for VLUN — smart-contract security reasoning dataset.

## Output
- Composition directory: `brag-output/composition/`
- Rendered video: `brag-output/brag.mp4`
- Format: landscape — 1920x1080
- Duration: 20 seconds

## Source Material
- Project root: C:\Users\jeet\Downloads\vlun-data-main\vlun-data-main
- Primary files read: README.md, pyproject.toml (name vlun-data, description "Provenance-preserving smart-contract security reasoning dataset built from Code4rena audits")
- Product name: VLUN
- Tagline / strongest claim: Every finding traces to a public artefact. Truth over scale — unknown is a counted outcome.
- Key UI or visual moment to recreate: provenance card (SOURCE → DERIVED → EXECUTED) + 7 evidence-type badges + L0–L6 verification ladder with real counts
- Copy that must appear verbatim:
  - Every finding traces to a public artefact.
  - Truth over scale.
  - jsonl/ is the contract: original evidence
  - 7 L6 verified patches
  - 2 L5 reproduced thefts on fork
  - Separate what the audit said — from what was derived — from what was executed.

## Creative Direction
- Tone preset: polished
- Creative direction: quiet premium research-film launch
- Interpretation: Slow reveals, generous letter-spacing, restrained motion. 4 scenes, 4–7s each. Soft crossfades only (0.7s). Confidence through restraint.
- Angle: Treat VLUN like a research instrument launch. Prove "truth over scale" with receipts: pinned citations, evidence types, L-levels, gates that recompute every count.
- Hook: Full-screen "Every finding traces to a public artefact." (first 4s)
- Outro / punchline: VLUN. Truth over scale. "Separate what the audit said — from what was derived — from what was executed."
- Avoid:
  - Generic SaaS language
  - Abstract filler visuals
  - Unrelated visual redesign

## Visual Identity
- Background: #0B0F14 (deep audit black)
- Text: #F2F5F7 (near-white)
- Muted: #B8C2CC
- Accent: #34D399 (emerald — verified)
- Secondary: #F5B544 (amber — caution)
- Display font: system-ui stack (no webfont in repo; system stack to pass font lint)
- Body font: system-ui stack
- Mono: ui-monospace stack for badges, hashes, L-levels
- Visual references from the project: evidence-model table (7 types), PoC quality ladder L0–L6, dataset-at-a-glance counts, gates matrix

## Storyboard
Use the storyboard in `brag-output/brag-plan.md` as the creative contract.

Scene summary:
1. Hook — 4s — eyebrow + "Every finding traces to a public artefact." + mono subline
2. Reveal / evidence model — 5s — "Truth over scale." + provenance card (3 rows arriving one by one) + 7 badges
3. Highlights / verification — 7s — "Proven, not promised." + L0–L6 ladder + 3 stat chips arriving one by one + gates footer
4. Outro — 4s — "VLUN / Truth over scale." + closer line, hold on dark

## Audio
- Audio role: warm bed
- Audio arc: fade in 0.8s, steady through scenes 1–3, fade out under logo in scene 4
- Music: happy-beats-business-moves-vol-12-by-ende-dot-app.mp3
- Music treatment: volume 0.30, fade-in 0.8s, fade-out last 1.5s; no ducking (no voice)
- Music cue guidance: preset assets/music/cues/happy-beats-business-moves-vol-12-by-ende-dot-app.music-cues.md — tempo ~109.96 BPM. Strong cues in window: 8.74s, 10.93s, 13.11s, 17.47s. Beat grid ~0.55s. Locks: badge-row set near 8.74s (±0.15s); stat payoff near 13.11s (±0.15s). Sequential text snaps to every other beat (≥1.0s apart). File copied to brag-output/composition/assets/music/
- Audio-reactive treatment: subtle; hero glow and provenance-card presence breathe with RMS. No waveform/equalizer visuals, no strobing, no text scaling. If extraction helper unavailable, use a gentle deterministic glow and document the skip.
- Audio-coupled moments:
  - Scene 2 provenance card landing — soft drop
  - Scene 3 L6 payoff ("7 L6 verified patches") — one deep bell
  - Scene 4 final logo — soft accent, ring over fade
- SFX selection guidance: sparse, motion-matched, professional restraint. 2–3 cues max. Prefer low HF-risk: impactSoft_medium for reveals, interface/drop_001 for card landing, impactBell_heavy_000 for payoff. See skills/brag/assets/sfx/sfx-analysis.md.
- SFX analysis guidance: skills/brag/assets/sfx/sfx-analysis.md + .json; prefer low/medium HF risk for polished moments.
- Exact SFX choice: Hyperframes should choose filenames, timestamps, density, and volume based on the implemented animation.
- Audio files: copy the chosen music and any Hyperframes-selected SFX into `brag-output/composition/assets/`

## Hyperframes Instructions
Load the composition-building Hyperframes domain skills — `hyperframes-core` (composition contract + `data-*` timing), `hyperframes-animation` (motion), `hyperframes-creative` (design spec, beats, audio-reactive), `hyperframes-keyframes` (seek-safe keyframes), and `hyperframes-cli` (lint/check/render). /brag is its own workflow: do not enter the `hyperframes` entry-point intent interview and do not route into its generic promo / launch-video workflow. Prefer native Hyperframes conventions over anything in `/brag`.

Requirements:
- Show at least one real UI, copy, or visual element from the source project.
- Keep all text readable in the final render.
- Keep the video within 15-25 seconds.
- Include the planned music/SFX layer unless audio was explicitly disabled or documented as intentionally silent.
- Treat `/brag` audio notes as guidance, not a fixed cue sheet. Choose SFX after the visual animation exists.
- Treat music cue metadata as optional timing hints. Hyperframes decides exact animation timing and should ignore cues that hurt readability, scene pacing, or the product story.
- Major reveals may move toward nearby strong cues within about 0.15s. Smaller entrances may align to nearby beat points within about 0.10s. Use only 1-3 strong cue locks in a 15-25s video unless the edit clearly benefits from more.
- Use SFX to support motion and interaction: card sounds for card-like reveals, short announcement cues for major payoffs, key/click sounds for text or user actions, and restraint when the edit is already busy.
- Honor planned music treatment such as fade-outs, ducking, beat-aligned reveals, or letting a final SFX ring over the music, using the best Hyperframes-supported implementation.
- When music is present and the treatment is not `none`, consider Hyperframes audio-reactive workflow: extract audio data and use RMS/frequency bands for subtle, brand-specific motion. Good targets are glow, depth, background warmth, card presence, title emphasis, or other existing visual elements. Avoid waveform/equalizer visuals, musical-note graphics, generic particle systems, strobing, or heavy pulsing.
- Use local assets for audio and any required runtime/media dependencies when possible.
- Run `hyperframes check` before render — it is brag's single gate.
