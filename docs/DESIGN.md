# Gatekeeper design system

Used by the demo dashboard (`demo_server.py` serves `demo_ui/`). Tokens are in
`demo_ui/tokens.css`, components in `demo_ui/components.css`. Change a token, not a component,
when you want a different look.

## The idea
The demo is a story about two screens, and the UI draws both:

| | **App** (left) | **Device** (right) |
|---|---|---|
| Who controls it | the AI | nobody but the hardware |
| Feels like | a normal, friendly enterprise assistant | the Gatekeeper box: black enclosure, OLED, LEDs |
| Shape | soft (14 px cards, pill tags, shadows) | machined (3 px corners, hairlines, no shadows) |
| Type | Hanken Grotesk | IBM Plex Mono, VT323 on the OLED |
| Job | show what the AI *says* | show what is *really* happening |

The contrast is the point. The app stays ordinary on purpose ("Acme Corp blue"), so the
moment the OLED says BLOCKED next to a friendly "Paying the Acme Supplies invoice." the
audience sees the lie without anyone explaining it.

## Rules
1. **Verdict colors mean verdicts.** Green, amber and red appear only for what the device
   decided (`--ok`, `--hold`, `--stop`) or for scenario tags that predict it. Never as decoration.
2. **The OLED only shows device truth.** Verdict word, a short reason, the clock. No marketing.
3. **The app never shows the real recipient or amount.** That's the device's job. Narration
   comes from the agent as-is.
4. **Nothing on stage needs typing.** Every scenario is a card and a number key (1 to 5).
5. **No emoji as icons.** Tags and words carry meaning; they read on a projector.
6. **Fonts ship with the repo** (`demo_ui/fonts/`, OFL). Venue Wi-Fi can't break the look.

## Tokens
Colors

| Token | Use |
|---|---|
| `--app-bg`, `--app-surface`, `--app-sunken` | app page, cards, assistant bubbles |
| `--app-ink`, `--app-ink-muted`, `--app-line` | app text, secondary text, borders |
| `--app-brand`, `--app-brand-soft` | the assistant's identity, user bubbles, focus ring |
| `--device-bg`, `--device-panel`, `--device-line` | enclosure, panels, hairlines |
| `--device-ink`, `--device-ink-muted` | device text |
| `--oled-bg`, `--oled-ink`, `--oled-glow` | the OLED only |
| `--ok` / `--hold` / `--stop` | LED colors on the device side |
| `--ok-ink`, `--ok-wash` (same for hold, stop) | the same meaning on the light app side |

Type: `--font-ui`, `--font-mono`, `--font-pixel` (OLED only). Scale: `--text-xs` 12,
`--text-sm` 13, `--text-md` 15, `--text-lg` 17 (chat), `--text-xl` 20, `--text-2xl` 26,
`--text-oled` 64.

Space: 4 px grid, `--s-1` (4) to `--s-14` (56). Shape: `--r-app` 14, `--r-control` 10,
`--r-pill`, `--r-device` 3. Motion: `--t-fast` 140 ms, `--t-med` 240 ms, both 0 under
`prefers-reduced-motion`.

## Components
| Component | Class | Notes |
|---|---|---|
| Shell | `.shell` | app column + fixed 440 px device column; stacks under 980 px |
| App header | `.app-head`, `.app-mark` | the caption says this screen can lie |
| Thread | `.thread`, `.msg.user` / `.assistant` / `.system` | system = Gatekeeper interrupting the AI |
| Bank checks | `.checks`, `.check.ok` / `.no` | forge scenario: PAID or REJECTED + reason |
| Scenario card | `.scenario` + `.tag.attack` / `.legit` / `.live` / `.proof` + `.key` | 3 + 2 grid so no card sits alone |
| LEDs | `.led.ok` / `.hold` / `.stop` + `.on` | one lit at a time |
| OLED | `.bezel > .oled` + `.ok` / `.hold` / `.stop` | 2:1 like the 128x64 panel, faint pixel rows |
| Readout | `.readout` + tone | the device's one-line explanation (the server's `note`) |
| Ledger | `.panel > .ledger > .row` + `.delta.up` / `.down` | lookalike accounts get a red `.flag` |
| Health | `.pill.up` / `.down` | device and bank red when down; voice grey when simply off |

## Verdict to UI
| Verdict | OLED | LED | Readout tone |
|---|---|---|---|
| `allow` | ALLOWED · auto-signed by policy | green | ok |
| `approved` | SIGNED · approved on the device | green | ok |
| `hold` | HOLD · a human must approve | amber | hold |
| `blocked` | BLOCKED · no override | red | stop |
| `locked` | LOCKED · the AI understated the risk | red | stop |
| `denied` | DENIED · no signature issued | red | stop |
| `forge` | VERIFIED · only the real approval paid | green | ok |
| while running | CHECKING + cursor | amber | hold ("hold the button, then tap the card") |
