# Gatekeeper: Idea

Sources: *Gatekeeper: Knowledge Transfer* (Oct 3), the Devpost draft, and the judge-style review. The milestones and timeline are in *Gatekeeper: Plan and Milestones to Final Product*, which isn't in the repo.

## One-line pitch
The only screen your AI can't lie to: a hardware wallet for AI agent actions. The agent can only ask, and nothing consequential happens until an ESP32 shows the real action on its own screen and signs it.

## Problem
Agents that read untrusted content (email, invoices) can be steered by instructions hidden in it. Today's confirmations appear on the same screen the software controls, so a hijacked agent can describe a dangerous action as harmless and the human approves something they never saw. Detection alone can't win, because many malicious requests look identical to legitimate ones.

## Target user
Teams that let agents take **high-stakes actions**: payments, data exports, admin changes. Not routine email. Business email compromise and invoice fraud are the headline threats.
TODO: name a concrete persona for the pitch (e.g. a small-business finance lead).

## Core features (MVP)
Build priority (per the review): **1** core sign-and-verify plus the trusted display, **2** invoice fraud demo, **3** separate verifier, **4** voice and RFID last.
- **Agent can only ask:** the LLM produces tool calls (`read_inbox`, `send_email`, `delete_file`, `run_code`, plus `pay_invoice` in M6) and holds no credentials.
- **Executor obeys the device:** it holds the credentials and acts only on `allow`/`approved` with a valid Ed25519 signature, a fresh nonce, an unexpired `exp`, and an unchanged file hash.
- **Device policy:** contacts, `/data/sensitive/`, more than 5 deletes in 10 minutes, unknown action is blocked. In v2, a payee list and amounts.
- **Trusted display:** the OLED shows the action, `TAINTED`, the registrable domain (`boss@company.com.evil.io` shows as `evil.io`), the full address, the file, and the AI's claim.
- **Lie check:** a `low` claim with any verdict other than `allow` sets LOCKED. Holding Reset for 3 s clears it.
- **Taint:** reading mail from outside `ourcompany.com` tightens every rule for the rest of the session.
- **Physical approval:** hold for 2 s to approve, auto-deny after 30 s, Kill sets FROZEN. An RFID co-sign covers large payments.
- **Sandbox:** `run_code` runs in Docker with `--network none`.
- **Extras:** buzzer, ElevenLabs spoken alerts that read the true action (M7), Nessie payments (M6).

## Out of scope
- Defending against a fully compromised laptop. In the prototype the executor verifies signatures on the same machine. In production, the bank or mail gateway verifies them.
- Real email or money (Mailpit and the Nessie sandbox only) and real sensitive data (fake PDFs)
- A secure element for the key (it's in ESP32 flash for now), per-organization policy management
- Approving every routine action

## Demo flow
The laptop shows the agent's large-text narration (the "lying screen"), and the device shows the truth.
1. **Data theft:** an injected email gets the agent to send `tax_return.pdf` to `records@compliance-archive.io` with a `low` claim. The device shows the real recipient, then BLOCKED or LOCKED.
2. **Invoice fraud:** a lookalike vendor asks for payment to a "new" account. The device blocks it, and the Nessie balances prove no money moved.
3. **Legitimate payment:** a real vendor is paid with a button hold plus an RFID co-sign.
4. **Bypass attempts:** the agent tries to exfiltrate through `run_code` (no network), and a request is tampered with after approval (signature fails).
- Backup: `GATEKEEPER_COMPROMISED=1` always attempts exfiltration, so the demo is deterministic.
- Before each judge, run the benign scenario as a smoke test.

## Open questions
From the KT doc (tick these off as they land):
- [ ] Prior-work rule confirmed with organizers
- [x] Fetch.ai ASI:One: **no-go** (see DECISIONS 2026-10-03 11:14)
- [ ] Can we enter both Hardware and FinTech? Ask organizers at check-in
- [x] Co-sign threshold: more than $500 (docs/CONTRACT.md)
- [ ] LLM provider chosen and API key tested with credits
- [ ] Enrolled RFID card UID copied into the firmware
- [x] Acme's Nessie account id added to the mock's payee list (firmware at F4)

Judge risks from the review (each needs an answer or a fix):
- [x] **"What does the hardware add if the executor is on the same laptop?"** Answered by M9 (`verifier.py` + `forge.py`, DECISIONS 2026-10-03 15:30). Proposed fix: a separate bank or mail-gateway process that verifies the signature itself, plus a demo where a forged laptop request is rejected.
- [ ] **Taint vs. "approvals stay rare":** what is the scope: per session, per action type, or per data source?
- [ ] **Lie-check false positives:** lock on every mismatch, or approve-and-flag for small ones and lock only on severe ones?
- [ ] **OLED limits for long values** (IBANs, paths): registrable domain plus the last 4 digits of an account?
- [ ] **The human still judges intent:** add a "new recipient" warning on the device?
- [ ] **Originality:** have a crisp answer for how this differs from existing human-in-the-loop approval tools.
