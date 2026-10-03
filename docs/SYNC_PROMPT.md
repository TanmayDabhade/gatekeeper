# Sync prompt

Paste the block below at the end of any Claude brainstorm, then copy the output into the matching files in `docs/`.

---

```
Before we finish, turn this conversation into updates for our shared docs. Use only what we actually decided here. Don't invent anything, and leave out anything we didn't settle.

Output exactly three sections:

### (a) DECISIONS.md: new entries
One entry per decision, appended in this exact format:

## YYYY-MM-DD HH:MM | <author> | <short title>
**Decision:** ...
**Why:** ...
**Alternatives considered:** ...

Use the current date and time. Ask me for <author> if you don't know it. If a decision reverses an earlier logged one, say so in **Why:**.

### (b) IDEA.md: updates
For each change, give the section name (One-line pitch, Problem, Target user, Core features (MVP), Out of scope, Demo flow, Open questions) and the replacement text. Say which TODO placeholders this resolves and which open questions were answered or added.

### (c) TODO.md: new items
Checkbox items grouped under Tanmay, Teammate, Unassigned or Blocked. For Blocked items, say what they're blocked on.

If a section has nothing, write "None".
```
