#include <Arduino.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <ArduinoJson.h>
#include <Preferences.h>
#include "monocypher.h"
#include "monocypher-ed25519.h"
#include <SPI.h>
#include <MFRC522.h>
#include "voice.h"

Adafruit_SSD1306 display(128, 64, &Wire, -1);
Preferences prefs;
String lineBuf;

// ---------- RFID co-sign (F4) ----------
// RC522 clone: SS=5, RST tied to 3.3V (soft reset), SPI 18/19/23. VersionReg reads 0x18.
MFRC522 rfid(5, MFRC522::UNUSED_PIN);
const uint8_t ENROLLED_UID[] = {0x20, 0x11, 0x1B, 0x5C}; // the card that co-signs large payments
const uint8_t ENROLLED_UID_LEN = sizeof(ENROLLED_UID);
int waitForCardTap(unsigned long timeoutMs); // defined below; used by the payment co-sign

// ---------- pins ----------
const int BTN_APPROVE = 13, BTN_KILL = 27, BTN_RESET = 26;
const int LED_R = 25, LED_G = 33, LED_B = 32;

// ---------- policy settings ----------
const unsigned long HOLD_MS = 2000;
const unsigned long APPROVAL_TIMEOUT_MS = 30000;
const unsigned long UNLOCK_HOLD_MS = 3000;
const unsigned long DELETE_WINDOW_MS = 600000UL; // 10 minutes
const int DELETE_LIMIT = 5;

const char *CONTACTS[] = {"boss@ourcompany.com", "accountant@trustedcpa.com"};
const int NUM_CONTACTS = 2;

// F4: pay_invoice payee allowlist (Acme's Nessie account id; must match mock_device.PAYEES)
const char *PAYEES[] = {"7083a93b-e422-4fa6-8188-330034f0c237"};
const char *PAYEE_NAMES[] = {"Acme Supplies"}; // spoken name, same order as PAYEES (M7)
const int NUM_PAYEES = 1;
const uint32_t COSIGN_THRESHOLD_CENTS = 50000;  // payments over $500 need an RFID co-sign (S3)
const uint32_t MAX_AMOUNT_CENTS = 100000000;    // $1,000,000; anything bigger is malformed

// ---------- state ----------
uint8_t secretKey[64];
uint8_t publicKey[32];
bool killActive = false;
bool sessionLocked = false;

const int MAX_DEL = 16;
unsigned long delTimes[MAX_DEL] = {0};
int delIdx = 0;

enum Verdict
{
  V_ALLOW,
  V_APPROVE,
  V_BLOCK
};

// ---------- small helpers ----------
void setLed(bool r, bool g, bool b)
{
  digitalWrite(LED_R, r);
  digitalWrite(LED_G, g);
  digitalWrite(LED_B, b);
}

String toHex(const uint8_t *data, size_t len)
{
  static const char *hex = "0123456789abcdef";
  String s;
  s.reserve(len * 2);
  for (size_t i = 0; i < len; i++)
  {
    s += hex[data[i] >> 4];
    s += hex[data[i] & 0x0F];
  }
  return s;
}

String registrableDomain(const String &addr)
{
  int at = addr.lastIndexOf('@');
  String host = at >= 0 ? addr.substring(at + 1) : addr;
  int last = host.lastIndexOf('.');
  if (last <= 0)
    return host;
  int prev = host.lastIndexOf('.', last - 1);
  return prev >= 0 ? host.substring(prev + 1) : host;
}

String baseName(const String &path)
{
  int slash = path.lastIndexOf('/');
  return slash >= 0 ? path.substring(slash + 1) : path;
}

String lastChars(const String &s, int n)
{
  return (int)s.length() > n ? s.substring(s.length() - n) : s;
}

void waitRelease(int pin)
{
  while (digitalRead(pin) == LOW)
    delay(10);
  delay(30);
}

// ---------- key and signing ----------
void loadOrCreateKey()
{
  uint8_t seed[32];
  prefs.begin("gk", false);
  if (prefs.getBytesLength("seed") == 32)
  {
    prefs.getBytes("seed", seed, 32);
  }
  else
  {
    for (int i = 0; i < 32; i += 4)
    {
      uint32_t r = esp_random();
      memcpy(seed + i, &r, 4);
    }
    prefs.putBytes("seed", seed, 32);
  }
  prefs.end();
  crypto_ed25519_key_pair(secretKey, publicKey, seed);
}

String signMsg(const String &msg)
{
  uint8_t sig[64];
  crypto_ed25519_sign(sig, secretKey, (const uint8_t *)msg.c_str(), msg.length());
  return toHex(sig, 64);
}

// ---------- policy ----------
bool isContact(const String &to)
{
  String t = to;
  t.toLowerCase();
  for (int i = 0; i < NUM_CONTACTS; i++)
  {
    if (t == CONTACTS[i])
      return true;
  }
  return false;
}

bool isPayee(const String &to)
{
  for (int i = 0; i < NUM_PAYEES; i++)
    if (to == PAYEES[i])
      return true;
  return false;
}

bool isSensitive(const String &file)
{
  // Case-insensitive: on macOS data/SENSITIVE/x.pdf opens the same file as data/sensitive/x.pdf
  String f = file;
  f.toLowerCase();
  return f.indexOf("/data/sensitive/") >= 0;
}

int deletesInWindow()
{
  int n = 0;
  unsigned long now = millis();
  for (int i = 0; i < MAX_DEL; i++)
  {
    if (delTimes[i] && now - delTimes[i] < DELETE_WINDOW_MS)
      n++;
  }
  return n;
}

void recordDelete()
{
  delTimes[delIdx] = millis() | 1; // never store 0 (means "empty")
  delIdx = (delIdx + 1) % MAX_DEL;
}

Verdict policy(const String &act, const String &to, const String &file, int taint)
{
  if (act == "send_email")
  {
    bool contact = isContact(to);
    bool sens = isSensitive(file);
    if (!contact && sens)
      return V_BLOCK;
    if (contact && !sens && !taint)
      return V_ALLOW;
    return V_APPROVE;
  }
  if (act == "delete_file")
  {
    // F6/atk-07: a tainted session (read outside mail) can't auto-sign deletes,
    // so an injection can't quietly wipe a public folder. Rate limit stays as
    // defense in depth for untainted sessions.
    if (isSensitive(file) || deletesInWindow() >= DELETE_LIMIT || taint)
      return V_APPROVE;
    return V_ALLOW;
  }
  if (act == "pay_invoice")
  {
    if (!isPayee(to))
      return V_BLOCK;  // unknown payee: fail closed
    return V_APPROVE;  // a listed payee always needs a human (co-sign if > $500, in handleReq)
  }
  return V_BLOCK; // unknown action: fail closed
}

// ---------- screens ----------
void drawIdle()
{
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.setTextSize(2);
  display.setCursor(0, 0);
  display.print("GATEKEEPER");
  display.setTextSize(1);
  display.setCursor(0, 30);
  display.print("Waiting for agent...");
  display.display();
}

void drawRequest(const char *verdict, const String &act, const String &to,
                 const String &file, const String &claim, bool tainted)
{
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.setTextSize(2);
  display.setCursor(0, 0);
  display.print(verdict);

  display.setTextSize(1);
  String a = act;
  a.toUpperCase();
  a.replace("_", " ");
  display.setCursor(0, 18);
  display.print(a);
  if (tainted)
  {
    display.setCursor(128 - 7 * 6, 18);
    display.print("TAINTED");
  }
  if (to.length())
  {
    display.setCursor(0, 28);
    display.print("to: " + registrableDomain(to));
    String full = lastChars(to, 21);
    display.setCursor(128 - full.length() * 6, 38);
    display.print(full);
  }
  if (file.length())
  {
    display.setCursor(0, 48);
    display.print("file: " + lastChars(baseName(file), 15));
  }
  String c = claim;
  c.toUpperCase();
  display.setCursor(0, 56);
  display.print("AI said: " + c + " RISK");
  display.display();
}

void drawResult(const char *big, const char *small)
{
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.setTextSize(2);
  display.setCursor(0, 0);
  display.print(big);
  display.setTextSize(1);
  display.setCursor(0, 30);
  display.print(small);
  display.display();
}

// Thin progress bar at the bottom of the yellow band
void drawHoldBar(int w)
{
  display.fillRect(0, 14, 128, 2, SSD1306_BLACK);
  if (w > 0)
    display.fillRect(0, 14, w, 2, SSD1306_WHITE);
  display.display();
}

void showHome()
{
  if (killActive)
  {
    setLed(false, false, true);
    drawResult("FROZEN", "Press KILL to resume");
  }
  else if (sessionLocked)
  {
    setLed(true, false, false);
    drawResult("LOCKED", "Hold RESET 3s: unlock");
  }
  else
  {
    setLed(false, false, false);
    drawIdle();
  }
}

// ---------- human approval ----------
// Returns 1 = approved (held 2 s), 0 = denied/timeout, -1 = kill pressed
int waitForHold()
{
  unsigned long start = millis();
  unsigned long pressStart = 0;
  int lastW = -1;
  while (millis() - start < APPROVAL_TIMEOUT_MS)
  {
    if (digitalRead(BTN_RESET) == LOW)
    {
      waitRelease(BTN_RESET);
      return 0;
    }
    if (digitalRead(BTN_KILL) == LOW)
    {
      killActive = true;
      waitRelease(BTN_KILL);
      return -1;
    }

    if (digitalRead(BTN_APPROVE) == LOW)
    {
      if (!pressStart)
        pressStart = millis();
      unsigned long held = millis() - pressStart;
      int w = min(128, (int)(held * 128 / HOLD_MS));
      if (w - lastW >= 8 || w == 128)
      {
        drawHoldBar(w);
        lastW = w;
      }
      bool on = ((millis() / (held > HOLD_MS / 2 ? 80 : 160)) % 2) == 0;
      setLed(on, on, false); // yellow blinks faster
      if (held >= HOLD_MS)
      {
        waitRelease(BTN_APPROVE);
        return 1;
      }
    }
    else
    {
      if (pressStart)
      {
        pressStart = 0;
        drawHoldBar(0);
        lastW = -1;
      }
      setLed(true, true, false); // steady yellow: waiting
    }
    delay(10);
  }
  return 0;
}

// ---------- request validation (mirrors validate() in mock_device.py) ----------
// Printable ASCII only: '|' would make the signed string ambiguous, control chars could
// spoof the screen, and non-ASCII could hide a lookalike.
bool cleanField(const String &s)
{
  for (unsigned i = 0; i < s.length(); i++)
  {
    uint8_t c = (uint8_t)s[i];
    if (c < 32 || c >= 0x7F || c == '|')
      return false;
  }
  return true;
}

bool isLowerHex(const String &s, unsigned n)
{
  if (s.length() != n)
    return false;
  for (unsigned i = 0; i < n; i++)
  {
    char c = s[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
      return false;
  }
  return true;
}

// Returns nullptr if the request is well-formed, else the reason.
const char *validateReq(JsonDocument &doc)
{
  const char *strs[] = {"act", "to", "file", "fh", "bh", "claim", "nonce"};
  for (const char *k : strs)
  {
    if (!doc[k].is<const char *>())
      return "missing string field";
    if (!cleanField(doc[k].as<String>()))
      return "forbidden characters";
  }
  const char *ints[] = {"exp", "taint", "bench", "amt"};
  for (const char *k : ints)
  {
    if (!doc[k].is<long long>())
      return "missing integer field";
  }
  String act = doc["act"].as<String>(), to = doc["to"].as<String>();
  String file = doc["file"].as<String>(), fh = doc["fh"].as<String>();
  String claim = doc["claim"].as<String>(), nonce = doc["nonce"].as<String>();
  String bh = doc["bh"].as<String>();
  long long taint = doc["taint"], bench = doc["bench"], exp = doc["exp"], amt = doc["amt"];
  if (claim != "low" && claim != "medium" && claim != "high")
    return "bad claim";
  if ((taint != 0 && taint != 1) || (bench != 0 && bench != 1))
    return "taint/bench must be 0 or 1";
  if (exp < 0 || exp > 0xFFFFFFFFLL)
    return "bad exp";
  if (amt < 0 || amt > 0xFFFFFFFFLL)
    return "bad amt";
  if (!isLowerHex(nonce, 32))
    return "bad nonce";
  if (act == "delete_file")
  {
    if (to.length())
      return "to must be empty for delete_file";
    if (!file.startsWith("/"))
      return "file must be an absolute path";
  }
  else if (act == "send_email")
  {
    if (!to.length())
      return "to is required for send_email";
    if (file.length() && !file.startsWith("/"))
      return "file must be an absolute path";
  }
  else if (act == "pay_invoice")
  {
    if (to.length() < 1 || to.length() > 64)
      return "bad payee id";
    for (unsigned i = 0; i < to.length(); i++)
      if (!isAlphaNumeric(to[i]) && to[i] != '-') // payee id: [A-Za-z0-9-]{1,64}
        return "bad payee id";
    if (file.length() || fh.length())
      return "pay_invoice has no file";
    if (amt <= 0 || amt > MAX_AMOUNT_CENTS)
      return "bad amt";
  }
  if (act != "pay_invoice" && amt != 0)
    return "amt only for pay_invoice";
  if (act == "send_email")
  {
    if (!isLowerHex(bh, 64)) // v2: send_email always carries a 64-hex body hash
      return "bad bh";
  }
  else if (bh.length())
    return "bh only for send_email";
  if (file.indexOf("/../") >= 0 || file.indexOf("/./") >= 0 || file.indexOf("//") >= 0)
    return "file must be a canonical path";
  if (file.length() ? !isLowerHex(fh, 64) : fh.length() != 0)
    return "bad fh";
  return nullptr;
}

// ---------- protocol ----------
// M7: what the device says aloud, from the validated fields only (the same truth as the OLED)
String spokenRequest(const String &act, const String &to, const String &file, uint32_t amt,
                     int taint)
{
  String s = "Gatekeeper. ";
  if (taint == 1)
    s += "After reading outside email, ";
  s += "the agent wants to ";
  if (act == "send_email")
  {
    s += "email ";
    if (file.length())
      s += voiceFile(file) + " ";
    s += "to " + voiceAddress(to) + ".";
  }
  else if (act == "delete_file")
    s += "delete " + voiceFile(file) + ".";
  else if (act == "pay_invoice")
  {
    char dollars[24];
    snprintf(dollars, sizeof(dollars), "$%lu.%02lu", (unsigned long)(amt / 100),
             (unsigned long)(amt % 100));
    String payee = "an unknown account ending in " + voiceDigits(lastChars(to, 4));
    for (int i = 0; i < NUM_PAYEES; i++)
      if (to == PAYEES[i])
        payee = PAYEE_NAMES[i];
    s += "pay " + String(dollars) + " to " + payee + ".";
  }
  else
    s += "do something unknown.";
  return s;
}

void sendRes(const String &nonce, const char *v, const String &sig)
{
  JsonDocument r;
  r["t"] = "res";
  r["nonce"] = nonce;
  r["v"] = v;
  r["sig"] = sig;
  serializeJson(r, Serial);
  Serial.println();
}

void handleReq(JsonDocument &doc)
{
  if (validateReq(doc))
  {
    String n = doc["nonce"].is<const char *>() ? doc["nonce"].as<String>() : String("");
    sendRes(n, "denied", ""); // malformed: refuse, never sign
    return;
  }
  String act = doc["act"] | "";
  String to = doc["to"] | "";
  String file = doc["file"] | "";
  String fh = doc["fh"] | "";
  String claim = doc["claim"] | "";
  String nonce = doc["nonce"] | "";
  uint32_t exp = doc["exp"].as<uint32_t>();
  int taint = doc["taint"] | 0;
  bool bench = (doc["bench"] | 0) == 1;
  String bh = doc["bh"] | "";
  uint32_t amt = doc["amt"].as<uint32_t>();

  String msg = "v2|" + act + "|" + to + "|" + file + "|" + fh + "|" + bh + "|" +
               String(amt) + "|" + nonce + "|" + String(exp) + "|" + String(taint);

  if (killActive || sessionLocked)
  {
    sendRes(nonce, "locked", "");
    return;
  }

  Verdict v = policy(act, to, file, taint);
  bool lied = claim.equalsIgnoreCase("low") && v != V_ALLOW;

  // Bench mode: answer instantly, never wait, never change state
  if (bench)
  {
    if (lied)
      sendRes(nonce, "locked", "");
    else if (v == V_ALLOW)
    {
      sendRes(nonce, "allow", signMsg(msg));
      if (act == "delete_file")
        recordDelete(); // a signed delete is real even in bench: keep the rate limit honest
    }
    else if (v == V_BLOCK)
      sendRes(nonce, "blocked", "");
    else
      sendRes(nonce, "hold", "");
    return;
  }

  // The AI understated the risk: treat the agent as compromised
  if (lied)
  {
    sessionLocked = true;
    voiceSay(spokenRequest(act, to, file, amt, taint) +
             " Session locked: the agent called this low risk.");
    setLed(true, false, false);
    drawRequest("LOCKED", act, to, file, claim, taint == 1);
    sendRes(nonce, "locked", "");
    return; // incident stays on screen until RESET is held
  }

  if (v == V_BLOCK)
  {
    voiceSay(spokenRequest(act, to, file, amt, taint) + " Blocked.");
    setLed(true, false, false);
    drawRequest("BLOCKED", act, to, file, claim, taint == 1);
    sendRes(nonce, "blocked", "");
    delay(2500);
    showHome();
    return;
  }

  if (v == V_ALLOW)
  {
    setLed(false, true, false);
    drawRequest("ALLOWED", act, to, file, claim, taint == 1);
    sendRes(nonce, "allow", signMsg(msg));
    if (act == "delete_file")
      recordDelete();
    delay(800);
    showHome();
    return;
  }

  // Needs a human
  voiceSay(spokenRequest(act, to, file, amt, taint) +
           (act == "pay_invoice" && amt > COSIGN_THRESHOLD_CENTS
                ? " Over 500 dollars: hold the button, then tap your card."
                : " Hold the button to approve, or press reset to deny."));
  drawRequest("HOLD TO OK", act, to, file, claim, taint == 1);
  int d = waitForHold();
  if (d == 1)
  {
    if (act == "pay_invoice" && amt > COSIGN_THRESHOLD_CENTS)
    {
      String p = "Tap card  $" + String(amt / 100);
      drawResult("CO-SIGN", p.c_str());
      int c = waitForCardTap(15000);
      if (c != 1)
      {
        sendRes(nonce, "denied", "");
        setLed(true, false, false);
        drawResult("NO CO-SIGN", c == -1 ? "Wrong card" : "No tap");
        delay(1500);
        showHome();
        return;
      }
    }
    sendRes(nonce, "approved", signMsg(msg));
    if (act == "delete_file")
      recordDelete();
    setLed(false, true, false);
    drawResult("SIGNED", "Approved by human");
  }
  else
  {
    sendRes(nonce, "denied", "");
    setLed(true, false, false);
    drawResult(d == -1 ? "FROZEN" : "DENIED", "No signature issued");
  }
  delay(1500);
  showHome();
}

// ---------- RFID co-sign (F4) ----------
String uidHex() // the UID of the last card read, as AA:BB:CC:DD
{
  String s;
  for (byte i = 0; i < rfid.uid.size; i++)
  {
    if (i)
      s += ":";
    if (rfid.uid.uidByte[i] < 0x10)
      s += "0";
    s += String(rfid.uid.uidByte[i], HEX);
  }
  s.toUpperCase();
  return s;
}

// Wait up to timeoutMs for a card. 1 = enrolled card, -1 = a different card, 0 = timeout.
int waitForCardTap(unsigned long timeoutMs)
{
  unsigned long start = millis();
  while (millis() - start < timeoutMs)
  {
    if (rfid.PICC_IsNewCardPresent() && rfid.PICC_ReadCardSerial())
    {
      bool match = (rfid.uid.size == ENROLLED_UID_LEN);
      for (byte i = 0; match && i < rfid.uid.size; i++)
        if (rfid.uid.uidByte[i] != ENROLLED_UID[i])
          match = false;
      rfid.PICC_HaltA();
      return match ? 1 : -1;
    }
    delay(20);
  }
  return 0;
}

void handleLine(const String &line)
{
  JsonDocument doc;
  if (deserializeJson(doc, line) || !doc.is<JsonObject>())
  {
    sendRes("", "denied", ""); // always answer, so the host never waits out its timeout
    return;
  }
  const char *t = doc["t"] | "";

  if (strcmp(t, "ping") == 0)
  {
    JsonDocument r;
    r["t"] = "pong";
    serializeJson(r, Serial);
    Serial.println();
  }
  else if (strcmp(t, "pubkey") == 0)
  {
    JsonDocument r;
    r["t"] = "pubkey";
    r["pk"] = toHex(publicKey, 32);
    serializeJson(r, Serial);
    Serial.println();
  }
  else if (strcmp(t, "req") == 0)
  {
    handleReq(doc);
  }
  else if (strcmp(t, "cosign") == 0)
  {
    // F4 bring-up: tap a card within 8s; reports if it's the enrolled co-sign card.
    drawResult("TAP CARD", "co-sign test (8s)");
    int r = waitForCardTap(8000);
    JsonDocument res;
    res["t"] = "cosign";
    res["match"] = (r == 1);
    res["uid"] = (r == 0) ? "none" : uidHex();
    serializeJson(res, Serial);
    Serial.println();
    showHome();
  }
  else
  {
    sendRes("", "denied", "");
  }
}

// ---------- buttons outside of approvals ----------
void checkButtons()
{
  static bool lastKill = HIGH;
  bool k = digitalRead(BTN_KILL);
  if (lastKill == HIGH && k == LOW)
  {
    delay(30);
    if (digitalRead(BTN_KILL) == LOW)
    {
      killActive = !killActive;
      showHome();
    }
  }
  lastKill = k;

  if (sessionLocked && !killActive && digitalRead(BTN_RESET) == LOW)
  {
    unsigned long s = millis();
    while (digitalRead(BTN_RESET) == LOW)
    {
      if (millis() - s >= UNLOCK_HOLD_MS)
      {
        sessionLocked = false;
        showHome();
        waitRelease(BTN_RESET);
        return;
      }
      delay(10);
    }
  }
}

void setup()
{
  Serial.setRxBufferSize(2048);
  Serial.begin(115200);
  Wire.begin(21, 22);
  Wire.setClock(400000); // faster screen updates
  display.begin(SSD1306_SWITCHCAPVCC, 0x3C);

  pinMode(BTN_APPROVE, INPUT_PULLUP);
  pinMode(BTN_KILL, INPUT_PULLUP);
  pinMode(BTN_RESET, INPUT_PULLUP);
  pinMode(LED_R, OUTPUT);
  pinMode(LED_G, OUTPUT);
  pinMode(LED_B, OUTPUT);

  SPI.begin(18, 19, 23, 5); // SCK, MISO, MOSI, SS
  rfid.PCD_Init();

  loadOrCreateKey();
  voiceBegin(); // M7: no-op without include/secrets.h
  showHome();
}

const unsigned MAX_LINE = 4096; // matches protocol.MAX_LINE

void loop()
{
  static bool overflow = false;
  checkButtons();
  while (Serial.available())
  {
    char c = Serial.read();
    if (c == '\n')
    {
      lineBuf.trim();
      if (overflow)
        sendRes("", "denied", ""); // too long: refuse instead of parsing a truncated line
      else if (lineBuf.length())
        handleLine(lineBuf);
      lineBuf = "";
      overflow = false;
    }
    else if (lineBuf.length() < MAX_LINE)
    {
      lineBuf += c;
    }
    else
    {
      overflow = true;
    }
  }
}