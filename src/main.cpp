#include <Arduino.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <ArduinoJson.h>
#include <Preferences.h>
#include "monocypher.h"
#include "monocypher-ed25519.h"

Adafruit_SSD1306 display(128, 64, &Wire, -1);
Preferences prefs;
String lineBuf;

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
  const char *strs[] = {"act", "to", "file", "fh", "claim", "nonce"};
  for (const char *k : strs)
  {
    if (!doc[k].is<const char *>())
      return "missing string field";
    if (!cleanField(doc[k].as<String>()))
      return "forbidden characters";
  }
  const char *ints[] = {"exp", "taint", "bench"};
  for (const char *k : ints)
  {
    if (!doc[k].is<long long>())
      return "missing integer field";
  }
  String act = doc["act"].as<String>(), to = doc["to"].as<String>();
  String file = doc["file"].as<String>(), fh = doc["fh"].as<String>();
  String claim = doc["claim"].as<String>(), nonce = doc["nonce"].as<String>();
  long long taint = doc["taint"], bench = doc["bench"], exp = doc["exp"];
  if (claim != "low" && claim != "medium" && claim != "high")
    return "bad claim";
  if ((taint != 0 && taint != 1) || (bench != 0 && bench != 1))
    return "taint/bench must be 0 or 1";
  if (exp < 0 || exp > 0xFFFFFFFFLL)
    return "bad exp";
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
  if (file.indexOf("/../") >= 0 || file.indexOf("/./") >= 0 || file.indexOf("//") >= 0)
    return "file must be a canonical path";
  if (file.length() ? !isLowerHex(fh, 64) : fh.length() != 0)
    return "bad fh";
  return nullptr;
}

// ---------- protocol ----------
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

  String msg = "v1|" + act + "|" + to + "|" + file + "|" + fh + "|" +
               nonce + "|" + String(exp) + "|" + String(taint);

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
    setLed(true, false, false);
    drawRequest("LOCKED", act, to, file, claim, taint == 1);
    sendRes(nonce, "locked", "");
    return; // incident stays on screen until RESET is held
  }

  if (v == V_BLOCK)
  {
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
  drawRequest("HOLD TO OK", act, to, file, claim, taint == 1);
  int d = waitForHold();
  if (d == 1)
  {
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

  loadOrCreateKey();
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