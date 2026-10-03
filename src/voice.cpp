// M7 voice: stream ElevenLabs text-to-speech to a MAX98357A I2S amp, on core 0.
//
// What is spoken is built in main.cpp from the request fields the device already validated,
// the same truth the OLED shows, never text from the laptop. Voice is a convenience channel:
// the verdict, the signature and the serial reply never wait for it, and if Wi-Fi or ElevenLabs
// fails the device simply stays silent.
//
// This task must never write to Serial: the main loop sends JSON replies on the same port, and
// a log line from the other core could land inside a reply and corrupt it.
#include "voice.h"

#if __has_include("secrets.h")
#include "secrets.h"   // WIFI_SSID, WIFI_PASS, ELEVEN_KEY, ELEVEN_VOICE_ID (gitignored)
#define VOICE_ENABLED 1
#else
#define VOICE_ENABLED 0
#endif

#if VOICE_ENABLED
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <driver/i2s.h>

// MAX98357A wiring (pins that are free next to the OLED, RC522, buttons and LED)
static const int I2S_BCLK = 14, I2S_LRC = 17, I2S_DOUT = 16;
static const int SAMPLE_RATE = 16000;            // ElevenLabs output_format=pcm_16000
static const char *MODEL_ID = "eleven_flash_v2_5";
static const unsigned long WIFI_WAIT_MS = 4000;
static const size_t MAX_TEXT = 400;

// api.elevenlabs.io chains to GTS Root R1 (cross-signed by GlobalSign Root CA). Both are
// trusted so the TLS check holds whichever path the server sends. Verified 2026-10-03.
static const char *ROOT_CA = R"PEM(
-----BEGIN CERTIFICATE-----
MIIFWjCCA0KgAwIBAgIQbkepxUtHDA3sM9CJuRz04TANBgkqhkiG9w0BAQwFADBH
MQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExM
QzEUMBIGA1UEAxMLR1RTIFJvb3QgUjEwHhcNMTYwNjIyMDAwMDAwWhcNMzYwNjIy
MDAwMDAwWjBHMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNl
cnZpY2VzIExMQzEUMBIGA1UEAxMLR1RTIFJvb3QgUjEwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQC2EQKLHuOhd5s73L+UPreVp0A8of2C+X0yBoJx9vaM
f/vo27xqLpeXo4xL+Sv2sfnOhB2x+cWX3u+58qPpvBKJXqeqUqv4IyfLpLGcY9vX
mX7wCl7raKb0xlpHDU0QM+NOsROjyBhsS+z8CZDfnWQpJSMHobTSPS5g4M/SCYe7
zUjwTcLCeoiKu7rPWRnWr4+wB7CeMfGCwcDfLqZtbBkOtdh+JhpFAz2weaSUKK0P
fyblqAj+lug8aJRT7oM6iCsVlgmy4HqMLnXWnOunVmSPlk9orj2XwoSPwLxAwAtc
vfaHszVsrBhQf4TgTM2S0yDpM7xSma8ytSmzJSq0SPly4cpk9+aCEI3oncKKiPo4
Zor8Y/kB+Xj9e1x3+naH+uzfsQ55lVe0vSbv1gHR6xYKu44LtcXFilWr06zqkUsp
zBmkMiVOKvFlRNACzqrOSbTqn3yDsEB750Orp2yjj32JgfpMpf/VjsPOS+C12LOO
Rc92wO1AK/1TD7Cn1TsNsYqiA94xrcx36m97PtbfkSIS5r762DL8EGMUUXLeXdYW
k70paDPvOmbsB4om3xPXV2V4J95eSRQAogB/mqghtqmxlbCluQ0WEdrHbEg8QOB+
DVrNVjzRlwW5y0vtOUucxD/SVRNuJLDWcfr0wbrM7Rv1/oFB2ACYPTrIrnqYNxgF
lQIDAQABo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNV
HQ4EFgQU5K8rJnEaK0gnhS9SZizv8IkTcT4wDQYJKoZIhvcNAQEMBQADggIBADiW
Cu49tJYeX++dnAsznyvgyv3SjgofQXSlfKqE1OXyHuY3UjKcC9FhHb8owbZEKTV1
d5iyfNm9dKyKaOOpMQkpAWBz40d8U6iQSifvS9efk+eCNs6aaAyC58/UEBZvXw6Z
XPYfcX3v73svfuo21pdwCxXu11xWajOl40k4DLh9+42FpLFZXvRq4d2h9mREruZR
gyFmxhE+885H7pwoHyXa/6xmld01D1zvICxi/ZG6qcz8WpyTgYMpl0p8WnK0OdC3
d8t5/Wk6kjftbjhlRn7pYL15iJdfOBL07q9bgsiG1eGZbYwE8na6SfZu6W0eX6Dv
J4J2QPim01hcDyxC2kLGe4g0x8HYRZvBPsVhHdljUEn2NIVq4BjFbkerQUIpm/Zg
DdIx02OYI5NaAIFItO/Nis3Jz5nu2Z6qNuFoS3FJFDYoOj0dzpqPJeaAcWErtXvM
+SUWgeExX6GjfhaknBZqlxi9dnKlC54dNuYvoS++cJEPqOba+MSSQGwlfnuzCdyy
F62ARPBopY+Udf90WuioAnwMCeKpSwughQtiue+hMZL77/ZRBIls6Kl0obsXs7X9
SQ98POyDGCBDTtWTurQ0sR8WNh8M5mQ5Fkzc4P4dyKliPUDqysU0ArSuiYgzNdws
E3PYJ/HQcu51OyLemGhmW/HGY0dVHLqlCFF1pkgl
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkG
A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jv
b3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw05ODA5MDExMjAw
MDBaFw0yODAxMjgxMjAwMDBaMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
YWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJHbG9iYWxT
aWduIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDaDuaZ
jc6j40+Kfvvxi4Mla+pIH/EqsLmVEQS98GPR4mdmzxzdzxtIK+6NiY6arymAZavp
xy0Sy6scTHAHoT0KMM0VjU/43dSMUBUc71DuxC73/OlS8pF94G3VNTCOXkNz8kHp
1Wrjsok6Vjk4bwY8iGlbKk3Fp1S4bInMm/k8yuX9ifUSPJJ4ltbcdG6TRGHRjcdG
snUOhugZitVtbNV4FpWi6cgKOOvyJBNPc1STE4U6G7weNLWLBYy5d4ux2x8gkasJ
U26Qzns3dLlwR5EiUWMWea6xrkEmCMgZK9FGqkjWZCrXgzT/LCrBbBlDSgeF59N8
9iFo7+ryUp9/k5DPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8E
BTADAQH/MB0GA1UdDgQWBBRge2YaRQ2XyolQL30EzTSo//z9SzANBgkqhkiG9w0B
AQUFAAOCAQEA1nPnfE920I2/7LqivjTFKDK1fPxsnCwrvQmeU79rXqoRSLblCKOz
yj1hTdNGCbM+w6DjY1Ub8rrvrTnhQ7k4o+YviiY776BQVvnGCv04zcQLcFGUl5gE
38NflNUVyRRBnMRddWQVDf9VMOyGj/8N7yy5Y0b2qvzfvGn9LhJIZJrglfCm7ymP
AbEVtQwdpf5pLGkkeB6zpxxxYu7KyJesF12KwvhHhm4qxFYxldBniYUr+WymXUad
DKqC5JlR3XC321Y9YeRq4VzW9v493kHMB65jUr9TU/Qr6cf9tveCX4XSQRjbgbME
HMUfpIBvFSDJ3gyICh3WZlXi/EjJKSZp4A==
-----END CERTIFICATE-----
)PEM";

struct Utterance
{
  char text[MAX_TEXT + 1];
};
static QueueHandle_t queue;

static String jsonEscape(const char *s)
{
  String out;
  for (; *s; s++)
  {
    if (*s == '"' || *s == '\\')
      out += '\\';
    if ((uint8_t)*s >= 32 && (uint8_t)*s < 127)
      out += *s;
  }
  return out;
}

// One POST, streamed straight into I2S. HTTP/1.0 keeps the server from using chunked encoding,
// so the body is raw 16-bit little-endian mono PCM until the connection closes.
static void speakNow(const char *text)
{
  unsigned long t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < WIFI_WAIT_MS)
    vTaskDelay(pdMS_TO_TICKS(100));
  if (WiFi.status() != WL_CONNECTED)
    return;

  WiFiClientSecure c;
  c.setCACert(ROOT_CA);
  c.setTimeout(10);
  if (!c.connect("api.elevenlabs.io", 443))
    return;
  String body = String("{\"text\":\"") + jsonEscape(text) + "\",\"model_id\":\"" + MODEL_ID + "\"}";
  c.print(String("POST /v1/text-to-speech/") + ELEVEN_VOICE_ID +
          "?output_format=pcm_16000 HTTP/1.0\r\n"
          "Host: api.elevenlabs.io\r\n"
          "xi-api-key: " + ELEVEN_KEY + "\r\n"
          "Content-Type: application/json\r\n"
          "Accept: audio/pcm\r\n"
          "Content-Length: " + String(body.length()) + "\r\n\r\n" + body);

  String status = c.readStringUntil('\n');
  if (status.indexOf(" 200") < 0)
  {
    c.stop();                       // bad key, voice id or quota: stay silent
    return;
  }
  while (c.connected() || c.available())  // skip the headers
  {
    String h = c.readStringUntil('\n');
    if (h == "\r" || h.length() == 0)
      break;
  }

  uint8_t buf[1024];
  size_t carry = 0;                 // a sample split across two reads
  while (c.connected() || c.available())
  {
    int n = c.read(buf + carry, sizeof(buf) - carry);
    if (n <= 0)
    {
      vTaskDelay(1);
      continue;
    }
    size_t total = carry + n, even = total & ~(size_t)1, written;
    i2s_write(I2S_NUM_0, buf, even, &written, portMAX_DELAY);
    carry = total - even;
    if (carry)
      buf[0] = buf[even];
  }
  c.stop();
  i2s_zero_dma_buffer(I2S_NUM_0);    // no hum or click after the last word
}

static void voiceTask(void *)
{
  Utterance u;
  for (;;)
    if (xQueueReceive(queue, &u, portMAX_DELAY) == pdTRUE)
      speakNow(u.text);
}

void voiceBegin()
{
  i2s_config_t cfg = {};
  cfg.mode = (i2s_mode_t)(I2S_MODE_MASTER | I2S_MODE_TX);
  cfg.sample_rate = SAMPLE_RATE;
  cfg.bits_per_sample = I2S_BITS_PER_SAMPLE_16BIT;
  cfg.channel_format = I2S_CHANNEL_FMT_ONLY_LEFT;
  cfg.communication_format = I2S_COMM_FORMAT_STAND_I2S;
  cfg.dma_buf_count = 8;
  cfg.dma_buf_len = 256;
  cfg.tx_desc_auto_clear = true;     // silence, not a repeating buffer, if the stream stalls
  i2s_pin_config_t pins = {};
  pins.bck_io_num = I2S_BCLK;
  pins.ws_io_num = I2S_LRC;
  pins.data_out_num = I2S_DOUT;
  pins.data_in_num = I2S_PIN_NO_CHANGE;
  i2s_driver_install(I2S_NUM_0, &cfg, 0, nullptr);
  i2s_set_pin(I2S_NUM_0, &pins);

  WiFi.mode(WIFI_STA);
  WiFi.setAutoReconnect(true);
  WiFi.begin(WIFI_SSID, WIFI_PASS);  // doesn't block: the task waits for it per sentence

  queue = xQueueCreate(1, sizeof(Utterance));
  // Core 0, below the Wi-Fi stack's priority; the Arduino loop (serial, buttons) runs on core 1
  xTaskCreatePinnedToCore(voiceTask, "voice", 8192, nullptr, 1, nullptr, 0);
}

void voiceSay(const String &text)
{
  if (!queue)
    return;
  Utterance u;
  strlcpy(u.text, text.c_str(), sizeof(u.text));
  xQueueOverwrite(queue, &u);        // the newest request matters, not a backlog
}

#else // no secrets.h: voice is off

void voiceBegin() {}
void voiceSay(const String &) {}

#endif

// ---- spoken forms (always compiled; pure string work) ----

static String spell(const String &s, bool path)
{
  String out;
  for (unsigned i = 0; i < s.length(); i++)
  {
    char ch = s[i];
    if (ch == '@')
      out += " at ";
    else if (ch == '.')
      out += " dot ";
    else if (ch == '-')
      out += " dash ";
    else if (ch == '_')
      out += path ? " " : " underscore ";
    else
      out += ch;
  }
  return out;
}

String voiceAddress(const String &addr) { return spell(addr, false); }

String voiceFile(const String &path)
{
  int slash = path.lastIndexOf('/');
  return spell(slash >= 0 ? path.substring(slash + 1) : path, true);
}

String voiceDigits(const String &s)
{
  String out;
  for (unsigned i = 0; i < s.length(); i++)
  {
    if (i)
      out += ' ';
    out += s[i];
  }
  return out;
}
