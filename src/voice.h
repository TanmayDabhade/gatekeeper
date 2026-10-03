// M7 voice: the device reads its own view of a request aloud through ElevenLabs.
// Optional: with no include/secrets.h it compiles to no-ops and the device works as before.
#pragma once
#include <Arduino.h>

void voiceBegin();                     // call once in setup(), before any request is handled
void voiceSay(const String &text);     // never blocks: the newest sentence replaces a queued one

// Spoken forms built from validated request fields (ASCII only, like the OLED)
String voiceAddress(const String &addr);   // records at compliance dash archive dot io
String voiceFile(const String &path);      // tax return dot pdf
String voiceDigits(const String &s);       // 9686 -> "9 6 8 6"
