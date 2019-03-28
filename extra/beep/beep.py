#!/usr/bin/env python

"""
beep.py - Make a beep sound

Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import os
import sys
import wave

BEEP_WAV_FILENAME = os.path.join(os.path.dirname(__file__), "beep.wav")

def beep():
    try:
        if sys.platform == "nt":
            _win_wav_play(BEEP_WAV_FILENAME)
        elif sys.platform == "darwin":
            _mac_beep()
        elif sys.platform.startswith("linux"):
            _linux_wav_play(BEEP_WAV_FILENAME)
        else:
            _speaker_beep()
    except:
        _speaker_beep()

def _speaker_beep():
    sys.stdout.write('\a')  # doesn't work on modern Linux systems

    try:
        sys.stdout.flush()
    except IOError:
        pass

def _mac_beep():
    import Carbon.Snd
    Carbon.Snd.SysBeep(1)

def _win_wav_play(filename):
    import winsound

    winsound.PlaySound(filename, winsound.SND_FILENAME)

def _linux_wav_play(filename):
    for _ in ("aplay", "paplay", "play"):
        if not os.system("%s '%s' 2>/dev/null" % (_, filename)):
            return

    import ctypes

    PA_STREAM_PLAYBACK = 1
    PA_SAMPLE_S16LE = 3
    BUFFSIZE = 1024

    class struct_pa_sample_spec(ctypes.Structure):
        _fields_ = [("format", ctypes.c_int), ("rate", ctypes.c_uint32), ("channels", ctypes.c_uint8)]

    pa = ctypes.cdll.LoadLibrary("libpulse-simple.so.0")

    wave_file = wave.open(filename, "rb")

    pa_sample_spec = struct_pa_sample_spec()
    pa_sample_spec.rate = wave_file.getframerate()
    pa_sample_spec.channels = wave_file.getnchannels()
    pa_sample_spec.format = PA_SAMPLE_S16LE

    error = ctypes.c_int(0)

    pa_stream = pa.pa_simple_new(None, filename, PA_STREAM_PLAYBACK, None, "playback", ctypes.byref(pa_sample_spec), None, None, ctypes.byref(error))
    if not pa_stream:
        raise Exception("Could not create pulse audio stream: %s" % pa.strerror(ctypes.byref(error)))

    while True:
        latency = pa.pa_simple_get_latency(pa_stream, ctypes.byref(error))
        if latency == -1:
            raise Exception("Getting latency failed")

        buf = wave_file.readframes(BUFFSIZE)
        if not buf:
            break

        if pa.pa_simple_write(pa_stream, buf, len(buf), ctypes.byref(error)):
            raise Exception("Could not play file")

    wave_file.close()

    if pa.pa_simple_drain(pa_stream, ctypes.byref(error)):
        raise Exception("Could not simple drain")

    pa.pa_simple_free(pa_stream)

if __name__ == "__main__":
    beep()
