# A FIC-less EDI stream on 36E

This note documents findings from analyzing a FIC-less EDI stream captured from Eutelsat 36E (Russian satellite).

### Stream Overview

| Property | Value |
|----------|-------|
| File | dump.ts |
| Size | 58 MB |
| Format | BBF/GSE |
| Source | Eutelsat 36E (PID 270) |
| Multicast | 224.17.101.98:10198 |
| AF packets | 10,813 |
| FIC present | NO (ficf=0) |
| Subchannels | 13 |
| Content | French DAB ensemble |

### Subchannel Analysis

| Index | SCID | Bitrate | Codec | Notes |
|-------|------|---------|-------|-------|
| 1-5 | 18, 17, 16, 15, 11 | 160 kbps | MP2 | MPEG-1 Layer II, 48kHz stereo, playable |
| 6-9 | 51-54 | 32 kbps | Data | HDLC links, see below |
| 10 | 62 | 8 kbps | Data | Packet mode, address 0: two packets by turns ("t40"/"t41") |
| 11-13 | 12, 13, 14 | 160 kbps | MP2 | MPEG-1 Layer II, 48kHz stereo, playable |

### The four 32 kbit/s streams (subchannels 51-54): HDLC

They carry no audio. Each is a synchronous HDLC link with inverted polarity:
the recurring `81 81` are two flags (0x7E inverted), the zero runs between
bursts are the idle line (all ones). With the bits inverted, the flags
taken off, the stuffed zero after five ones deleted and the bytes read LSB
first, every frame has a right FCS-16 (X.25) - about 12,470 frames a minute
in each stream, in bursts every 64 ms.

| Frame starts with | Length (without FCS) | Rate | What is in it |
|-------------------|----------------------|------|---------------|
| `ff e0` | 11 bytes (a few 13) | ~185/s | `00 87 90 0x` or `80 87 80 0x`, a counter, two 16 bit values (little endian) |
| `00 xx` | 12 and 13 bytes, in pairs | ~16/s each | the second of a pair is the first with `81` put in; `xx` counts |
| `02 80` | 13 bytes (a few 15) | ~8/s | `d0 a4 80`, a counter, `02`, a few bytes |
| `ff c0` | 7 bytes | 2/s | always `84 19 03 10 03` |

No text is in them. Streams 51 and 54 carry the same frames (over 99 %), 52
and 53 too, and the two pairs share most of theirs: two links, each sent
twice. What protocol it is, is not known - telemetry or control of the
network, by the look of it.

(An earlier reading took the `81 81` for the sync word of an unknown audio
format.)

### Data Channel (Subchannel 62)

- Packet mode: packets of 24 bytes, address 0, each with a right CRC
- Two packets by turns, 6 bytes of data: `00 0f 12 "t40"` and `00 0e 12 "t41"`

### What else the frames have

- The audio frames have the DAB layout (scale factor CRC, F-PAD) but no PAD:
  the F-PAD is `00 00`, there is no X-PAD - no dynamic label, no slideshow.
- By the course of their loudness the eight programmes are three in several
  versions: 11 = 12 (17 mostly), 13 = 14 = 15 = 18 mostly, 16 on its own.
- `deti`: FICF 0, mode I, MNSC `ff ff`, a time stamp (ATST) that is right.
  The start addresses of the streams are no addresses of an ensemble (0 for
  all audio streams, 1016-1023 for the others).
- A TAG `dist` that is not in the EDI standard: two packets of 24 bytes in
  the packet mode layout, address 1 with `00 fe 00`, address 2 with four
  floats (big endian: -6.5, -3.0, 7.1, 4.0), the same in every frame.

### What the library makes of it

Up to 2.8.0 nothing: frames without FIC were dropped. Now the audio streams
are told by how their frames start and are the services of an ensemble
without FIC (`DVBDAB_EID_NO_FIC`): "Service 11" to "Service 18", the ids
0x010B to 0x0112. The other five streams are no services. The transponder
is single stream GSE (MATYPE 0x72), 12734 H, 2731 kBd, QPSK 1/3.

### Commands Used

With libdvbdab 1.x (2.0 reads no BBFrame captures):

```bash
# Analyze stream
./build/edi_info bbf dump.ts

# Extract all audio
./build/edi_extract bbf dump.ts all /tmp/output_
```
