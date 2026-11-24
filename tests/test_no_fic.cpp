// Tests for an ensemble that comes without its FIC (FICF 0 in every frame: a
// feed to transmitters that make the FIC themselves): its audio streams are
// told by how their frames start and become its services - at the EDI parser,
// and through the C API into the list of ensembles, the PAT, the SDT and the
// audio that go out. Synthetic frames, no capture.

#include <dvbdab/dvbdab_c.h>
#include "../src/dab_stream_parser.h"
#include "../src/logging.h"
#include "../src/utils/crc_utils.hpp"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

using namespace dvbdab;

static int failures = 0;

static void check(bool ok, const char* what) {
    std::printf("%s: %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) failures++;
}

using Bytes = std::vector<uint8_t>;

static void be32(Bytes& v, uint32_t x) {
    v.push_back(x >> 24);
    v.push_back(x >> 16);
    v.push_back(x >> 8);
    v.push_back(x);
}
static void tag(Bytes& v, const char* id, const Bytes& val) {
    v.insert(v.end(), id, id + 4);
    be32(v, static_cast<uint32_t>(val.size() * 8));
    v.insert(v.end(), val.begin(), val.end());
}

// ---- what the streams carry ----

// a frame of DAB audio at 48 kHz: an MPEG-1 Layer II frame of the bitrate
static Bytes mp2_48(int bitrate, int n) {
    static const int rates[] = {0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384};
    int index = 0;
    for (int i = 1; i < 15; i++)
        if (rates[i] == bitrate) index = i;
    Bytes f(static_cast<size_t>(bitrate) * 3, static_cast<uint8_t>(0x21 + n % 7));
    f[0] = 0xFF;
    f[1] = 0xFC;
    f[2] = static_cast<uint8_t>(index << 4 | 0x04);
    f[3] = 0x00;
    return f;
}

// the frame `n` of DAB audio at 24 kHz: an MPEG-2 LSF Layer II frame takes
// two, its header is in the even ones
static Bytes mp2_24(int bitrate, int n) {
    static const int rates[] = {0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160};
    int index = 0;
    for (int i = 1; i < 15; i++)
        if (rates[i] == bitrate) index = i;
    Bytes f(static_cast<size_t>(bitrate) * 3, static_cast<uint8_t>(0x31 + n % 5));
    if (n % 2 == 0) {
        f[0] = 0xFF;
        f[1] = 0xF4;
        f[2] = static_cast<uint8_t>(index << 4 | 0x04);
        f[3] = 0x00;
    }
    return f;
}

// a superframe of a 24 kbit/s DAB+ subchannel (5 frames of 72 bytes, 3 AUs)
static Bytes superframe(uint8_t fill) {
    const size_t fs = 72, audio = fs * 5 - 3 * 10;
    Bytes sf(fs * 5, 0);
    sf[2] = 0x60;
    const size_t start[4] = {6, 114, 222, audio};
    sf[3] = start[1] >> 4;
    sf[4] = static_cast<uint8_t>((start[1] & 0x0F) << 4 | (start[2] >> 8));
    sf[5] = start[2] & 0xFF;
    for (int i = 0; i < 3; i++) {
        size_t len = start[i + 1] - start[i];
        for (size_t k = 0; k + 2 < len; k++) sf[start[i] + k] = fill;
        uint16_t c = crc16_ccitt_xor(sf.data() + start[i], len - 2);
        sf[start[i] + len - 2] = c >> 8;
        sf[start[i] + len - 1] = c & 0xFF;
    }
    uint16_t crc = 0;
    for (int i = 0; i < 9; i++) crc = static_cast<uint16_t>((crc << 8) ^ firecode_table[((crc >> 8) ^ sf[2 + i]) & 0xFF]);
    sf[0] = crc >> 8;
    sf[1] = crc & 0xFF;
    return sf;
}
static Bytes dabplus_24(int n) {
    Bytes sf = superframe(static_cast<uint8_t>(0x40 + (n / 5) % 8));
    return Bytes(sf.begin() + (n % 5) * 72, sf.begin() + (n % 5) * 72 + 72);
}

// data: bytes that are no audio frame
static Bytes data_stream(size_t size, int n) {
    Bytes f(size);
    uint32_t x = 0x1234567u + static_cast<uint32_t>(n) * 2654435761u;
    for (auto& b : f) {
        x = x * 1664525u + 1013904223u;
        b = static_cast<uint8_t>(x >> 24);
    }
    f[0] = 0x00;  // never a syncword or a superframe
    f[1] = 0x1B;
    return f;
}

// ---- the frames ----

struct Est {
    int scid;
    int tpl;
    Bytes data;
};

// an AF packet of a frame without FIC: *ptr, deti (FICF 0), the streams
static Bytes af_packet(int frame, const std::vector<Est>& streams, bool ficf = false) {
    Bytes deti = {static_cast<uint8_t>((ficf ? 0x40 : 0) | (frame % 5000) / 250), static_cast<uint8_t>(frame % 250)};
    be32(deti, 1u << 22);  // mode I
    if (ficf) deti.resize(deti.size() + 96, 0);   // a FIC of nothing (its FIBs fail their CRC)
    Bytes tags;
    tag(tags, "*ptr", {'D', 'E', 'T', 'I', 0, 0, 0, 0});
    tag(tags, "deti", deti);
    for (size_t k = 0; k < streams.size(); k++) {
        Bytes est = {static_cast<uint8_t>(streams[k].scid << 2), 0, static_cast<uint8_t>(streams[k].tpl << 2)};
        est.insert(est.end(), streams[k].data.begin(), streams[k].data.end());
        tag(tags, (std::string("est") + static_cast<char>(k + 1)).c_str(), est);
    }
    Bytes af = {'A', 'F'};
    be32(af, static_cast<uint32_t>(tags.size()));
    af.push_back(0);
    af.push_back(0);
    af.push_back(0x90);
    af.push_back('T');
    af.insert(af.end(), tags.begin(), tags.end());
    uint16_t c = crc16_ccitt_xor(af.data(), af.size());
    af.push_back(c >> 8);
    af.push_back(c & 0xFF);
    return af;
}

// The feed of the test: Layer II at 48 kHz in stream 11 (160 kbit/s, UEP 5)
// and at 24 kHz in 12 (64 kbit/s), DAB+ in 20 (24 kbit/s, EEP 3-A), data in
// 51 (32 kbit/s) and nothing in 62 (8 kbit/s)
struct Feed {
    bool with12 = true;      // stream 12 is there
    bool audio51 = false;    // stream 51 carries Layer II instead of data
    int lose11 = 0;          // every n-th frame of stream 11 did not come (zeros)
    std::vector<Est> at(int n) const {
        std::vector<Est> s;
        Bytes a = mp2_48(160, n);
        if (lose11 && n % lose11 == 0) a.assign(a.size(), 0);
        s.push_back({11, 0x14, a});
        if (with12) s.push_back({12, 0x13, mp2_24(64, n)});
        s.push_back({20, 0x22, dabplus_24(n)});
        s.push_back({51, 0x21, audio51 ? mp2_48(32, n) : data_stream(96, n)});
        s.push_back({62, 0x21, Bytes(24, 0)});
        return s;
    }
};

static const DABService* find(const DABEnsemble& e, uint32_t sid) {
    for (const auto& s : e.services)
        if (s.sid == sid) return &s;
    return nullptr;
}

static void run(DABStreamParser& p, const Feed& f, int frames, int& n) {
    for (int i = 0; i < frames; i++, n++) {
        Bytes af = af_packet(n, f.at(n));
        p.process_edi_packet(af.data(), af.size());
    }
}

// ---- the TS that goes out ----

struct TsOut {
    std::map<uint16_t, Bytes> sec;
    std::map<uint16_t, uint64_t> pids;
    std::set<uint16_t> programs;             // of the last PAT
    std::map<uint16_t, std::string> names;   // of the last SDT sections
    std::map<uint16_t, std::string> providers;
    int tsid = -1;
    void section(uint16_t pid, const uint8_t* s, size_t n) {
        if (pid == 0 && s[0] == 0x00) {
            tsid = s[3] << 8 | s[4];
            programs.clear();
            for (size_t p = 8; p + 4 <= n - 4; p += 4) programs.insert(static_cast<uint16_t>(s[p] << 8 | s[p + 1]));
        }
        if (pid == 0x11 && s[0] == 0x42) {
            if (s[6] == 0) names.clear();
            for (size_t p = 11; p + 5 <= n - 4;) {
                uint16_t sid = static_cast<uint16_t>(s[p] << 8 | s[p + 1]);
                size_t dl = static_cast<size_t>((s[p + 3] & 0x0F) << 8 | s[p + 4]);
                // service descriptor: tag, length, type, provider (length, text), name (length, text)
                if (dl >= 5 && s[p + 5] == 0x48) {
                    size_t pl = s[p + 8], nl = s[p + 9 + pl];
                    providers[sid] = std::string(s + p + 9, s + p + 9 + pl);
                    names[sid] = std::string(s + p + 10 + pl, s + p + 10 + pl + nl);
                }
                p += 5 + dl;
            }
        }
    }
    void feed(const uint8_t* d, size_t len) {
        for (size_t o = 0; o + 188 <= len; o += 188) {
            const uint8_t* k = d + o;
            uint16_t pid = static_cast<uint16_t>((k[1] & 0x1F) << 8 | k[2]);
            pids[pid]++;
            if (pid != 0 && pid != 0x11) continue;
            size_t pl = 4;
            if (k[3] & 0x20) pl = 5 + k[4];
            if (pl >= 188) continue;
            Bytes& b = sec[pid];
            if (k[1] & 0x40) {
                size_t ptr = k[pl];
                b.assign(k + pl + 1 + ptr, k + 188);
            } else {
                b.insert(b.end(), k + pl, k + 188);
            }
            while (b.size() >= 3 && b[0] != 0xFF) {
                size_t n = 3 + static_cast<size_t>((b[1] & 0x0F) << 8 | b[2]);
                if (b.size() < n) break;
                section(pid, b.data(), n);
                b.erase(b.begin(), b.begin() + static_cast<std::ptrdiff_t>(n));
            }
        }
    }
};

// the AF packet in UDP to 239.1.1.1:5000, in IPv4
static Bytes ip_packet(const Bytes& af) {
    Bytes p(28 + af.size());
    size_t total = p.size(), ul = 8 + af.size();
    p[0] = 0x45;
    p[2] = total >> 8;
    p[3] = total & 0xFF;
    p[8] = 64;
    p[9] = 17;
    p[16] = 0xEF;
    p[17] = p[18] = p[19] = 1;
    uint32_t sum = 0;
    for (size_t k = 0; k < 20; k += 2) sum += (static_cast<uint32_t>(p[k]) << 8) | p[k + 1];
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    uint16_t ck = static_cast<uint16_t>(~sum);
    p[10] = ck >> 8;
    p[11] = ck & 0xFF;
    p[22] = 5000 >> 8;
    p[23] = 5000 & 0xFF;
    p[24] = ul >> 8;
    p[25] = ul & 0xFF;
    std::memcpy(&p[28], af.data(), af.size());
    return p;
}

int main() {
    set_log_level(LogLevel::ERROR);

    // ---- at the parser ----
    {
        DABStreamParser p(0xEF010101, 5000);
        Feed f;
        int n = 0;

        run(p, f, 49, n);
        check(!p.is_basic_ready() && p.get_ensemble().eid == 0 && p.get_ensemble().services.empty(),
              "no ensemble before the streams are told (a window of 50 frames)");
        check(p.has_data(), "frames without FIC are frames");

        run(p, f, 2, n);
        const DABEnsemble& e = p.get_ensemble();
        check(p.is_basic_ready() && p.is_complete(), "after it the ensemble is ready, and complete (no labels come)");
        check(e.eid == EID_NO_FIC && e.label.empty(), "it has the id of an ensemble without FIC and no label");
        check(e.services.size() == 3, "its three audio streams are its services, the data streams are none");
        const DABService* a = find(e, SID_NO_FIC_BASE + 11);
        const DABService* b = find(e, SID_NO_FIC_BASE + 12);
        const DABService* c = find(e, SID_NO_FIC_BASE + 20);
        check(a && a->label == "Service 11" && a->subchannel_id == 11 && a->bitrate == 160 && !a->dabplus,
              "Layer II at 48 kHz: \"Service 11\", DAB, 160 kbit/s");
        check(b && b->label == "Service 12" && b->subchannel_id == 12 && b->bitrate == 64 && !b->dabplus,
              "Layer II at 24 kHz (a header every second frame): \"Service 12\", DAB, 64 kbit/s");
        check(c && c->label == "Service 20" && c->subchannel_id == 20 && c->bitrate == 24 && c->dabplus,
              "superframes: \"Service 20\", DAB+, 24 kbit/s");
        check(a && a->subchannel_size == 80 && a->protection_level == 5 && !a->eep_protection,
              "the TPL of a stream: UEP level 5, 80 capacity units at 160 kbit/s");
        check(c && c->subchannel_size == 18 && c->protection_level == 2 && c->eep_protection,
              "... EEP 3-A, 18 capacity units at 24 kbit/s");

        // frames of a stream that got lost: still that service
        uint32_t rev = p.ensemble_revision();
        f.lose11 = 3;
        run(p, f, 200, n);
        check(p.get_ensemble().services.size() == 3 && p.ensemble_revision() == rev,
              "a third of the frames of a stream lost: the same ensemble");
        f.lose11 = 0;

        // a stream that carries audio now: a service after two windows
        f.audio51 = true;
        run(p, f, 60, n);
        check(p.get_ensemble().services.size() == 3, "a data stream that carries audio now: not yet after one window");
        run(p, f, 100, n);
        const DABService* d = find(p.get_ensemble(), SID_NO_FIC_BASE + 51);
        check(p.get_ensemble().services.size() == 4 && d && d->bitrate == 32 && !d->dabplus && d->eep_protection &&
                  d->subchannel_size == 32 && p.ensemble_revision() > rev,
              "... after two it is \"Service 51\", and the ensemble has changed");
        f.audio51 = false;
        run(p, f, 160, n);
        check(p.get_ensemble().services.size() == 3, "... and none again when it carries data again");

        // a stream that goes
        rev = p.ensemble_revision();
        f.with12 = false;
        run(p, f, 400, n);
        check(p.get_ensemble().services.size() == 3, "a stream the frames no longer have: still there for a while");
        run(p, f, 150, n);
        check(p.get_ensemble().services.size() == 2 && !find(p.get_ensemble(), SID_NO_FIC_BASE + 12) &&
                  p.ensemble_revision() > rev,
              "... and gone after 12 s");
        // ... and comes again
        f.with12 = true;
        run(p, f, 60, n);
        check(p.get_ensemble().services.size() == 3 && find(p.get_ensemble(), SID_NO_FIC_BASE + 12),
              "... and a service again when it comes again");
    }

    // only data: no ensemble
    {
        DABStreamParser p(0xEF010101, 5000);
        for (int n = 0; n < 200; n++) {
            Bytes af = af_packet(n, {{51, 0x21, data_stream(96, n)}, {62, 0x21, Bytes(24, 0)}});
            p.process_edi_packet(af.data(), af.size());
        }
        check(!p.is_basic_ready() && p.get_ensemble().eid == 0 && p.get_ensemble().services.empty(),
              "frames without FIC and without audio are no ensemble");
    }

    // a FIC that comes later: what the streams told goes
    {
        DABStreamParser p(0xEF010101, 5000);
        Feed f;
        int n = 0;
        run(p, f, 60, n);
        check(p.get_ensemble().eid == EID_NO_FIC, "(an ensemble without FIC)");
        for (int i = 0; i < 5; i++, n++) {
            Bytes af = af_packet(n, f.at(n), true);
            p.process_edi_packet(af.data(), af.size());
        }
        check(p.get_ensemble().eid == 0 && p.get_ensemble().services.empty() && !p.is_basic_ready(),
              "frames with a FIC after it: the ensemble is what the FIC says, not the streams");
        run(p, f, 120, n);
        check(p.get_ensemble().eid == 0, "... and frames without one again do not bring it back");
    }

    // ---- through the C API ----
    {
        // a scan: no filter, the ensembles of the stream
        dvbdab_streamer_config_t c;
        std::memset(&c, 0, sizeof(c));
        c.format = DVBDAB_FORMAT_IPV4;
        dvbdab_streamer_t* s = dvbdab_streamer_create(&c);
        Feed f;
        for (int n = 0; n < 60; n++) {
            Bytes p = ip_packet(af_packet(n, f.at(n)));
            dvbdab_streamer_feed(s, p.data(), p.size());
        }
        int count = 0;
        dvbdab_ensemble_t* e = dvbdab_streamer_get_all_ensembles(s, &count);
        check(e && count == 1 && e[0].eid == DVBDAB_EID_NO_FIC && e[0].label[0] == '\0' && e[0].service_count == 3 &&
                  e[0].source_ip == 0xEF010101 && e[0].source_port == 5000,
              "a scan finds the ensemble without FIC: its id, no label, 3 services, where it is");
        bool named = e && count == 1 && e[0].service_count == 3 && e[0].services &&
                     std::string(e[0].services[0].label) == "Service 11" &&
                     e[0].services[0].sid == DVBDAB_SID_NO_FIC_BASE + 11 && e[0].services[0].subchannel_id == 11;
        check(named, "... its first service is \"Service 11\"");
        if (e) dvbdab_streamer_free_all_ensembles(e, count);
        dvbdab_streamer_destroy(s);
    }
    {
        // a stream: the PAT, the SDT and the audio
        dvbdab_streamer_config_t c;
        std::memset(&c, 0, sizeof(c));
        c.format = DVBDAB_FORMAT_IPV4;
        c.filter_ip = 0xEF010101;
        c.filter_port = 5000;
        c.eid = DVBDAB_EID_NO_FIC;
        dvbdab_streamer_t* s = dvbdab_streamer_create(&c);
        TsOut out;
        dvbdab_streamer_set_output(s, [](void* o, const uint8_t* d, size_t n) { static_cast<TsOut*>(o)->feed(d, n); }, &out);
        dvbdab_streamer_start_all(s);
        Feed f;
        for (int n = 0; n < 400; n++) {
            Bytes p = ip_packet(af_packet(n, f.at(n)));
            dvbdab_streamer_feed(s, p.data(), p.size());
            dvbdab_streamer_start_all(s);
        }
        check(out.tsid == DVBDAB_EID_NO_FIC, "the TS has the id of an ensemble without FIC");
        check(out.programs == std::set<uint16_t>{0x010B, 0x010C, 0x0114}, "the PAT has the three services");
        check(out.names[0x010B] == "Service 11" && out.names[0x010C] == "Service 12" && out.names[0x0114] == "Service 20",
              "the SDT names them \"Service <SubChId>\"");
        check(out.providers[0x010B].empty(), "... without a provider (the ensemble has no label)");
        check(out.pids[0x1000 + 11] > 100 && out.pids[0x1000 + 12] > 40 && out.pids[0x1000 + 20] > 10,
              "the audio of the three goes out");
        check(out.pids.count(0x1000 + 51) == 0 && out.pids.count(0x1000 + 62) == 0, "the data streams have no PID");
        dvbdab_streamer_destroy(s);
    }

    if (failures) {
        std::printf("%d check(s) failed\n", failures);
        return 1;
    }
    std::printf("all checks passed\n");
    return 0;
}
