// The scanner without a clock (dvbdab_scanner_set_timeout(scanner, 0)): it is
// not done because time went by - a caller that reads a capture, faster or
// slower than real time, gets the same from it every time. With a timeout
// the scanner ends when that is over.

#include <dvbdab/dvbdab_c.h>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <random>
#include <thread>

static int failures = 0;

static void check(bool ok, const char* what) {
    std::printf("%s: %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) failures++;
}

// packets of one PID without a payload unit start, with random payload:
// nothing the scanner finds DAB in
static int feed(dvbdab_scanner_t* sc, std::mt19937& rng, int packets) {
    static uint8_t cc = 0;
    int done = 0;
    for (int i = 0; i < packets; i++) {
        uint8_t ts[188];
        for (auto& b : ts) b = static_cast<uint8_t>(rng());
        ts[0] = 0x47;
        ts[1] = 0x01;                       // PID 0x100, no PUSI, no error
        ts[2] = 0x00;
        ts[3] = static_cast<uint8_t>(0x10 | (cc++ & 0x0F));
        done |= dvbdab_scanner_feed(sc, ts, sizeof(ts));
    }
    return done;
}

int main() {
    std::mt19937 rng(20261125);
    dvbdab_set_log_level(DVBDAB_LOG_ERROR);

    dvbdab_scanner_t* sc = dvbdab_scanner_create();
    dvbdab_scanner_set_timeout(sc, 0);
    int done = feed(sc, rng, 500);
    check(!done && !dvbdab_scanner_is_done(sc), "without a clock: not done after the first data");
    // longer than the second after which a scanner with a clock gives up
    // where it found no DAB
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));
    done = feed(sc, rng, 500);
    check(!done && !dvbdab_scanner_is_done(sc), "without a clock: not done because time went by");
    dvbdab_results_t* r = dvbdab_scanner_get_results(sc);
    check(r != nullptr && r->ensemble_count == 0 && r->etina_count == 0, "and nothing found in random data");
    if (r) dvbdab_results_free(r);
    dvbdab_scanner_destroy(sc);

    sc = dvbdab_scanner_create();
    dvbdab_scanner_set_timeout(sc, 200);
    feed(sc, rng, 10);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    done = feed(sc, rng, 10);
    check(done && dvbdab_scanner_is_done(sc), "with a timeout: done when it is over");
    dvbdab_scanner_destroy(sc);

    return failures ? 1 : 0;
}
