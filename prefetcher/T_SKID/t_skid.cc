#include <algorithm>
#include <array>
#include <map>
#include <optional>
#include "cache.h"
#include "msl/lru_table.h"

namespace {

struct TSKID_Prefetcher {
    struct tracker_entry {
        uint64_t ip = 0;
        uint64_t last_cl_addr = 0;
        int64_t last_stride = 0;
        int confidence = 0;
        auto index() const { return ip; }
        auto tag() const { return ip; }
    };

    struct lookahead_entry {
        uint64_t address = 0;
        int64_t stride = 0;
        int degree = 0;
        uint64_t issue_cycle = 0;
    };

    constexpr static std::size_t TRACKER_SETS = 256;
    constexpr static std::size_t TRACKER_WAYS = 4;
    constexpr static int PREFETCH_DEGREE = 3;
    constexpr static int CONFIDENCE_THRESHOLD = 2;
    constexpr static uint64_t PREFETCH_DELAY = 30;

    std::optional<lookahead_entry> active_lookahead;
    champsim::msl::lru_table<tracker_entry> table{TRACKER_SETS, TRACKER_WAYS};

    void initiate_lookahead(uint64_t ip, uint64_t cl_addr, CACHE* cache) {
        /*predict memory access based on patterns*/
        int64_t stride = 0;
        auto found = table.check_hit({ip, cl_addr, stride, 0}); 

        if (found.has_value()) {
            stride = static_cast<int64_t>(cl_addr) - static_cast<int64_t>(found->last_cl_addr);

            if (stride == found->last_stride) {
                found->confidence = std::min(found->confidence + 1, CONFIDENCE_THRESHOLD);
            } else {
                found->confidence = std::max(found->confidence - 1, 0);
            }

            if (stride != 0 && found->confidence >= CONFIDENCE_THRESHOLD - 1) {
                active_lookahead = {cl_addr << LOG2_BLOCK_SIZE, stride, PREFETCH_DEGREE, cache->current_cycle + PREFETCH_DELAY};
            }
        }

        table.fill({ip, cl_addr, stride, found.has_value() ? found->confidence : 0});
    }

    void advance_lookahead(CACHE* cache) {
        /*actually perform the prefetching based on the pattern*/

        if (active_lookahead.has_value() && active_lookahead->issue_cycle <= cache->current_cycle) {
            auto [old_pf_address, stride, degree, _] = active_lookahead.value();
            assert(degree > 0);

            auto addr_delta = stride * BLOCK_SIZE;
            auto pf_address = static_cast<uint64_t>(static_cast<int64_t>(old_pf_address) + addr_delta);

            if (cache->virtual_prefetch || (pf_address >> LOG2_PAGE_SIZE) == (old_pf_address >> LOG2_PAGE_SIZE)) {
                bool success = cache->prefetch_line(pf_address, (cache->get_mshr_occupancy_ratio() < 0.5), 0);
                if (success) {
                    active_lookahead = {pf_address, stride, degree - 1, cache->current_cycle + PREFETCH_DELAY};
                }

                if (active_lookahead->degree == 0) {
                    active_lookahead.reset();
                }
            } else {
                active_lookahead.reset();
            }
        }
    }
};

std::map<CACHE*, TSKID_Prefetcher> prefetchers;

} // namespace

void CACHE::prefetcher_initialize() {}

void CACHE::prefetcher_cycle_operate() {
    /*runs every cycle of the pf operation*/
    /*It looks at the current memory access and tries to predict what memory might be needed next, based on patterns it has seen.*/
    ::prefetchers[this].advance_lookahead(this);
}

uint32_t CACHE::prefetcher_cache_operate(uint64_t addr, uint64_t ip, uint8_t cache_hit, bool useful_prefetch, uint8_t type, uint32_t metadata_in) {
    /*func called whenever the CACHE IS USED*/
    /*It looks at the current memory access and tries to predict what memory might be needed next, based on patterns it has seen.*/
    ::prefetchers[this].initiate_lookahead(ip, addr >> LOG2_BLOCK_SIZE, this);
    return metadata_in;
}

uint32_t CACHE::prefetcher_cache_fill(uint64_t addr, uint32_t set, uint32_t way, uint8_t prefetch, uint64_t evicted_addr, uint32_t metadata_in) {
    /*func called when new data is put into the cache*/
    return metadata_in;
}

void CACHE::prefetcher_final_stats() {}