#ifndef MAI_CB_2026_UTILS_H
#define MAI_CB_2026_UTILS_H

#include <span>
#include <vector>


enum class BitOrder {
    LsbToMsb,
    MsbToLsb
};

enum class IndexBase : std::uint8_t {
    ZeroBased = 0,
    OneBased = 1
};

auto PermuteBits(
    std::span<const std::uint8_t> bytes,
    std::span<const std::uint64_t> p_block,
    BitOrder bit_order,
    IndexBase index_base
) -> std::vector<std::uint8_t>;

#endif //MAI_CB_2026_UTILS_H