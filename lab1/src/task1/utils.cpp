#include <lab1/utils.h>


auto PermuteBits(
    std::span<const std::uint8_t> bytes,
    std::span<const std::uint64_t> p_block,
    BitOrder bit_order,
    IndexBase index_base
) -> std::vector<std::uint8_t> {
    std::vector<std::uint8_t> result((p_block.size() + 7) >> 3);

    for (std::uint64_t i = 0; i < p_block.size(); ++i) {
        auto b_index = i;

        if (bit_order == BitOrder::MsbToLsb) {
            b_index = (p_block.size() - 1) - b_index;
        }

        auto b_byte_shift = b_index >> 3;
        auto b_bit_shift = b_index & 7;

        auto p_index = p_block[i] - static_cast<std::uint8_t>(index_base);

        if (bit_order == BitOrder::MsbToLsb) {
            p_index = ((bytes.size() << 3) - 1) - p_index;
        }

        auto p_byte_shift = p_index >> 3;
        auto p_bit_shift = p_index & 7;

        result[b_byte_shift] |= ((bytes[p_byte_shift] >> p_bit_shift) & 1) << b_bit_shift;
    }

    return result;
}
