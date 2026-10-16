#include <lab1/utils.h>


// auto GetBitCoordinates(
//     std::size_t index,
//     std::size_t total_bits,
//     BitOrder bit_order
// ) -> std::pair<std::size_t, std::size_t> {
//     const std::size_t g_bit = (bit_order == BitOrder::MsbToLsb) ? index : (total_bits - 1 - index);
//
//     return { g_bit >> 3, 7 - (g_bit & 7) };
// }
//
// auto ReadBit(
//     std::span<const std::uint8_t> bytes,
//     std::size_t index,
//     std::size_t total_bits,
//     BitOrder bit_order
// ) -> std::uint8_t {
//     const auto [byte_idx, bit_pos] = GetBitCoordinates(index, total_bits, bit_order);
//
//     return (bytes[byte_idx] >> bit_pos) & 1;
// }
//
// auto WriteBit(
//     std::span<std::uint8_t> bytes,
//     std::size_t index,
//     std::size_t total_bits,
//     BitOrder bit_order,
//     std::uint8_t bit_val
// ) -> void {
//     const auto [byte_idx, bit_pos] = GetBitCoordinates(index, total_bits, bit_order);
//
//     bytes[byte_idx] |= (bit_val << bit_pos);
// }
//
// auto PermuteBits(
//     std::span<const std::uint8_t> bytes,
//     std::span<const std::uint64_t> p_block,
//     BitOrder bit_order,
//     IndexBase index_base
// ) -> std::vector<std::uint8_t> {
//     const auto out_bits = p_block.size();
//     const auto in_bits = bytes.size() << 3;
//     const auto base_offset = static_cast<std::uint64_t>(index_base);
//
//     std::vector<std::uint8_t> result((out_bits + 7) >> 3, 0);
//
//     for (std::size_t i = 0; i < out_bits; ++i) {
//         const auto bit = ReadBit(bytes, p_block[i] - base_offset, in_bits, bit_order);
//
//         WriteBit(result, i, out_bits, bit_order, bit);
//     }
//
//     return result;
//
//     // std::vector<std::uint8_t> result((p_block.size() + 7) >> 3, 0);
//     //
//     // for (std::uint64_t i = 0; i < p_block.size(); ++i) {
//     //     // Выходной бит: байт всегда прямой (i >> 3), инвертируется только позиция внутри байта
//     //     const auto b_byte_shift = i >> 3;
//     //     const auto b_bit_shift = (bit_order == BitOrder::MsbToLsb)
//     //         ? static_cast<std::uint8_t>(7 - (i & 7))
//     //         : static_cast<std::uint8_t>(i & 7);
//     //
//     //     // Входной бит: байт всегда прямой (p_index >> 3)
//     //     const auto p_index = p_block[i] - static_cast<std::uint8_t>(index_base);
//     //     const auto p_byte_shift = p_index >> 3;
//     //     const auto p_bit_shift = (bit_order == BitOrder::MsbToLsb)
//     //         ? static_cast<std::uint8_t>(7 - (p_index & 7))
//     //         : static_cast<std::uint8_t>(p_index & 7);
//     //
//     //     const auto bit_val = (bytes[p_byte_shift] >> p_bit_shift) & 1;
//     //     result[b_byte_shift] |= (bit_val << b_bit_shift);
//     // }
//     //
//     // return result;
//
//     // std::vector<std::uint8_t> result((p_block.size() + 7) >> 3);
//     //
//     // for (std::uint64_t i = 0; i < p_block.size(); ++i) {
//     //     auto b_index = i;
//     //
//     //     if (bit_order == BitOrder::MsbToLsb) {
//     //         b_index = (p_block.size() - 1) - b_index;
//     //     }
//     //
//     //     auto b_byte_shift = b_index >> 3;
//     //     auto b_bit_shift = b_index & 7;
//     //
//     //     auto p_index = p_block[i] - static_cast<std::uint8_t>(index_base);
//     //
//     //     if (bit_order == BitOrder::MsbToLsb) {
//     //         p_index = ((bytes.size() << 3) - 1) - p_index;
//     //     }
//     //
//     //     auto p_byte_shift = p_index >> 3;
//     //     auto p_bit_shift = p_index & 7;
//     //
//     //     result[b_byte_shift] |= ((bytes[p_byte_shift] >> p_bit_shift) & 1) << b_bit_shift;
//     // }
//     //
//     // return result;
// }
//
// // TODO:
// auto Extract6BitChunk(
//     std::span<const std::uint8_t> bytes,
//     std::size_t index
// ) -> std::uint8_t {
//     if (bytes.size() != 6 || index > 7) {
//         throw std::runtime_error("[ERROR] Invalid arguments for Extract6BitChunk!");
//     }
//
//     const std::size_t bit_start = index * 6;
//     const std::size_t b_idx = bit_start >> 3;
//
//     const std::uint16_t val = (static_cast<std::uint16_t>(bytes[b_idx]) << 8) |
//                               (b_idx + 1 < 6 ? bytes[b_idx + 1] : 0);
//
//     return static_cast<std::uint8_t>((val >> (10 - (bit_start & 7))) & 0x3F);
// }
//
// auto CircularShiftLeft(
//     std::span<const std::uint8_t> bytes,
//     std::size_t shift,
//     std::size_t total_bits
// ) -> std::vector<std::uint8_t> {
//     if (total_bits == 0) return {};
//
//     std::vector<std::uint8_t> result((total_bits + 7) >> 3, 0);
//     shift %= total_bits;
//
//     for (std::size_t i = 0; i < total_bits; ++i) {
//         const auto bit = ReadBit(bytes, (i + shift) % total_bits, total_bits, BitOrder::MsbToLsb);
//         WriteBit(result, i, total_bits, BitOrder::MsbToLsb, bit);
//     }
//     return result;
// }
//
// auto Xor(
//     std::span<std::uint8_t> dst,
//     std::span<const std::uint8_t> src
// ) -> void {
//     for (std::size_t i = 0; i < dst.size(); ++i) {
//         dst[i] ^= src[i];
//     }
// }
//
// auto Xor(
//     std::span<std::uint8_t> dst,
//     std::span<const std::uint8_t> src1,
//     std::span<const std::uint8_t> src2
// ) -> void {
//     for (std::size_t i = 0; i < dst.size(); ++i) {
//         dst[i] = src1[i] ^ src2[i];
//     }
// }
//
// auto SplitBlock(
//     std::span<const std::uint8_t> block
// ) -> std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> {
//     const auto half = block.size() >> 1;
//
//     return {
//         std::vector<std::uint8_t>(block.begin(), block.begin() + half),
//         std::vector<std::uint8_t>(block.begin() + half, block.end())
//     };
// }
//
// auto ConcatBlocks(
//     std::span<const std::uint8_t> left,
//     std::span<const std::uint8_t> right,
//     std::span<std::uint8_t> out
// ) -> void {
//     std::copy(left.begin(), left.end(), out.begin());
//     std::copy(right.begin(), right.end(), out.begin() + left.size());
// }
//
// auto AddToCounter(
//     std::span<std::uint8_t> counter,
//     std::uint64_t delta
// ) -> void {
//     std::uint64_t carry = delta;
//     for (std::size_t i = counter.size(); i-- > 0 && carry > 0;) {
//         carry += counter[i];
//         counter[i] = static_cast<std::uint8_t>(carry & 0xFF);
//         carry >>= 8;
//     }
// }
