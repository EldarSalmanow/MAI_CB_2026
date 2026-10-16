#ifndef MAI_CB_2026_UTILS_H
#define MAI_CB_2026_UTILS_H

#include <future>
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

constexpr auto GetBitCoordinates(
    std::uint64_t index,
    std::uint64_t total_bits,
    BitOrder bit_order
) -> std::pair<std::uint64_t, std::uint64_t> {
    const auto g_bit = (bit_order == BitOrder::MsbToLsb) ? index : (total_bits - 1 - index);

    return { g_bit >> 3, 7 - (g_bit & 7) };
}

constexpr auto ReadBit(
    std::span<const std::uint8_t> bytes,
    std::uint64_t index,
    std::uint64_t total_bits,
    BitOrder bit_order
) -> std::uint8_t {
    const auto [byte_idx, bit_pos] = GetBitCoordinates(index, total_bits, bit_order);

    return (bytes[byte_idx] >> bit_pos) & 1;
}

constexpr auto WriteBit(
    std::span<std::uint8_t> bytes,
    std::uint64_t index,
    std::uint64_t total_bits,
    BitOrder bit_order,
    std::uint8_t bit_val
) -> void {
    const auto [byte_idx, bit_pos] = GetBitCoordinates(index, total_bits, bit_order);

    bytes[byte_idx] &= ~(1 << bit_pos);
    bytes[byte_idx] |= ((bit_val & 1) << bit_pos);
}

constexpr void PermuteBits(
    std::span<const std::uint8_t> bytes,
    std::span<const std::uint64_t> p_block,
    BitOrder bit_order,
    IndexBase index_base,
    std::span<std::uint8_t> out
) {
    const auto out_bits_count = p_block.size();
    const auto in_bits_count  = bytes.size() << 3;
    const auto out_physical_bits = out.size() * 8;
    const auto base_offset = static_cast<std::uint64_t>(index_base);

    for (std::uint64_t i = 0; i < out_bits_count; ++i) {
        const auto bit_val = ReadBit(bytes, p_block[i] - base_offset, in_bits_count, bit_order);

        WriteBit(out, i, out_physical_bits, bit_order, bit_val);
    }
}

// TODO:
constexpr auto Extract6BitChunk(
    std::span<const std::uint8_t> bytes,
    std::uint64_t index
) -> std::uint8_t {
    if (bytes.size() != 6 || index > 7) {
        throw std::runtime_error("[ERROR] Invalid arguments for Extract6BitChunk!");
    }

    const auto bit_start = index * 6;
    const auto bit_index = bit_start >> 3;

    const std::uint16_t b1 = bytes[bit_index];
    const std::uint16_t b2 = (bit_index + 1 < bytes.size()) ? bytes[bit_index + 1] : 0;

    const std::uint16_t value = (b1 << 8) | b2;
    const auto shift = 10 - (bit_start % 8);

    return static_cast<std::uint8_t>((value >> shift) & 0x3F);
}

constexpr auto CircularShiftLeft(
    std::span<const std::uint8_t> bytes,
    std::uint64_t shift,
    std::uint64_t total_bits,
    std::span<std::uint8_t> out
) -> void {
    if (total_bits == 0) {
        return;
    }

    shift %= total_bits;

    for (std::uint64_t i = 0; i < total_bits; ++i) {
        const auto bit = ReadBit(bytes, (i + shift) % total_bits, total_bits, BitOrder::MsbToLsb);

        WriteBit(out, i, total_bits, BitOrder::MsbToLsb, bit);
    }
}

constexpr auto Xor(
    std::span<std::uint8_t> dst,
    std::span<const std::uint8_t> src
) -> void {
    for (std::size_t i = 0; i < dst.size(); ++i) {
        dst[i] ^= src[i];
    }
}

constexpr auto Xor(
    std::span<std::uint8_t> dst,
    std::span<const std::uint8_t> src1,
    std::span<const std::uint8_t> src2
) -> void {
    for (std::size_t i = 0; i < dst.size(); ++i) {
        dst[i] = src1[i] ^ src2[i];
    }
}

constexpr auto AddToCounter(
    std::span<std::uint8_t> counter,
    std::uint64_t delta
) -> void {
    std::uint64_t carry = delta;

    for (std::uint64_t i = counter.size(); i > 0 && carry > 0; --i) {
        const auto sum = (carry & 0xFF) + counter[i - 1];
        counter[i - 1] = static_cast<std::uint8_t>(sum);
        carry = (carry >> 8) + (sum >> 8);
    }
}

// Add a full 64 x 64-bit product without truncating the high half for DEAL.
constexpr auto AddCounterProduct(
    std::span<std::uint8_t> counter,
    std::uint64_t index,
    std::uint64_t delta
) -> void {
    constexpr std::uint64_t mask = 0xFFFFFFFF;
    const auto low = (index & mask) * (delta & mask);
    const auto middle = (index >> 32) * (delta & mask) + (low >> 32);
    const auto upper = (index & mask) * (delta >> 32) + (middle & mask);
    const auto high = (index >> 32) * (delta >> 32) + (middle >> 32) + (upper >> 32);
    AddToCounter(counter, (upper << 32) | (low & mask));
    if (counter.size() > 8) {
        AddToCounter(counter.first(counter.size() - 8), high);
    }
}

template <typename FunctionT>
auto ParallelFor(
    std::uint64_t tasks_count,
    FunctionT &&function
) -> void {
    if (tasks_count == 0) {
        return;
    }

    const auto threads = std::min(
        tasks_count,
        std::max<std::size_t>(1, std::thread::hardware_concurrency())
    );

    if (threads <= 1) {
        for (std::size_t i = 0; i < tasks_count; ++i) {
            function(i);
        }

        return;
    }

    std::vector<std::future<void>> futures;
    futures.reserve(threads);

    const auto chunk_size = (tasks_count + threads - 1) / threads;
    for (std::size_t t = 0; t < threads; ++t) {
        futures.push_back(
            std::async(std::launch::async,
                       [t, chunk_size, tasks_count, &function]() {
                           const std::size_t start = t * chunk_size;
                           const std::size_t end = std::min(start + chunk_size, static_cast<std::size_t>(tasks_count));

                           for (std::size_t i = start; i < end; ++i) {
                               function(i);
                           }
                       }
            )
        );
    }

    for (auto &future : futures) {
        future.get();
    }
}

#endif //MAI_CB_2026_UTILS_H
