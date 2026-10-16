#ifndef MAI_CB_2026_FEISTEL_NETWORK_H
#define MAI_CB_2026_FEISTEL_NETWORK_H

#include <lab1/block_cipher.h>
#include <lab1/key_expander.h>
#include <lab1/round_function.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <utility>


template<std::size_t BlockBytes>
class FeistelNetwork : public ISymmetricBlockCipher {
public:
    static_assert(BlockBytes > 0 && BlockBytes % 2 == 0,
                  "[ERROR] Block bytes in Feistel network must be positive & even!");

public:
    FeistelNetwork(
        std::unique_ptr<IKeyExpander> key_expander,
        std::unique_ptr<IRoundFunction> round_function
    ) : key_expander_(std::move(key_expander)),
        round_function_(std::move(round_function)) {}

public:
    auto EncryptBlock(
        std::span<const std::uint8_t> input,
        std::span<std::uint8_t> output
    ) const -> void override {
        ProcessFeistel(input, output, true);
    }

    auto DecryptBlock(
        std::span<const std::uint8_t> input,
        std::span<std::uint8_t> output
    ) const -> void override {
        ProcessFeistel(input, output, false);
    }

    auto SetEncryptionKey(
        std::span<const std::uint8_t> key
    ) -> void override {
        round_keys_ = key_expander_->ExpandKey(key);
    }

    auto SetDecryptionKey(
        std::span<const std::uint8_t> key
    ) -> void override {
        round_keys_ = key_expander_->ExpandKey(key);
    }

    auto BlockSize() const -> std::size_t override {
        return BlockBytes;
    }

private:
    auto ProcessFeistel(
        std::span<const std::uint8_t> input,
        std::span<std::uint8_t> output,
        bool is_encrypt
    ) const -> void {
        constexpr auto half = BlockBytes / 2;

        if (input.size() != BlockBytes
         || output.size() != BlockBytes) {
            throw std::runtime_error("[ERROR] Invalid block size!");
        }

        if (round_keys_.empty()) {
            throw std::runtime_error("[ERROR] Key is not set!");
        }

        std::array<std::uint8_t, half> L{};
        std::array<std::uint8_t, half> R{};
        std::array<std::uint8_t, half> f_result{};
        std::copy_n(input.begin(), half, L.begin());
        std::copy_n(input.begin() + half, half, R.begin());

        const auto rounds_count = round_keys_.size();

        for (std::size_t i = 0; i < rounds_count; ++i) {
            const auto key_index = is_encrypt ? i : (rounds_count - 1 - i);

            round_function_->ProcessBlock(R, round_keys_[key_index], f_result);

            for(std::size_t j = 0; j < half; ++j) {
                const auto temp = R[j];

                R[j] = L[j] ^ f_result[j];
                L[j] = temp;
            }
        }

        std::copy_n(R.begin(), half, output.begin());
        std::copy_n(L.begin(), half, output.begin() + half);
    }

private:
    std::unique_ptr<IKeyExpander> key_expander_;
    std::unique_ptr<IRoundFunction> round_function_;
    std::vector<std::vector<std::uint8_t>> round_keys_;
};

#endif //MAI_CB_2026_FEISTEL_NETWORK_H
