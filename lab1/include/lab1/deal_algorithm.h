#ifndef MAI_CB_2026_DEAL_ALGORITHM_H
#define MAI_CB_2026_DEAL_ALGORITHM_H

#include <lab1/des_algorithm.h>


class DesToRoundFunctionAdapter : public IRoundFunction {
public:
    void ProcessBlock(
        std::span<const std::uint8_t> input_block,
        std::span<const std::uint8_t> round_key,
        std::span<std::uint8_t> output_block
    ) const override {
        if (input_block.size() != 8 || round_key.size() != 8 || output_block.size() != 8) {
            throw std::invalid_argument("[ERROR] DEAL round inputs, keys and outputs must be 8 bytes!");
        }

        DESAlgorithm des_algorithm;

        des_algorithm.SetEncryptionKey(round_key);

        des_algorithm.EncryptBlock(input_block, output_block);
    }
};

class DealKeyExpander : public IKeyExpander {
public:
    auto ExpandKey(
        std::span<const std::uint8_t> base_key
    ) const -> std::vector<std::vector<std::uint8_t>> override {
        if (base_key.size() != 16) {
            throw std::invalid_argument("[ERROR] DEAL-128 requires exactly a 128-bit key!");
        }

        constexpr std::array<std::uint8_t, 8> fixed_key{
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
        };

        DESAlgorithm des;
        des.SetEncryptionKey(fixed_key);

        auto K_0 = base_key.subspan(0, 8);
        auto K_1 = base_key.subspan(8, 8);

        std::vector<std::vector<std::uint8_t>> round_keys(6, std::vector<std::uint8_t>(8));

        std::array<std::uint8_t, 8> previous_rk{};
        std::array<std::uint8_t, 8> current_input{};

        for (std::size_t i = 0; i < 6; ++i) {
            auto current_K = (i % 2 == 0) ? K_0 : K_1;

            for (std::size_t j = 0; j < 8; ++j) {
                current_input[j] = current_K[j] ^ previous_rk[j];
            }

            if (i >= 2) {
                std::uint8_t C_i = static_cast<std::uint8_t>(0x80u >> (i - 2));

                current_input[0] ^= C_i;
            }

            des.EncryptBlock(current_input, previous_rk);

            std::copy(previous_rk.begin(), previous_rk.end(), round_keys[i].begin());
        }

        return round_keys;
    }
};

class DEALAlgorithm : public ISymmetricBlockCipher {
public:
    DEALAlgorithm() : network_(
        std::make_unique<DealKeyExpander>(),
        std::make_unique<DesToRoundFunctionAdapter>()
    ) {}

public:
    auto EncryptBlock(
        std::span<const std::uint8_t> input,
        std::span<std::uint8_t> output
    ) const -> void override {
        if (input.size() != 16 || output.size() != 16) {
            throw std::invalid_argument("[ERROR] DEAL requires 16-byte blocks!");
        }

        std::array<std::uint8_t, 16> swapped{};

        std::copy_n(input.begin() + 8, 8, swapped.begin());
        std::copy_n(input.begin(), 8, swapped.begin() + 8);

        network_.EncryptBlock(swapped, output);
    }

    auto DecryptBlock(
        std::span<const std::uint8_t> input,
        std::span<std::uint8_t> output
    ) const -> void override {
        if (input.size() != 16 || output.size() != 16) {
            throw std::invalid_argument("[ERROR] DEAL requires 16-byte blocks!");
        }

        std::array<std::uint8_t, 16> swapped{};

        network_.DecryptBlock(input, swapped);

        std::copy_n(swapped.begin() + 8, 8, output.begin());
        std::copy_n(swapped.begin(), 8, output.begin() + 8);
    }

    auto SetEncryptionKey(
        std::span<const std::uint8_t> key
    ) -> void override {
        network_.SetEncryptionKey(key);
    }

    auto SetDecryptionKey(
        std::span<const std::uint8_t> key
    ) -> void override {
        network_.SetDecryptionKey(key);
    }

    auto BlockSize() const -> std::size_t override {
        return 16;
    }

private:
    FeistelNetwork<16> network_;
};

#endif //MAI_CB_2026_DEAL_ALGORITHM_H
