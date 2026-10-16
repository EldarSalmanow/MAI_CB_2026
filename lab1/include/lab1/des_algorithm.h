#ifndef MAI_CB_2026_DES_ALGORITHM_H
#define MAI_CB_2026_DES_ALGORITHM_H

#include <lab1/feistel_network.h>
#include <lab1/utils.h>


constexpr std::array<std::uint64_t, 64> IP_TABLE = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};

constexpr std::array<std::uint64_t, 64> FP_TABLE = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25
};

constexpr std::array<std::uint64_t, 48> E_TABLE = {
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
};

constexpr std::array<std::array<std::array<std::uint8_t, 16>, 4>, 8> S_BOX = {{
    {
        {
            {14,  4, 13, 1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9, 0,  7},
            { 0, 15,  7, 4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5, 3,  8},
            { 4,  1, 14, 8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10, 5,  0},
            {15, 12,  8, 2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0, 6, 13}
        }
    },

    {
        {
            { 15,  1,  8, 14,  6, 11,  3,  4,  9, 7,  2, 13, 12, 0,  5, 10},
            {  3, 13,  4,  7, 15,  2,  8, 14, 12, 0,  1, 10,  6, 9, 11,  5},
            {  0, 14,  7, 11, 10,  4, 13,  1,  5, 8, 12,  6,  9, 3,  2, 15},
            { 13,  8, 10,  1,  3, 15,  4,  2, 11, 6,  7, 12,  0, 5, 14,  9}
        }
    },

    {
        {
            { 10,  0,  9, 14, 6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
            { 13,  7,  0,  9, 3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
            { 13,  6,  4,  9, 8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
            {  1, 10, 13,  0, 6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12}
        }
    },

    {
        {
            {  7, 13, 14, 3,  0,  6,  9, 10,  1, 2, 8,  5, 11, 12,  4, 15},
            { 13,  8, 11, 5,  6, 15,  0,  3,  4, 7, 2, 12,  1, 10, 14,  9},
            { 10,  6,  9, 0, 12, 11,  7, 13, 15, 1, 3, 14,  5,  2,  8,  4},
            {  3, 15,  0, 6, 10,  1, 13,  8,  9, 4, 5, 11, 12,  7,  2, 14}
        }
    },

    {
        {
            {  2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13, 0, 14,  9},
            { 14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3, 9,  8,  6},
            {  4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6, 3,  0, 14},
            { 11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10, 4,  5,  3}
        }
    },

    {
        {
            { 12,  1, 10, 15, 9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
            { 10, 15,  4,  2, 7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
            {  9, 14, 15,  5, 2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
            {  4,  3,  2, 12, 9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13}
        }
    },

    {
        {
            {  4, 11,  2, 14, 15, 0,  8, 13,  3, 12, 9,  7,  5, 10, 6,  1},
            { 13,  0, 11,  7,  4, 9,  1, 10, 14,  3, 5, 12,  2, 15, 8,  6},
            {  1,  4, 11, 13, 12, 3,  7, 14, 10, 15, 6,  8,  0,  5, 9,  2},
            {  6, 11, 13,  8,  1, 4, 10,  7,  9,  5, 0, 15, 14,  2, 3, 12}
        }
    },

    {
        {
            { 13,  2,  8, 4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7},
            {  1, 15, 13, 8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2},
            {  7, 11,  4, 1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
            {  2,  1, 14, 7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11}
        }
    }
}};

constexpr std::array<std::uint64_t, 32> P_TABLE = {
    16,  7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26,  5, 18, 31, 10,
     2,  8, 24, 14, 32, 27,  3,  9,
    19, 13, 30,  6, 22, 11,  4, 25
};

constexpr std::array<std::uint64_t, 28> PC1_C_TABLE = {
    57, 49, 41, 33, 25, 17,  9,  1,
    58, 50, 42, 34, 26, 18, 10,  2,
    59, 51, 43, 35, 27, 19, 11,  3,
    60, 52, 44, 36
};

constexpr std::array<std::uint64_t, 28> PC1_D_TABLE = {
                    63, 55, 47, 39,
    31, 23, 15,  7, 62, 54, 46, 38,
    30, 22, 14,  6, 61, 53, 45, 37,
    29, 21, 13,  5, 28, 20, 12,  4
};

// constexpr std::array<std::uint64_t, 56> PC1_TABLE = {
//     57, 49, 41, 33, 25, 17,  9,  1,
//     58, 50, 42, 34, 26, 18, 10,  2,
//     59, 51, 43, 35, 27, 19, 11,  3,
//     60, 52, 44, 36, 63, 55, 47, 39,
//     31, 23, 15,  7, 62, 54, 46, 38,
//     30, 22, 14,  6, 61, 53, 45, 37,
//     29, 21, 13,  5, 28, 20, 12,  4
// };

constexpr std::array<std::uint64_t, 48> PC2_TABLE = {
    14, 17, 11, 24,  1,  5,  3, 28,
    15,  6, 21, 10, 23, 19, 12,  4,
    26,  8, 16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32
};

constexpr std::array<std::size_t, 16> SHIFT_SCHEDULE = {
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

class DesKeyExpander : public IKeyExpander {
public:
    auto ExpandKey(
        std::span<const std::uint8_t> base_key
    ) const -> std::vector<std::vector<std::uint8_t>> override {
        if (base_key.size() != 8) {
            throw std::invalid_argument("[ERROR] DES key must be exactly 8 bytes (64 bits)!");
        }

        std::vector<std::vector<std::uint8_t>> round_keys;
        round_keys.reserve(16);

        std::array<std::uint8_t, 4> C{};
        std::array<std::uint8_t, 4> D{};

        PermuteBits(base_key, PC1_C_TABLE, BitOrder::MsbToLsb, IndexBase::OneBased, C);
        PermuteBits(base_key, PC1_D_TABLE, BitOrder::MsbToLsb, IndexBase::OneBased, D);

        for (std::size_t i = 0; i < 16; ++i) {
            const auto shift = SHIFT_SCHEDULE[i];

            std::array<std::uint8_t, 4> next_C{};
            std::array<std::uint8_t, 4> next_D{};

            CircularShiftLeft(C, shift, 28, next_C);
            CircularShiftLeft(D, shift, 28, next_D);

            C = next_C;
            D = next_D;

            std::array<std::uint8_t, 7> cd{};
            cd[0] = C[0];
            cd[1] = C[1];
            cd[2] = C[2];
            cd[3] = (C[3] & 0xF0) | (D[0] >> 4);
            cd[4] = (D[0] << 4)   | (D[1] >> 4);
            cd[5] = (D[1] << 4)   | (D[2] >> 4);
            cd[6] = (D[2] << 4)   | (D[3] >> 4);

            std::vector<std::uint8_t> round_key(6);
            PermuteBits(cd, PC2_TABLE, BitOrder::MsbToLsb, IndexBase::OneBased, round_key);

            round_keys.push_back(std::move(round_key));
        }

        return round_keys;
    }
};

class DesRoundFunction : public IRoundFunction {
public:
    void ProcessBlock(
        std::span<const std::uint8_t> input_block,
        std::span<const std::uint8_t> round_key,
        std::span<std::uint8_t> output_block
    ) const override {
        std::array<std::uint8_t, 6> e_expanded{};
        PermuteBits(input_block, E_TABLE, BitOrder::MsbToLsb, IndexBase::OneBased, e_expanded);

        std::array<std::uint8_t, 6> xored{};
        for (std::size_t i = 0; i < 6; ++i) {
            xored[i] = e_expanded[i] ^ round_key[i];
        }

        std::array<std::uint8_t, 4> sbox_out{};
        for (std::size_t i = 0; i < 8; ++i) {
            std::uint8_t chunk = Extract6BitChunk(xored, i);
            std::uint8_t row = ((chunk & 0x20) >> 4) | (chunk & 0x01);
            std::uint8_t column = (chunk & 0x1E) >> 1;
            std::uint8_t value = S_BOX[i][row][column];

            if (i % 2 == 0) {
                sbox_out[i / 2] = static_cast<std::uint8_t>(value << 4);
            } else {
                sbox_out[i / 2] |= value;
            }
        }

        PermuteBits(sbox_out, P_TABLE, BitOrder::MsbToLsb, IndexBase::OneBased, output_block);
    }
};

class DESAlgorithm : public ISymmetricBlockCipher {
public:
    DESAlgorithm() : network_(
        std::make_unique<DesKeyExpander>(),
        std::make_unique<DesRoundFunction>()
    ) {}

public:
    auto EncryptBlock(
        std::span<const std::uint8_t> input,
        std::span<std::uint8_t> output
    ) const -> void override {
        std::array<std::uint8_t, 8> ip_out{};
        PermuteBits(input, IP_TABLE, BitOrder::MsbToLsb, IndexBase::OneBased, ip_out);

        std::array<std::uint8_t, 8> feistel_out{};
        network_.EncryptBlock(ip_out, feistel_out);

        PermuteBits(feistel_out, FP_TABLE, BitOrder::MsbToLsb, IndexBase::OneBased, output);
    }

    auto DecryptBlock(
        std::span<const std::uint8_t> input,
        std::span<std::uint8_t> output
    ) const -> void override {
        std::array<std::uint8_t, 8> ip_out{};
        PermuteBits(input, IP_TABLE, BitOrder::MsbToLsb, IndexBase::OneBased, ip_out);

        std::array<std::uint8_t, 8> feistel_out{};
        network_.DecryptBlock(ip_out, feistel_out);

        PermuteBits(feistel_out, FP_TABLE, BitOrder::MsbToLsb, IndexBase::OneBased, output);
    }

    auto SetEncryptionKey(
        std::span<const std::uint8_t> key
    ) -> void override {
        if (key.size() != 8) {
            throw std::runtime_error("[ERROR] DES key must be exactly 64 bits!");
        }

        network_.SetEncryptionKey(key);
    }

    auto SetDecryptionKey(
        std::span<const std::uint8_t> key
    ) -> void override {
        if (key.size() != 8) {
            throw std::invalid_argument("[ERROR] DES key must be exactly 64 bits!");
        }

        network_.SetDecryptionKey(key);
    }

    auto BlockSize() const -> std::size_t override {
        return 8;
    }

private:
    FeistelNetwork<8> network_;
};

#endif //MAI_CB_2026_DES_ALGORITHM_H
