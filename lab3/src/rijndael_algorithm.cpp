#include <lab3/rijndael_algorithm.h>

#include <array>


namespace crypto::symmetric {

    constexpr auto RotL(
        const std::uint32_t b,
        const std::uint64_t k
    ) -> std::uint32_t {
        return (b << k) | (b >> (32 - k));
    }

    constexpr auto RotR(
        const std::uint32_t b,
        const std::uint64_t k
    ) -> std::uint32_t {
        return (b >> k) | (b << (32 - k));
    }

    RijndaelContext::RijndaelContext(
        BlockLength block_length,
        KeyLength key_length,
        std::uint8_t gf_modulus,
        galois::GFService gf_service
    ) : block_length_(block_length),
        key_length_(key_length),
        gf_modulus_(gf_modulus),
        gf_service_(gf_service) {
        if (!gf_service_.IsIrreducible(gf_modulus_)) {
            throw galois::ReducibleModulusException();
        }
    }

    auto RijndaelContext::BlockSize() const -> std::size_t {
        return static_cast<std::size_t>(block_length_);
    }

    auto RijndaelContext::KeySize() const -> std::size_t {
        return static_cast<std::size_t>(key_length_);
    }

    auto RijndaelContext::RoundsCount() const -> std::size_t {
        return std::max(BlockSize() / 4, KeySize() / 4) + 6;
    }

    auto RijndaelContext::Modulus() const -> std::uint8_t {
        return gf_modulus_;
    }

    auto RijndaelContext::GF() const -> const galois::GFService & {
        return gf_service_;
    }

    auto RijndaelContext::SBox() const -> const std::vector<std::uint8_t> & {

    }

    auto RijndaelContext::InvSBox() const -> const std::vector<std::uint8_t> & {}

    auto RijndaelContext::InitializeSBoxes() const -> void {
        if (sboxes_initialized_) {
            return;
        }

        auto rotl8 = [] (const std::uint8_t b, const std::uint64_t k) -> std::uint8_t {
            return (b << k) | (b >> (8 - k));
        };

        auto sbox_i = [&] (const std::uint8_t b) -> std::uint8_t {
            const auto rotl1 = rotl8(b, 1);
            const auto rotl2 = rotl8(b, 2);
            const auto rotl3 = rotl8(b, 3);
            const auto rotl4 = rotl8(b, 4);

            auto result = b;
            result = gf_service_.Add(result, rotl1);
            result = gf_service_.Add(result, rotl2);
            result = gf_service_.Add(result, rotl3);
            result = gf_service_.Add(result, rotl4);
            result = gf_service_.Add(result, 0x63);

            return result;
        };

        auto inv_sbox_i = [&] (const std::uint8_t b) -> std::uint8_t {
            const auto rotl1 = rotl8(b, 1);
            const auto rotl3 = rotl8(b, 3);
            const auto rotl6 = rotl8(b, 6);

            auto result = rotl1;
            result = gf_service_.Add(result, rotl3);
            result = gf_service_.Add(result, rotl6);
            result = gf_service_.Add(result, 0x05);

            return result;
        };

        for (std::uint16_t i = 0; i <= 255; ++i) {
            const auto b = i == 0 ? 0 : gf_service_.Inverse(i, gf_modulus_);

            sbox_[i] = sbox_i(b);
        }

        for (std::uint16_t i = 0; i <= 255; ++i) {
            const auto b = inv_sbox_i(i);

            inv_sbox_[i] = b == 0 ? 0 : gf_service_.Inverse(b, gf_modulus_);
        }

        s = true;
    }

    RijndaelKeyExpander::RijndaelKeyExpander(
        std::shared_ptr<const RijndaelContext> context
    ) : context_(std::move(context)) {}

    auto RijndaelKeyExpander::ExpandKey(
        std::span<const std::uint8_t> base_key
    ) const -> std::vector<std::vector<std::uint8_t>> {
        // std::vector<

        std::vector<std::vector<std::uint8_t>> keys;

        const auto rotw = [] () {

        };
        const auto subw = [] () {

        };

        

        return keys;
    }

    RijndaelRoundFunction::RijndaelRoundFunction(
        Direction direction,
        std::shared_ptr<const RijndaelContext> context
    ) : direction_(direction),
        context_(std::move(context)) {}

    auto RijndaelRoundFunction::ProcessBlock(
        std::span<const std::uint8_t> input_block,
        std::span<const std::uint8_t> round_key,
        std::span<std::uint8_t> output_block
    ) const -> void {

    }

    auto RijndaelRoundFunction::ProcessFinalBlock(
        std::span<const std::uint8_t> input_block,
        std::span<const std::uint8_t> round_key,
        std::span<std::uint8_t> output_block
    ) const -> void {

    }

    auto RijndaelRoundFunction::ProcessRound(
        std::span<const std::uint8_t> input_block,
        std::span<const std::uint8_t> round_key,
        std::span<std::uint8_t> output_block,
        bool with_mix_columns
    ) const -> void {

    }

    auto RijndaelRoundFunction::SubBytes(
        std::span<std::uint8_t> state
    ) const -> void {
        for (auto &byte : state) {
            byte = context_->SBox()[byte];
        }
    }

    auto RijndaelRoundFunction::InvSubBytes(
        std::span<std::uint8_t> state
    ) const -> void {
        for (auto &byte : state) {
            byte = context_->InvSBox()[byte];
        }
    }

    auto RijndaelRoundFunction::ShiftRows(
        std::span<std::uint8_t> state
    ) const -> void {
        const std::array<std::uint8_t, 4> shifts = {0, 1, 2, 3};
        // const auto shifts = {0, 1, 3, 4}; n_b == 8 TODO

        for (std::uint8_t i = 0; i < 4; ++i) {
            std::uint32_t row = 0;

            for (std::uint8_t j = 0; j < 4; ++j) {
                row = (row << 1) | state[i + 4 * j];
            }

            row = RotL(row, shifts[i]);

            for (std::int8_t j = 4; j >= 0; --j) {
                state[i + 4 * j] = row & 0x1;

                row >>= 1;
            }
        }
    }

    auto RijndaelRoundFunction::InvShiftRows(
        std::span<std::uint8_t> state
    ) const -> void {
        const std::array<std::uint8_t, 4> shifts = {0, 1, 2, 3};
        // const auto shifts = {0, 1, 3, 4}; n_b == 8 TODO

        for (std::uint8_t i = 0; i < 4; ++i) {
            std::uint32_t row = 0;

            for (std::uint8_t j = 0; j < 4; ++j) {
                row = (row << 1) | state[i + 4 * j];
            }

            row = RotR(row, shifts[i]);

            for (std::int8_t j = 4; j >= 0; --j) {
                state[i + 4 * j] = row & 0x1;

                row >>= 1;
            }
        }
    }

    auto RijndaelRoundFunction::MixColumns(
        std::span<std::uint8_t> state
    ) const -> void {
        std::array<std::array<std::uint8_t, 4>, 4> MIX_COLUMNS_MATRIX;
        MIX_COLUMNS_MATRIX[0] = {0x02, 0x01, 0x01, 0x03};
        MIX_COLUMNS_MATRIX[1] = {0x03, 0x02, 0x01, 0x01};
        MIX_COLUMNS_MATRIX[2] = {0x01, 0x03, 0x02, 0x01};
        MIX_COLUMNS_MATRIX[3] = {0x01, 0x01, 0x03, 0x02};

        for (std::uint64_t i = 0; i < 4; ++i) {
            for (std::uint64_t j = 0; j < 4; ++j) {
                state[j + 4 * i] = context_->GF().Multiply(MIX_COLUMNS_MATRIX[i][0], state[4 * i], context_->Modulus());

                for (std::uint64_t k = 1; k < 4; ++k) {
                    const auto multiply = context_->GF().Multiply(
                        MIX_COLUMNS_MATRIX[i][k],
                        state[k + 4 * i],
                        context_->Modulus()
                    );

                    state[j + 4 * i] = context_->GF().Add(state[j + 4 * i], multiply);
                }
            }
        }
    }

    auto RijndaelRoundFunction::InvMixColumns(
        std::span<std::uint8_t> state
    ) const -> void {
        std::array<std::array<std::uint8_t, 4>, 4> INV_MIX_COLUMNS_MATRIX;
        INV_MIX_COLUMNS_MATRIX[0] = {0x0E, 0x0B, 0x0D, 0x09};
        INV_MIX_COLUMNS_MATRIX[1] = {0x09, 0x0E, 0x0B, 0x0D};
        INV_MIX_COLUMNS_MATRIX[2] = {0x0D, 0x09, 0x0E, 0x0B};
        INV_MIX_COLUMNS_MATRIX[3] = {0x0B, 0x0D, 0x09, 0x0E};

        for (std::uint64_t i = 0; i < 4; ++i) {
            for (std::uint64_t j = 0; j < 4; ++j) {
                state[j + 4 * i] = context_->GF().Multiply(INV_MIX_COLUMNS_MATRIX[i][0], state[4 * i], context_->Modulus());

                for (std::uint64_t k = 1; k < 4; ++k) {
                    const auto multiply = context_->GF().Multiply(
                        INV_MIX_COLUMNS_MATRIX[i][k],
                        state[k + 4 * i],
                        context_->Modulus()
                    );

                    state[j + 4 * i] = context_->GF().Add(state[j + 4 * i], multiply);
                }
            }
        }
    }

    auto RijndaelRoundFunction::AddRoundKey(
        std::span<std::uint8_t> state,
        std::span<const std::uint8_t> round_key
    ) const -> void {
        for (std::uint64_t i = 0; i < state.size(); ++i) {
            state[i] = context_->GF().Add(state[i], round_key[i]);
        }
    }

    RijndaelAlgorithm::RijndaelAlgorithm(
        BlockLength block_length,
        KeyLength key_length,
        std::uint8_t gf_modulus,
        galois::GFService gf_service
    ) : context_(std::make_shared<RijndaelContext>(block_length, key_length, gf_modulus, gf_service)),
        key_expander_(context_),
        encrypt_round_(RijndaelRoundFunction::Direction::Encrypt, context_),
        decrypt_round_(RijndaelRoundFunction::Direction::Decrypt, context_) {}

    auto RijndaelAlgorithm::EncryptBlock(
        std::span<const std::uint8_t> input,
        std::span<std::uint8_t> output
    ) const -> void {

    }

    auto RijndaelAlgorithm::DecryptBlock(
        std::span<const std::uint8_t> input,
        std::span<std::uint8_t> output
    ) const -> void {

    }

    auto RijndaelAlgorithm::SetEncryptionKey(
        std::span<const std::uint8_t> key
    ) -> void {
        round_keys_ = key_expander_.ExpandKey(key);
    }

    auto RijndaelAlgorithm::SetDecryptionKey(
        std::span<const std::uint8_t> key
    ) -> void {

    }

    auto RijndaelAlgorithm::BlockSize() const -> std::size_t {
        return context_->BlockSize();
    }

}
