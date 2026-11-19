#include <lab3/rijndael_algorithm.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cstring>
#include <stdexcept>
#include <utility>


namespace crypto::symmetric {

    RijndaelState::RijndaelState(
        std::span<const std::uint8_t> input
    ) : columns_count_(input.size() / 4) {
        if (input.size() != static_cast<std::size_t>(BlockLength::Bits128)
            && input.size() != static_cast<std::size_t>(BlockLength::Bits192)
            && input.size() != static_cast<std::size_t>(BlockLength::Bits256)) {
            throw std::invalid_argument("[ERROR] Invalid Rijndael block size!");
        }

        std::copy(input.begin(), input.end(), bytes_.begin());
    }

    auto RijndaelState::ColumnsCount() const -> std::size_t {
        return columns_count_;
    }

    auto RijndaelState::Bytes() -> std::span<std::uint8_t> {
        return std::span<std::uint8_t>(bytes_).first(4 * columns_count_);
    }

    auto RijndaelState::Bytes() const -> std::span<const std::uint8_t> {
        return std::span<const std::uint8_t>(bytes_).first(4 * columns_count_);
    }

    auto RijndaelState::At(
        std::size_t row,
        std::size_t column
    ) -> std::uint8_t & {
        return bytes_[row + 4 * column];
    }

    auto RijndaelState::Store(
        std::span<std::uint8_t> output
    ) const -> void {
        const auto bytes = Bytes();

        if (output.size() != bytes.size()) {
            throw std::invalid_argument("[ERROR] Invalid Rijndael block size!");
        }

        std::memmove(output.data(), bytes.data(), bytes.size());
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
        if (block_length_ != BlockLength::Bits128
            && block_length_ != BlockLength::Bits192
            && block_length_ != BlockLength::Bits256) {
            throw std::invalid_argument("[ERROR] Unsupported Rijndael block length!");
        }

        if (key_length_ != KeyLength::Bits128
            && key_length_ != KeyLength::Bits192
            && key_length_ != KeyLength::Bits256) {
            throw std::invalid_argument("[ERROR] Unsupported Rijndael key length!");
        }

        if (!gf_service_.IsIrreducible(gf_modulus_)) {
            throw galois::ReducibleModulusException();
        }

        row_shifts_ = ColumnsCount() == 8
            ? std::array<std::size_t, 4>{0, 1, 3, 4}
            : std::array<std::size_t, 4>{0, 1, 2, 3};

        for (std::size_t i = 1; i < row_shifts_.size(); ++i) {
            inv_row_shifts_[i] = ColumnsCount() - row_shifts_[i];
        }
    }

    auto RijndaelContext::BlockSize() const -> std::size_t {
        return static_cast<std::size_t>(block_length_);
    }

    auto RijndaelContext::KeySize() const -> std::size_t {
        return static_cast<std::size_t>(key_length_);
    }

    auto RijndaelContext::ColumnsCount() const -> std::size_t {
        return BlockSize() / 4;
    }

    auto RijndaelContext::KeyWordsCount() const -> std::size_t {
        return KeySize() / 4;
    }

    auto RijndaelContext::RoundsCount() const -> std::size_t {
        return std::max(ColumnsCount(), KeyWordsCount()) + 6;
    }

    auto RijndaelContext::Modulus() const -> std::uint8_t {
        return gf_modulus_;
    }

    auto RijndaelContext::GF() const -> const galois::GFService & {
        return gf_service_;
    }

    auto RijndaelContext::RowShifts() const -> const std::array<std::size_t, 4> & {
        return row_shifts_;
    }

    auto RijndaelContext::InvRowShifts() const -> const std::array<std::size_t, 4> & {
        return inv_row_shifts_;
    }

    auto RijndaelContext::SBox() const -> const std::array<std::uint8_t, 256> & {
        InitializeSBoxes();

        return sbox_;
    }

    auto RijndaelContext::InvSBox() const -> const std::array<std::uint8_t, 256> & {
        InitializeSBoxes();

        return inv_sbox_;
    }

    auto RijndaelContext::InitializeSBoxes() const -> void {
        std::call_once(sboxes_once_flag_, [this] {
            for (std::size_t i = 0; i < sbox_.size(); ++i) {
                const auto byte = static_cast<std::uint8_t>(i);
                const auto inverse = byte == 0 ? std::uint8_t{0} : gf_service_.Inverse(byte, gf_modulus_);
                const auto transformed = InvAffineTransform(byte);

                sbox_[i] = AffineTransform(inverse);
                inv_sbox_[i] = transformed == 0 ? std::uint8_t{0} : gf_service_.Inverse(transformed, gf_modulus_);
            }
        });
    }

    auto RijndaelContext::AffineTransform(
        std::uint8_t byte
    ) const -> std::uint8_t {
        auto result = byte;

        for (int shift = 1; shift <= 4; ++shift) {
            result = gf_service_.Add(result, std::rotl(byte, shift));
        }

        return gf_service_.Add(result, 0x63);
    }

    auto RijndaelContext::InvAffineTransform(
        std::uint8_t byte
    ) const -> std::uint8_t {
        auto result = gf_service_.Add(std::rotl(byte, 1), std::rotl(byte, 3));
        result = gf_service_.Add(result, std::rotl(byte, 6));

        return gf_service_.Add(result, 0x05);
    }

    RijndaelKeyExpander::RijndaelKeyExpander(
        std::shared_ptr<const RijndaelContext> context
    ) : context_(std::move(context)) {
        if (!context_) {
            throw std::invalid_argument("[ERROR] Rijndael context must not be null!");
        }
    }

    auto RijndaelKeyExpander::ExpandKey(
        std::span<const std::uint8_t> base_key
    ) const -> std::vector<std::vector<std::uint8_t>> {
        if (base_key.size() != context_->KeySize()) {
            throw std::invalid_argument("[ERROR] Invalid Rijndael key size!");
        }

        const auto key_words_count = context_->KeyWordsCount();
        const auto columns_count = context_->ColumnsCount();
        const auto rounds_count = context_->RoundsCount();

        std::vector<Word> words(columns_count * (rounds_count + 1));

        for (std::size_t i = 0; i < key_words_count; ++i) {
            for (std::size_t j = 0; j < 4; ++j) {
                words[i][j] = base_key[4 * i + j];
            }
        }

        std::uint8_t round_constant = 0x01;

        for (std::size_t i = key_words_count; i < words.size(); ++i) {
            auto word = words[i - 1];

            if (i % key_words_count == 0) {
                std::rotate(word.begin(), word.begin() + 1, word.end());
                SubWord(word);

                word[0] = context_->GF().Add(word[0], round_constant);
                round_constant = context_->GF().MultiplyUnchecked(round_constant, 0x02, context_->Modulus());
            } else if (key_words_count == 8 && i % key_words_count == 4) {
                SubWord(word);
            }

            for (std::size_t j = 0; j < 4; ++j) {
                words[i][j] = context_->GF().Add(words[i - key_words_count][j], word[j]);
            }
        }

        std::vector<std::vector<std::uint8_t>> keys(rounds_count + 1, std::vector<std::uint8_t>(context_->BlockSize()));

        for (std::size_t i = 0; i < keys.size(); ++i) {
            for (std::size_t j = 0; j < keys[i].size(); ++j) {
                keys[i][j] = words[i * columns_count + j / 4][j % 4];
            }
        }

        return keys;
    }

    auto RijndaelKeyExpander::SubWord(
        Word &word
    ) const -> void {
        const auto &sbox = context_->SBox();

        for (auto &byte : word) {
            byte = sbox[byte];
        }
    }

    RijndaelRoundFunction::RijndaelRoundFunction(
        std::shared_ptr<const RijndaelContext> context
    ) : context_(std::move(context)) {
        if (!context_) {
            throw std::invalid_argument("[ERROR] Rijndael context must not be null!");
        }
    }

    auto RijndaelRoundFunction::ProcessBlock(
        std::span<const std::uint8_t> input_block,
        std::span<const std::uint8_t> round_key,
        std::span<std::uint8_t> output_block
    ) const -> void {
        ValidateBuffers(input_block, output_block);

        RijndaelState state(input_block);

        ApplyRound(state, round_key);

        state.Store(output_block);
    }

    auto RijndaelRoundFunction::ProcessFinalBlock(
        std::span<const std::uint8_t> input_block,
        std::span<const std::uint8_t> round_key,
        std::span<std::uint8_t> output_block
    ) const -> void {
        ValidateBuffers(input_block, output_block);

        RijndaelState state(input_block);

        ApplyFinalRound(state, round_key);

        state.Store(output_block);
    }

    auto RijndaelRoundFunction::ApplyInitialKey(
        RijndaelState &state,
        std::span<const std::uint8_t> round_key
    ) const -> void {
        ValidateState(state, round_key);

        AddRoundKey(state, round_key);
    }

    auto RijndaelRoundFunction::ValidateState(
        const RijndaelState &state,
        std::span<const std::uint8_t> round_key
    ) const -> void {
        if (state.Bytes().size() != context_->BlockSize()) {
            throw std::invalid_argument("[ERROR] Invalid Rijndael block size!");
        }

        if (round_key.size() != context_->BlockSize()) {
            throw std::invalid_argument("[ERROR] Invalid Rijndael round key size!");
        }
    }

    auto RijndaelRoundFunction::SubstituteBytes(
        RijndaelState &state,
        const std::array<std::uint8_t, 256> &sbox
    ) const -> void {
        for (auto &byte : state.Bytes()) {
            byte = sbox[byte];
        }
    }

    auto RijndaelRoundFunction::ShiftRows(
        RijndaelState &state,
        const std::array<std::size_t, 4> &shifts
    ) const -> void {
        const auto columns_count = state.ColumnsCount();

        for (std::size_t i = 1; i < shifts.size(); ++i) {
            std::array<std::uint8_t, 8> row{};

            for (std::size_t j = 0; j < columns_count; ++j) {
                row[j] = state.At(i, j);
            }

            for (std::size_t j = 0; j < columns_count; ++j) {
                state.At(i, j) = row[(j + shifts[i]) % columns_count];
            }
        }
    }

    auto RijndaelRoundFunction::MixColumns(
        RijndaelState &state,
        const Matrix &matrix
    ) const -> void {
        for (std::size_t i = 0; i < state.ColumnsCount(); ++i) {
            const Column column = {
                state.At(0, i), state.At(1, i), state.At(2, i), state.At(3, i)
            };

            for (std::size_t j = 0; j < column.size(); ++j) {
                std::uint8_t result = 0;

                for (std::size_t k = 0; k < column.size(); ++k) {
                    const auto product = context_->GF().MultiplyUnchecked(matrix[j][k], column[k], context_->Modulus());

                    result = context_->GF().Add(result, product);
                }

                state.At(j, i) = result;
            }
        }
    }

    auto RijndaelRoundFunction::AddRoundKey(
        RijndaelState &state,
        std::span<const std::uint8_t> round_key
    ) const -> void {
        const auto bytes = state.Bytes();

        for (std::size_t i = 0; i < bytes.size(); ++i) {
            bytes[i] = context_->GF().Add(bytes[i], round_key[i]);
        }
    }

    auto RijndaelRoundFunction::ValidateBuffers(
        std::span<const std::uint8_t> input,
        std::span<std::uint8_t> output
    ) const -> void {
        if (input.size() != context_->BlockSize() || output.size() != context_->BlockSize()) {
            throw std::invalid_argument("[ERROR] Invalid Rijndael block size!");
        }
    }

    RijndaelEncryptRound::RijndaelEncryptRound(
        std::shared_ptr<const RijndaelContext> context
    ) : RijndaelRoundFunction(std::move(context)) {}

    auto RijndaelEncryptRound::ApplyRound(
        RijndaelState &state,
        std::span<const std::uint8_t> round_key
    ) const -> void {
        static constexpr Matrix MIX_COLUMNS_MATRIX = {{
            {0x02, 0x03, 0x01, 0x01},
            {0x01, 0x02, 0x03, 0x01},
            {0x01, 0x01, 0x02, 0x03},
            {0x03, 0x01, 0x01, 0x02}
        }};

        ValidateState(state, round_key);

        SubstituteBytes(state, context_->SBox());
        ShiftRows(state, context_->RowShifts());
        MixColumns(state, MIX_COLUMNS_MATRIX);
        AddRoundKey(state, round_key);
    }

    auto RijndaelEncryptRound::ApplyFinalRound(
        RijndaelState &state,
        std::span<const std::uint8_t> round_key
    ) const -> void {
        ValidateState(state, round_key);

        SubstituteBytes(state, context_->SBox());
        ShiftRows(state, context_->RowShifts());
        AddRoundKey(state, round_key);
    }

    RijndaelDecryptRound::RijndaelDecryptRound(
        std::shared_ptr<const RijndaelContext> context
    ) : RijndaelRoundFunction(std::move(context)) {}

    auto RijndaelDecryptRound::ApplyRound(
        RijndaelState &state,
        std::span<const std::uint8_t> round_key
    ) const -> void {
        static constexpr Matrix INV_MIX_COLUMNS_MATRIX = {{
            {0x0E, 0x0B, 0x0D, 0x09},
            {0x09, 0x0E, 0x0B, 0x0D},
            {0x0D, 0x09, 0x0E, 0x0B},
            {0x0B, 0x0D, 0x09, 0x0E}
        }};

        ValidateState(state, round_key);

        ShiftRows(state, context_->InvRowShifts());
        SubstituteBytes(state, context_->InvSBox());
        AddRoundKey(state, round_key);
        MixColumns(state, INV_MIX_COLUMNS_MATRIX);
    }

    auto RijndaelDecryptRound::ApplyFinalRound(
        RijndaelState &state,
        std::span<const std::uint8_t> round_key
    ) const -> void {
        ValidateState(state, round_key);

        ShiftRows(state, context_->InvRowShifts());
        SubstituteBytes(state, context_->InvSBox());
        AddRoundKey(state, round_key);
    }

    RijndaelAlgorithm::RijndaelAlgorithm(
        BlockLength block_length,
        KeyLength key_length,
        std::uint8_t gf_modulus,
        galois::GFService gf_service
    ) : context_(std::make_shared<RijndaelContext>(block_length, key_length, gf_modulus, gf_service)),
        key_expander_(context_),
        encrypt_round_(context_),
        decrypt_round_(context_) {}

    auto RijndaelAlgorithm::EncryptBlock(
        std::span<const std::uint8_t> input,
        std::span<std::uint8_t> output
    ) const -> void {
        ValidateBlock(input, output);

        RijndaelState state(input);

        encrypt_round_.ApplyInitialKey(state, round_keys_.front());

        for (std::size_t round = 1; round < context_->RoundsCount(); ++round) {
            encrypt_round_.ApplyRound(state, round_keys_[round]);
        }

        encrypt_round_.ApplyFinalRound(state, round_keys_.back());

        state.Store(output);
    }

    auto RijndaelAlgorithm::DecryptBlock(
        std::span<const std::uint8_t> input,
        std::span<std::uint8_t> output
    ) const -> void {
        ValidateBlock(input, output);

        RijndaelState state(input);

        decrypt_round_.ApplyInitialKey(state, round_keys_.back());

        for (std::size_t round = context_->RoundsCount() - 1; round > 0; --round) {
            decrypt_round_.ApplyRound(state, round_keys_[round]);
        }

        decrypt_round_.ApplyFinalRound(state, round_keys_.front());

        state.Store(output);
    }

    auto RijndaelAlgorithm::SetEncryptionKey(
        std::span<const std::uint8_t> key
    ) -> void {
        SetKey(key);
    }

    auto RijndaelAlgorithm::SetDecryptionKey(
        std::span<const std::uint8_t> key
    ) -> void {
        SetKey(key);
    }

    auto RijndaelAlgorithm::BlockSize() const -> std::size_t {
        return context_->BlockSize();
    }

    auto RijndaelAlgorithm::ValidateBlock(
        std::span<const std::uint8_t> input,
        std::span<std::uint8_t> output
    ) const -> void {
        if (input.size() != BlockSize() || output.size() != BlockSize()) {
            throw std::invalid_argument("[ERROR] Invalid Rijndael block size!");
        }

        if (round_keys_.empty()) {
            throw std::runtime_error("[ERROR] Rijndael key is not set!");
        }
    }

    auto RijndaelAlgorithm::SetKey(
        std::span<const std::uint8_t> key
    ) -> void {
        round_keys_ = key_expander_.ExpandKey(key);
    }

} // namespace crypto::symmetric
