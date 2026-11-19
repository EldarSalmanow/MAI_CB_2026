#ifndef MAI_CB_2026_RIJNDAEL_ALGORITHM_H
#define MAI_CB_2026_RIJNDAEL_ALGORITHM_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <span>
#include <vector>

#include <lab3/galois_field.h>

#include "../../../lab1/include/lab1/block_cipher.h"
#include "../../../lab1/include/lab1/key_expander.h"
#include "../../../lab1/include/lab1/round_function.h"

namespace crypto::symmetric {

    enum class BlockLength : std::size_t {
        Bits128 = 16,
        Bits192 = 24,
        Bits256 = 32
    };

    enum class KeyLength : std::size_t {
        Bits128 = 16,
        Bits192 = 24,
        Bits256 = 32
    };

    class RijndaelState {
    public:
        explicit RijndaelState(
            std::span<const std::uint8_t> input
        );

    public:
        auto ColumnsCount() const -> std::size_t;

        auto Bytes() -> std::span<std::uint8_t>;

        auto Bytes() const -> std::span<const std::uint8_t>;

        auto At(
            std::size_t row,
            std::size_t column
        ) -> std::uint8_t &;

        auto Store(
            std::span<std::uint8_t> output
        ) const -> void;

    private:
        std::array<std::uint8_t, 32> bytes_{};
        std::size_t columns_count_;
    };

    class RijndaelContext {
    public:
        RijndaelContext(
            BlockLength block_length,
            KeyLength key_length,
            std::uint8_t gf_modulus,
            galois::GFService gf_service = {}
        );

    public:
        auto BlockSize() const -> std::size_t;

        auto KeySize() const -> std::size_t;

        auto ColumnsCount() const -> std::size_t;

        auto KeyWordsCount() const -> std::size_t;

        auto RoundsCount() const -> std::size_t;

        auto Modulus() const -> std::uint8_t;

        auto GF() const -> const galois::GFService &;

        auto RowShifts() const -> const std::array<std::size_t, 4> &;

        auto InvRowShifts() const -> const std::array<std::size_t, 4> &;

        auto SBox() const -> const std::array<std::uint8_t, 256> &;

        auto InvSBox() const -> const std::array<std::uint8_t, 256> &;

    private:
        auto InitializeSBoxes() const -> void;

        auto AffineTransform(
            std::uint8_t byte
        ) const -> std::uint8_t;

        auto InvAffineTransform(
            std::uint8_t byte
        ) const -> std::uint8_t;

    private:
        BlockLength block_length_;
        KeyLength key_length_;
        std::uint8_t gf_modulus_;
        galois::GFService gf_service_;
        std::array<std::size_t, 4> row_shifts_{};
        std::array<std::size_t, 4> inv_row_shifts_{};

        mutable std::once_flag sboxes_once_flag_;
        mutable std::array<std::uint8_t, 256> sbox_{};
        mutable std::array<std::uint8_t, 256> inv_sbox_{};
    };

    class RijndaelKeyExpander : public IKeyExpander {
    private:
        using Word = std::array<std::uint8_t, 4>;

    public:
        RijndaelKeyExpander(
            std::shared_ptr<const RijndaelContext> context
        );

    public:
        auto ExpandKey(
            std::span<const std::uint8_t> base_key
        ) const -> std::vector<std::vector<std::uint8_t>> override;

    private:
        auto SubWord(
            Word &word
        ) const -> void;

    private:
        std::shared_ptr<const RijndaelContext> context_;
    };

    class RijndaelRoundFunction : public IRoundFunction {
    protected:
        using Column = std::array<std::uint8_t, 4>;
        using Matrix = std::array<Column, 4>;

    protected:
        explicit RijndaelRoundFunction(
            std::shared_ptr<const RijndaelContext> context
        );

    public:
        auto ProcessBlock(
            std::span<const std::uint8_t> input_block,
            std::span<const std::uint8_t> round_key,
            std::span<std::uint8_t> output_block
        ) const -> void override final;

        auto ProcessFinalBlock(
            std::span<const std::uint8_t> input_block,
            std::span<const std::uint8_t> round_key,
            std::span<std::uint8_t> output_block
        ) const -> void;

        // In-place operations require the round key to use separate storage.
        virtual auto ApplyRound(
            RijndaelState &state,
            std::span<const std::uint8_t> round_key
        ) const -> void = 0;

        virtual auto ApplyFinalRound(
            RijndaelState &state,
            std::span<const std::uint8_t> round_key
        ) const -> void = 0;

        auto ApplyInitialKey(
            RijndaelState &state,
            std::span<const std::uint8_t> round_key
        ) const -> void;

    protected:
        auto ValidateState(
            const RijndaelState &state,
            std::span<const std::uint8_t> round_key
        ) const -> void;

        auto SubstituteBytes(
            RijndaelState &state,
            const std::array<std::uint8_t, 256> &sbox
        ) const -> void;

        auto ShiftRows(
            RijndaelState &state,
            const std::array<std::size_t, 4> &shifts
        ) const -> void;

        auto MixColumns(
            RijndaelState &state,
            const Matrix &matrix
        ) const -> void;

        auto AddRoundKey(
            RijndaelState &state,
            std::span<const std::uint8_t> round_key
        ) const -> void;

    private:
        auto ValidateBuffers(
            std::span<const std::uint8_t> input,
            std::span<std::uint8_t> output
        ) const -> void;

    protected:
        std::shared_ptr<const RijndaelContext> context_;
    };

    class RijndaelEncryptRound final : public RijndaelRoundFunction {
    public:
        explicit RijndaelEncryptRound(
            std::shared_ptr<const RijndaelContext> context
        );

    public:
        auto ApplyRound(
            RijndaelState &state,
            std::span<const std::uint8_t> round_key
        ) const -> void override;

        auto ApplyFinalRound(
            RijndaelState &state,
            std::span<const std::uint8_t> round_key
        ) const -> void override;
    };

    class RijndaelDecryptRound final : public RijndaelRoundFunction {
    public:
        explicit RijndaelDecryptRound(
            std::shared_ptr<const RijndaelContext> context
        );

    public:
        auto ApplyRound(
            RijndaelState &state,
            std::span<const std::uint8_t> round_key
        ) const -> void override;

        auto ApplyFinalRound(
            RijndaelState &state,
            std::span<const std::uint8_t> round_key
        ) const -> void override;
    };

    class RijndaelAlgorithm : public ISymmetricBlockCipher {
    public:
        RijndaelAlgorithm(
            BlockLength block_length,
            KeyLength key_length,
            std::uint8_t gf_modulus,
            galois::GFService gf_service
        );

    public:
        auto EncryptBlock(
            std::span<const std::uint8_t> input,
            std::span<std::uint8_t> output
        ) const -> void override;

        auto DecryptBlock(
            std::span<const std::uint8_t> input,
            std::span<std::uint8_t> output
        ) const -> void override;

        auto SetEncryptionKey(
            std::span<const std::uint8_t> key
        ) -> void override;

        auto SetDecryptionKey(
            std::span<const std::uint8_t> key
        ) -> void override;

        auto BlockSize() const -> std::size_t override;

    private:
        auto ValidateBlock(
            std::span<const std::uint8_t> input,
            std::span<std::uint8_t> output
        ) const -> void;

        auto SetKey(
            std::span<const std::uint8_t> key
        ) -> void;

    private:
        std::shared_ptr<const RijndaelContext> context_;
        RijndaelKeyExpander key_expander_;
        RijndaelEncryptRound encrypt_round_;
        RijndaelDecryptRound decrypt_round_;

        std::vector<std::vector<std::uint8_t>> round_keys_;
    };

} // namespace crypto::symmetric

#endif //MAI_CB_2026_RIJNDAEL_ALGORITHM_H
