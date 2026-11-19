#ifndef MAI_CB_2026_RIJNDAEL_ALGORITHM_H
#define MAI_CB_2026_RIJNDAEL_ALGORITHM_H

#include <cstdint>
#include <mutex>
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

        auto RoundsCount() const -> std::size_t;

        auto Modulus() const -> std::uint8_t;

        auto GF() const -> const galois::GFService &;

        auto SBox() const -> const std::vector<std::uint8_t> &;

        auto InvSBox() const -> const std::vector<std::uint8_t> &;

    private:
        auto InitializeSBoxes() const -> void;

    private:
        BlockLength block_length_;
        KeyLength key_length_;
        std::uint8_t gf_modulus_;
        galois::GFService gf_service_;

        mutable std::once_flag sboxes_once_flag_;
        mutable std::vector<std::uint8_t> sbox_;
        mutable std::vector<std::uint8_t> inv_sbox_;
    };

    class RijndaelKeyExpander : public IKeyExpander {
    public:
        RijndaelKeyExpander(
            std::shared_ptr<const RijndaelContext> context
        );

    public:
        auto ExpandKey(
            std::span<const std::uint8_t> base_key
        ) const -> std::vector<std::vector<std::uint8_t>> override;

    private:
        std::shared_ptr<const RijndaelContext> context_;
    };

    class RijndaelRoundFunction : public IRoundFunction {
    public:
        enum class Direction {
            Encrypt,
            Decrypt
        };

    public:
        RijndaelRoundFunction(
            Direction direction,
            std::shared_ptr<const RijndaelContext> context
        );

    public:
        auto ProcessBlock(
            std::span<const std::uint8_t> input_block,
            std::span<const std::uint8_t> round_key,
            std::span<std::uint8_t> output_block
        ) const -> void override;

        auto ProcessFinalBlock(
            std::span<const std::uint8_t> input_block,
            std::span<const std::uint8_t> round_key,
            std::span<std::uint8_t> output_block
        ) const -> void;

    private:
        auto ProcessRound(
            std::span<const std::uint8_t> input_block,
            std::span<const std::uint8_t> round_key,
            std::span<std::uint8_t> output_block,
            bool with_mix_columns
        ) const -> void;

        auto SubBytes(
            std::span<std::uint8_t> state
        ) const -> void;

        auto InvSubBytes(
            std::span<std::uint8_t> state
        ) const -> void;

        auto ShiftRows(
            std::span<std::uint8_t> state
        ) const -> void;

        auto InvShiftRows(
            std::span<std::uint8_t> state
        ) const -> void;

        auto MixColumns(
            std::span<std::uint8_t> state
        ) const -> void;

        auto InvMixColumns(
            std::span<std::uint8_t> state
        ) const -> void;

        auto AddRoundKey(
            std::span<std::uint8_t> state,
            std::span<const std::uint8_t> round_key
        ) const -> void;

    private:
        Direction direction_;
        std::shared_ptr<const RijndaelContext> context_;
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
        std::shared_ptr<const RijndaelContext> context_;
        RijndaelKeyExpander key_expander_;
        RijndaelRoundFunction encrypt_round_;
        RijndaelRoundFunction decrypt_round_;

        std::vector<std::vector<std::uint8_t>> round_keys_;
    };

} // namespace crypto::symmetric

#endif //MAI_CB_2026_RIJNDAEL_ALGORITHM_H
