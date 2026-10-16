#ifndef MAI_CB_2026_BLOCK_CIPHER_H
#define MAI_CB_2026_BLOCK_CIPHER_H

#include <span>


class ISymmetricBlockCipher {
public:
    virtual ~ISymmetricBlockCipher() = default;

public:
    virtual auto EncryptBlock(
        std::span<const std::uint8_t> input,
        std::span<std::uint8_t> output
    ) const -> void = 0;
    virtual auto DecryptBlock(
        std::span<const std::uint8_t> input,
        std::span<std::uint8_t> output
    ) const -> void = 0;

    virtual auto SetEncryptionKey(
        std::span<const std::uint8_t> key
    ) -> void = 0;
    virtual auto SetDecryptionKey(
        std::span<const std::uint8_t> key
    ) -> void = 0;

    virtual auto BlockSize() const -> std::size_t = 0;
};

#endif //MAI_CB_2026_BLOCK_CIPHER_H