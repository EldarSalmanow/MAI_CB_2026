#ifndef MAI_CB_2026_CIPHER_MODE_H
#define MAI_CB_2026_CIPHER_MODE_H

#include <lab1/utils.h>

#include <any>


// see https://ru.wikipedia.org/wiki/Режим_шифрования
enum class CipherMode {
    ECB,
    CBC,
    PCBC,
    CFB,
    OFB,
    CTR,
    RandomDelta
};

struct CipherParams {
    std::vector<std::uint8_t> iv;
    std::vector<std::any> additional_args;
};

class ICipherModeStrategy {
public:
    virtual ~ICipherModeStrategy() = default;

public:
    virtual auto EncryptChunk(
        std::span<const std::uint8_t> in,
        std::span<std::uint8_t> out,
        const ISymmetricBlockCipher &cipher
    ) -> void = 0;

    virtual auto DecryptChunk(
        std::span<const std::uint8_t> in,
        std::span<std::uint8_t> out,
        const ISymmetricBlockCipher &cipher
    ) -> void = 0;

    virtual auto ResetState() -> void = 0;

    virtual auto RequiresPadding() const -> bool = 0;
};

class ECBCipherStrategy : public ICipherModeStrategy {
public:
    ECBCipherStrategy() = default;

public:
    auto EncryptChunk(
        std::span<const std::uint8_t> in,
        std::span<std::uint8_t> out,
        const ISymmetricBlockCipher &cipher
    ) -> void override {
        const auto block_size = cipher.BlockSize();

        ParallelFor(in.size() / block_size, [&] (const std::size_t i) {
            cipher.EncryptBlock(in.subspan(i * block_size, block_size), out.subspan(i * block_size, block_size));
        });
    }

    auto DecryptChunk(
        std::span<const std::uint8_t> in,
        std::span<std::uint8_t> out,
        const ISymmetricBlockCipher &cipher
    ) -> void override {
        const auto block_size = cipher.BlockSize();

        ParallelFor(in.size() / block_size, [&] (const std::size_t i) {
            cipher.DecryptBlock(in.subspan(i * block_size, block_size), out.subspan(i * block_size, block_size));
        });
    }

    auto ResetState() -> void override {}

    auto RequiresPadding() const -> bool {
        return true;
    }
};

class CBCCipherStrategy : public ICipherModeStrategy {
public:
    explicit CBCCipherStrategy(std::vector<std::uint8_t> iv)
            : init_iv_(std::move(iv)) {
        curr_iv_ = init_iv_;
    }

public:
    auto EncryptChunk(
        std::span<const std::uint8_t> in,
        std::span<std::uint8_t> out,
        const ISymmetricBlockCipher &cipher
    ) -> void override {
        const auto block_size = cipher.BlockSize();

        for (std::size_t i = 0; i < in.size(); i += block_size) {
            auto out_block = out.subspan(i, block_size);

            Xor(out_block, in.subspan(i, block_size), curr_iv_);

            cipher.EncryptBlock(out_block, out_block);

            std::copy_n(out_block.begin(), block_size, curr_iv_.begin());
        }
    }

    auto DecryptChunk(
        std::span<const std::uint8_t> in,
        std::span<std::uint8_t> out,
        const ISymmetricBlockCipher &cipher
    ) -> void override {
        const auto block_size = cipher.BlockSize();

        std::vector<std::uint8_t> next_iv(in.end() - block_size, in.end());

        ParallelFor(in.size() / block_size, [&](const std::size_t i) {
            const auto in_block = in.subspan(i * block_size, block_size);
            const auto out_block = out.subspan(i * block_size, block_size);

            cipher.DecryptBlock(in_block, out_block);

            const auto prev_block =
                (i == 0) ? std::span<const std::uint8_t>(curr_iv_)
                         : in.subspan((i - 1) * block_size, block_size);

            Xor(out_block, prev_block);
        });

        curr_iv_ = std::move(next_iv);
    }

    auto ResetState() -> void override {
        curr_iv_ = init_iv_;
    }

    auto RequiresPadding() const -> bool {
        return true;
    }

private:
    std::vector<std::uint8_t> init_iv_;
    std::vector<std::uint8_t> curr_iv_;
};

class PCBCCipherStrategy : public ICipherModeStrategy {
public:
    explicit PCBCCipherStrategy(std::vector<std::uint8_t> iv)
            : init_iv_(std::move(iv)) {
        curr_iv_ = init_iv_;
    }

public:
    auto EncryptChunk(
        std::span<const std::uint8_t> in,
        std::span<std::uint8_t> out,
        const ISymmetricBlockCipher &cipher
    ) -> void override {
        const auto block_size = cipher.BlockSize();

        std::vector<std::uint8_t> tmp(block_size);
        for (std::size_t i = 0; i < in.size(); i += block_size) {
            const auto in_block = in.subspan(i, block_size);
            const auto out_block = out.subspan(i, block_size);

            Xor(out_block, in_block, curr_iv_);

            cipher.EncryptBlock(out_block, tmp);
            std::copy_n(tmp.begin(), block_size, out_block.begin());

            Xor(curr_iv_, in_block, out_block);
        }
    }

    auto DecryptChunk(
        std::span<const std::uint8_t> in,
        std::span<std::uint8_t> out,
        const ISymmetricBlockCipher &cipher
    ) -> void override {
        const auto block_size = cipher.BlockSize();

        for (std::size_t i = 0; i < in.size(); i += block_size) {
            const auto in_block = in.subspan(i, block_size);
            const auto out_block = out.subspan(i, block_size);

            cipher.DecryptBlock(in_block, out_block);

            Xor(out_block, curr_iv_);

            Xor(curr_iv_, in_block, out_block);
        }
    }

    auto ResetState() -> void override {
        curr_iv_ = init_iv_;
    }

    auto RequiresPadding() const -> bool {
        return true;
    }

private:
    std::vector<std::uint8_t> init_iv_;
    std::vector<std::uint8_t> curr_iv_;
};

class CFBCipherStrategy : public ICipherModeStrategy {
public:
    explicit CFBCipherStrategy(std::vector<std::uint8_t> iv)
            : init_iv_(std::move(iv)) {
        curr_iv_ = init_iv_;
    }

public:
    auto EncryptChunk(
        std::span<const std::uint8_t> in,
        std::span<std::uint8_t> out,
        const ISymmetricBlockCipher &cipher
    ) -> void override {
        const auto block_size = cipher.BlockSize();

        for (std::size_t i = 0; i < in.size(); i += block_size) {
            const auto in_block = in.subspan(i, block_size);
            const auto out_block = out.subspan(i, block_size);

            cipher.EncryptBlock(curr_iv_, out_block);

            Xor(out_block, in_block);

            std::copy_n(out_block.begin(), block_size, curr_iv_.begin());
        }
    }

    auto DecryptChunk(
        std::span<const std::uint8_t> in,
        std::span<std::uint8_t> out,
        const ISymmetricBlockCipher &cipher
    ) -> void override {
        if (in.empty()) {
            return;
        }
        const std::size_t block_size = cipher.BlockSize();

        std::vector<std::uint8_t> next_iv(in.end() - block_size, in.end());

        ParallelFor(in.size() / block_size, [&](std::size_t i) {
            const auto in_block = in.subspan(i * block_size, block_size);
            const auto out_block = out.subspan(i * block_size, block_size);

            const auto prev_block = (i == 0) ? std::span<const std::uint8_t>(curr_iv_)
                                                             : in.subspan((i - 1) * block_size, block_size);

            cipher.EncryptBlock(prev_block, out_block);
            Xor(out_block, in_block);
        });

        curr_iv_ = std::move(next_iv);
    }

    auto ResetState() -> void override {
        curr_iv_ = init_iv_;
    }

    auto RequiresPadding() const -> bool {
        return false;
    }

private:
    std::vector<std::uint8_t> init_iv_;
    std::vector<std::uint8_t> curr_iv_;
};

class OFBCipherStrategy : public ICipherModeStrategy {
public:
    explicit OFBCipherStrategy(std::vector<std::uint8_t> iv)
            : init_iv_(std::move(iv)) {
        curr_iv_ = init_iv_;
    }

public:
    auto EncryptChunk(
        std::span<const std::uint8_t> in,
        std::span<std::uint8_t> out,
        const ISymmetricBlockCipher &cipher
    ) -> void override {
        const auto block_size = cipher.BlockSize();

        for (std::size_t i = 0; i < in.size(); i += block_size) {
            const auto out_block = out.subspan(i, block_size);

            cipher.EncryptBlock(curr_iv_, curr_iv_);

            Xor(out_block, in.subspan(i, block_size), curr_iv_);
        }
    }

    auto DecryptChunk(
        std::span<const std::uint8_t> in,
        std::span<std::uint8_t> out,
        const ISymmetricBlockCipher &cipher
    ) -> void override {
        EncryptChunk(in, out, cipher);
    }

    auto ResetState() -> void override {
        curr_iv_ = init_iv_;
    }

    auto RequiresPadding() const -> bool {
        return false;
    }

private:
    std::vector<std::uint8_t> init_iv_;
    std::vector<std::uint8_t> curr_iv_;
};

class CTRCipherStrategy : public ICipherModeStrategy {
public:
    explicit CTRCipherStrategy(std::vector<std::uint8_t> iv)
            : init_iv_(std::move(iv)),
              block_index_(0) {}

public:
    auto EncryptChunk(
        std::span<const std::uint8_t> in,
        std::span<std::uint8_t> out,
        const ISymmetricBlockCipher &cipher
    ) -> void override {
        const auto block_size = cipher.BlockSize();
        const auto chunk_start_idx = block_index_;

        ParallelFor(in.size() / block_size, [&] (std::size_t i) -> void {
            std::vector<std::uint8_t> counter = init_iv_;
            AddToCounter(counter, chunk_start_idx + i);

            const auto out_block = out.subspan(i * block_size, block_size);

            cipher.EncryptBlock(counter, out_block);

            Xor(out_block, in.subspan(i * block_size, block_size));
        });

        block_index_ += in.size() / block_size;
    }

    auto DecryptChunk(
        std::span<const std::uint8_t> in,
        std::span<std::uint8_t> out,
        const ISymmetricBlockCipher &cipher
    ) -> void override {
        EncryptChunk(in, out, cipher);
    }

    auto ResetState() -> void override {
        block_index_ = 0;
    }

    auto RequiresPadding() const -> bool {
        return false;
    }

private:
    std::vector<std::uint8_t> init_iv_;
    std::uint64_t block_index_;
};

class RandomDeltaCipherStrategy : public ICipherModeStrategy {
public:
    RandomDeltaCipherStrategy(std::vector<std::uint8_t> iv,
                              const std::uint64_t delta)
            : init_iv_(std::move(iv)),
              block_index_(0),
              delta_(delta) {}

public:
    auto EncryptChunk(
        std::span<const std::uint8_t> in,
        std::span<std::uint8_t> out,
        const ISymmetricBlockCipher &cipher
    ) -> void override {
        const auto block_size = cipher.BlockSize();
        const auto chunk_start_index = block_index_;

        ParallelFor(in.size() / block_size, [&] (const std::size_t i) {
            std::vector<std::uint8_t> counter = init_iv_;
            AddCounterProduct(counter, chunk_start_index + i, delta_);

            const auto out_block = out.subspan(i * block_size, block_size);

            cipher.EncryptBlock(counter, out_block);

            Xor(out_block, in.subspan(i * block_size, block_size));
        });

        block_index_ += in.size() / block_size;
    }

    auto DecryptChunk(
        std::span<const std::uint8_t> in,
        std::span<std::uint8_t> out,
        const ISymmetricBlockCipher &cipher
    ) -> void override {
        EncryptChunk(in, out, cipher);
    }

    auto ResetState() -> void override {
        block_index_ = 0;
    }

    auto RequiresPadding() const -> bool {
        return false;
    }

private:
    std::vector<std::uint8_t> init_iv_;
    std::uint64_t block_index_;
    std::uint64_t delta_;
};

class CipherModeFactory {
public:
    static auto Create(CipherMode mode,
                       const CipherParams &params) -> std::unique_ptr<ICipherModeStrategy> {
        if (mode == CipherMode::RandomDelta && params.additional_args.empty()) {
            throw std::runtime_error("[ERROR] Delta value not provided for RandomDelta cipher mode!");
        }

        switch (mode) {
            case CipherMode::ECB: {
                return std::make_unique<ECBCipherStrategy>();
            }
            case CipherMode::CBC: {
                return std::make_unique<CBCCipherStrategy>(params.iv);
            }
            case CipherMode::PCBC: {
                return std::make_unique<PCBCCipherStrategy>(params.iv);
            }
            case CipherMode::CFB: {
                return std::make_unique<CFBCipherStrategy>(params.iv);
            }
            case CipherMode::OFB: {
                return std::make_unique<OFBCipherStrategy>(params.iv);
            }
            case CipherMode::CTR: {
                return std::make_unique<CTRCipherStrategy>(params.iv);
            }
            case CipherMode::RandomDelta: {
                std::uint64_t delta = std::any_cast<std::uint64_t>(params.additional_args.front());

                return std::make_unique<RandomDeltaCipherStrategy>(params.iv, delta);
            }
            default: {
                throw std::runtime_error("[ERROR] Unknown cipher mode!");
            }
        }
    }
};

#endif //MAI_CB_2026_CIPHER_MODE_H
