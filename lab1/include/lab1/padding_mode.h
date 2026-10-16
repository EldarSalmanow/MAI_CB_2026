#ifndef MAI_CB_2026_PADDING_MODE_H
#define MAI_CB_2026_PADDING_MODE_H

#include <memory>
#include <random>
#include <span>
#include <stdexcept>


// see https://ru.wikipedia.org/wiki/Дополнение_(криптография)
enum class PaddingMode {
    ANSI_X923,
    ISO_10126,
    PKCS7,
    Zeros
};

class IPaddingStrategy {
public:
    virtual ~IPaddingStrategy() = default;

public:
    virtual auto ApplyPadding(
        std::span<std::uint8_t> block,
        std::size_t valid_bytes
    ) const -> void = 0;

    virtual auto RemovePadding(
        std::span<const std::uint8_t> block
    ) const -> std::span<const std::uint8_t> = 0;
};

// ANSI - 0 + size
class AnsiX923PaddingStrategy : public IPaddingStrategy {
public:
    AnsiX923PaddingStrategy() = default;

public:
    auto ApplyPadding(
        std::span<std::uint8_t> block,
        std::size_t valid_bytes
    ) const -> void override {
        const std::size_t padding_length = block.size() - valid_bytes;

        std::fill(block.begin() + valid_bytes, block.end() - 1, 0x00);

        block.back() = static_cast<std::uint8_t>(padding_length);
    }

    auto RemovePadding(
        std::span<const std::uint8_t> block
    ) const -> std::span<const std::uint8_t> override {
        if (block.empty()) {
            return block;
        }

        const std::uint8_t padding_length = block.back();

        if (padding_length == 0 || padding_length > block.size()) {
            throw std::runtime_error("[ERROR] Invalid ANSI X.923 padding length!");
        }

        for (std::size_t i = block.size() - padding_length; i < block.size() - 1; ++i) {
            if (block[i] != 0x00) {
                throw std::runtime_error("[ERROR] Corrupted ANSI X.923 padding bytes!");
            }
        }

        return block.first(block.size() - padding_length);
    }
};

// ISO - random + size
class ISO10126PaddingStrategy : public IPaddingStrategy {
public:
    ISO10126PaddingStrategy() = default;

public:
    auto ApplyPadding(
        std::span<std::uint8_t> block,
        std::size_t valid_bytes
    ) const -> void override {
        const std::size_t padding_length = block.size() - valid_bytes;

        thread_local std::random_device random_device;
        thread_local std::mt19937 engine(random_device());
        std::uniform_int_distribution<std::uint16_t> distribution(0, 255);

        for (std::size_t i = valid_bytes; i < block.size() - 1; ++i) {
            block[i] = static_cast<std::uint8_t>(distribution(engine));
        }

        block.back() = static_cast<std::uint8_t>(padding_length);
    }

    auto RemovePadding(
        std::span<const std::uint8_t> block
    ) const -> std::span<const std::uint8_t> override {
        if (block.empty()) {
            return block;
        }

        const std::uint8_t padding_length = block.back();

        if (padding_length == 0 || padding_length > block.size()) {
            throw std::runtime_error("[ERROR] Invalid ISO 10126 padding length!");
        }

        return block.first(block.size() - padding_length);
    }
};

// PKCS - size
class PKCS7PaddingStrategy : public IPaddingStrategy {
public:
    PKCS7PaddingStrategy() = default;

public:
    auto ApplyPadding(
        std::span<std::uint8_t> block,
        std::size_t valid_bytes
    ) const -> void override {
        const std::size_t padding_length = block.size() - valid_bytes;

        std::fill(block.begin() + valid_bytes, block.end(), static_cast<std::uint8_t>(padding_length));
    }

    auto RemovePadding(
        std::span<const std::uint8_t> block
    ) const -> std::span<const std::uint8_t> override {
        if (block.empty()) {
            return block;
        }

        const std::uint8_t padding_length = block.back();

        if (padding_length == 0 || padding_length > block.size()) {
            throw std::runtime_error("[ERROR] Invalid PKCS7 padding length!");
        }

        for (std::size_t i = block.size() - padding_length; i < block.size(); ++i) {
            if (block[i] != padding_length) {
                throw std::runtime_error("[ERROR] Corrupted PKCS7 padding!");
            }
        }

        return block.first(block.size() - padding_length);
    }
};

// Zeros - zero :)
class ZerosPaddingStrategy : public IPaddingStrategy {
public:
    ZerosPaddingStrategy() = default;

public:
    auto ApplyPadding(
        std::span<std::uint8_t> block,
        std::size_t valid_bytes
    ) const -> void override {
        std::fill(block.begin() + valid_bytes, block.end(), 0x00);
    }

    auto RemovePadding(
        std::span<const std::uint8_t> block
    ) const -> std::span<const std::uint8_t> override {
        return block;
    }
};

class PaddingModeFactory {
public:
    static auto Create(
        PaddingMode mode
    ) -> std::unique_ptr<IPaddingStrategy> {
        switch (mode) {
            case PaddingMode::ANSI_X923: {
                return std::make_unique<AnsiX923PaddingStrategy>();
            }
            case PaddingMode::ISO_10126: {
                return std::make_unique<ISO10126PaddingStrategy>();
            }
            case PaddingMode::PKCS7: {
                return std::make_unique<PKCS7PaddingStrategy>();
            }
            case PaddingMode::Zeros: {
                return std::make_unique<ZerosPaddingStrategy>();
            }
            default: {
                throw std::runtime_error("[ERROR] Unknown padding mode!");
            }
        }
    }
};

#endif //MAI_CB_2026_PADDING_MODE_H
