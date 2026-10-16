#ifndef MAI_CB_2026_CIPHER_CONTEXT_H
#define MAI_CB_2026_CIPHER_CONTEXT_H

#include <lab1/block_cipher.h>
#include <lab1/cipher_mode.h>
#include <lab1/padding_mode.h>

#include <algorithm>
#include <filesystem>
#include <fstream>


template<typename CipherT>
class SymmetricCipherContext {
public:
    using CipherType = CipherT;

public:
    static_assert(std::is_base_of_v<ISymmetricBlockCipher, CipherType>,
                  "[ERROR] CipherType must be derived from ISymmetricBlockCipher!");

public:
    SymmetricCipherContext(
        std::span<const std::uint8_t> key,
        const CipherMode mode,
        const PaddingMode padding,
        const CipherParams &params = {}
    ) : cipher_(),
        mode_strategy_(nullptr),
        padding_strategy_(nullptr) {
        if (mode != CipherMode::ECB && params.iv.size() != cipher_.BlockSize()) {
            throw std::invalid_argument("[ERROR] IV and block sizes must be equal!");
        }

        mode_strategy_ = CipherModeFactory::Create(mode, params);
        padding_strategy_ = PaddingModeFactory::Create(padding);

        cipher_.SetEncryptionKey(key);
        cipher_.SetDecryptionKey(key);
    }

    SymmetricCipherContext(const SymmetricCipherContext &) = delete;

public:
    auto EncryptAsync(
        std::vector<std::uint8_t> plain_text
    ) -> std::future<std::vector<std::uint8_t>> {
        return std::async(std::launch::async, [this, data = std::move(plain_text)]() {
            return ProcessMemoryEncrypt(std::move(data));
        });
    }

    auto DecryptAsync(
        std::vector<std::uint8_t> cipher_text
    ) -> std::future<std::vector<std::uint8_t>> {
        return std::async(std::launch::async, [this, data = std::move(cipher_text)]()  {
            return ProcessMemoryDecrypt(std::move(data));
        });
    }

    auto EncryptFileAsync(
        const std::filesystem::path &input_path,
        const std::filesystem::path &output_path
    ) -> std::future<void> {
        return std::async(std::launch::async, [this, input_path, output_path]() {
            return ProcessFileEncrypt(input_path, output_path);
        });
    }

    auto DecryptFileAsync(
        const std::filesystem::path &input_path,
        const std::filesystem::path &output_path
    ) -> std::future<void> {
        return std::async(std::launch::async, [this, input_path, output_path]() {
            return ProcessFileDecrypt(input_path, output_path);
        });
    }

private:
    auto ProcessMemoryEncrypt(
        std::vector<std::uint8_t> data
    ) -> std::vector<std::uint8_t> {
        const auto block_size = cipher_.BlockSize();
        const auto tail = data.size() % block_size;
        const bool requires_padding = mode_strategy_->RequiresPadding();

        mode_strategy_->ResetState();

        if (requires_padding) {
            data.resize(data.size() + (block_size - tail), 0);

            padding_strategy_->ApplyPadding(std::span(data).last(block_size), tail);
        } else if (tail != 0) {
            data.resize(data.size() + (block_size - tail), 0);
        }

        std::vector<std::uint8_t> result(data.size());
        mode_strategy_->EncryptChunk(data, result, cipher_);

        if (!requires_padding && tail != 0) {
            result.resize(result.size() - (block_size - tail));
        }

        return result;
    }

    auto ProcessMemoryDecrypt(
        std::vector<std::uint8_t> data
    ) -> std::vector<std::uint8_t> {
        const auto block_size = cipher_.BlockSize();
        const auto original_size = data.size();
        const auto tail = original_size % block_size;
        const bool requires_padding = mode_strategy_->RequiresPadding();

        mode_strategy_->ResetState();

        if (requires_padding && (original_size == 0 || tail != 0)) {
            throw std::invalid_argument("[ERROR] Ciphertext size must be a multiple of block size!");
        }

        if (!requires_padding && tail != 0) {
            data.resize(original_size + (block_size - tail), 0);
        }

        std::vector<std::uint8_t> result(data.size());
        mode_strategy_->DecryptChunk(data, result, cipher_);

        if (requires_padding) {
            auto valid_span = padding_strategy_->RemovePadding(std::span(result).last(block_size));

            result.resize(result.size() - block_size + valid_span.size());
        } else {
            result.resize(original_size);
        }

        return result;
    }

    auto ProcessFileEncrypt(
        const std::filesystem::path& input_path,
        const std::filesystem::path& output_path
    ) -> void {
        std::ifstream in(input_path, std::ios::binary);
        std::ofstream out(output_path, std::ios::binary);

        if (!in || !out) {
            throw std::runtime_error("[ERROR] Failed to open files!");
        }

        const auto block_size = cipher_.BlockSize();
        const auto requires_padding = mode_strategy_->RequiresPadding();

        std::vector<std::uint8_t> in_buffer(1024 * block_size);
        std::vector<std::uint8_t> out_buffer(1024 * block_size);

        mode_strategy_->ResetState();

        auto is_eof = false;
        while (!is_eof) {
            in.read(reinterpret_cast<char*>(in_buffer.data()), in_buffer.size());

            const auto read_bytes = in.gcount();

            in.peek();
            is_eof = in.eof();

            if (read_bytes == 0 && (!requires_padding || !is_eof)) {
                break;
            }

            if (is_eof && requires_padding) {
                const auto tail = read_bytes % block_size;
                const auto padded_size = read_bytes + (block_size - tail);

                std::vector<std::uint8_t> final_in(padded_size, 0);
                std::copy_n(in_buffer.begin(), read_bytes, final_in.begin());

                padding_strategy_->ApplyPadding(std::span(final_in).last(block_size), tail);

                std::vector<std::uint8_t> final_out(padded_size);
                mode_strategy_->EncryptChunk(final_in, final_out, cipher_);

                out.write(reinterpret_cast<const char*>(final_out.data()), padded_size);

                break;
            }

            if (read_bytes == 0) {
                break;
            }

            auto process_size = read_bytes;
            if (read_bytes % block_size != 0) {
                process_size += block_size - (read_bytes % block_size);

                std::fill(in_buffer.begin() + read_bytes, in_buffer.begin() + process_size, 0);
            }

            mode_strategy_->EncryptChunk(std::span(in_buffer).first(process_size), std::span(out_buffer).first(process_size), cipher_);

            out.write(reinterpret_cast<const char*>(out_buffer.data()), requires_padding ? process_size : read_bytes);
        }
    }

    auto ProcessFileDecrypt(
        const std::filesystem::path& input_path,
        const std::filesystem::path& output_path
    ) -> void {
        std::ifstream in(input_path, std::ios::binary);
        std::ofstream out(output_path, std::ios::binary);

        if (!in || !out) {
            throw std::runtime_error("[ERROR] Failed to open files!");
        }

        const auto block_size = cipher_.BlockSize();
        const bool requires_padding = mode_strategy_->RequiresPadding();

        std::vector<std::uint8_t> in_buf(1024 * block_size);
        std::vector<std::uint8_t> out_buf(1024 * block_size);

        mode_strategy_->ResetState();

        auto is_eof = false;
        while (!is_eof) {
            in.read(reinterpret_cast<char*>(in_buf.data()), in_buf.size());

            const auto read_bytes = in.gcount();

            in.peek();
            is_eof = in.eof();

            if (read_bytes == 0) {
                if (requires_padding) {
                    throw std::runtime_error("[ERROR] Padded ciphertext cannot be empty!");
                }
                break;
            }

            if (requires_padding && read_bytes % block_size != 0) {
                throw std::runtime_error("[ERROR] Corrupted file: size is not a multiple of block size!");
            }

            auto process_size = read_bytes;
            if (!requires_padding && read_bytes % block_size != 0) {
                process_size += block_size - (read_bytes % block_size);

                std::fill(in_buf.begin() + read_bytes, in_buf.begin() + process_size, 0);
            }

            auto in_chunk = std::span(in_buf).first(process_size);
            auto out_chunk = std::span(out_buf).first(process_size);

            mode_strategy_->DecryptChunk(in_chunk, out_chunk, cipher_);

            if (is_eof && requires_padding) {
                auto valid_span = padding_strategy_->RemovePadding(out_chunk.last(block_size));

                out.write(reinterpret_cast<const char*>(out_chunk.data()), process_size - block_size);
                out.write(reinterpret_cast<const char*>(valid_span.data()), valid_span.size());
            } else {
                out.write(reinterpret_cast<const char*>(out_chunk.data()), requires_padding ? process_size : read_bytes);
            }
        }
    }

public:
    auto operator=(const SymmetricCipherContext &other) -> SymmetricCipherContext & = delete;

private:
    CipherType cipher_;
    std::unique_ptr<ICipherModeStrategy> mode_strategy_;
    std::unique_ptr<IPaddingStrategy> padding_strategy_;
};

#endif //MAI_CB_2026_CIPHER_CONTEXT_H
