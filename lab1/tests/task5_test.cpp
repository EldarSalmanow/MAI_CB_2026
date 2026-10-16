#include <gtest/gtest.h>

#include <any>
#include <cstdint>

#include <lab1/cipher_context.h>
#include <lab1/des_algorithm.h>

#include <array>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <random>
#include <string>
#include <tuple>

namespace {

namespace fs = std::filesystem;
using Bytes = std::vector<std::uint8_t>;
using Context = SymmetricCipherContext<DESAlgorithm>;
using Combination = std::tuple<CipherMode, PaddingMode>;

const Bytes key{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1};
const CipherParams params{{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}, {std::uint64_t{17}}};

auto RequiresPadding(CipherMode mode) -> bool {
    return mode == CipherMode::ECB || mode == CipherMode::CBC || mode == CipherMode::PCBC;
}

auto ExpectedPlain(Bytes bytes, CipherMode mode, PaddingMode padding) -> Bytes {
    if (RequiresPadding(mode) && padding == PaddingMode::Zeros) {
        bytes.resize(bytes.size() + 8 - bytes.size() % 8, 0);
    }
    return bytes;
}

auto RandomBytes(std::size_t size) -> Bytes {
    std::mt19937 engine(42);
    Bytes bytes(size);
    for (auto& byte : bytes) {
        byte = static_cast<std::uint8_t>(engine() & 0xFF);
    }
    return bytes;
}

auto Write(const fs::path& path, const Bytes& bytes) -> void {
    std::ofstream out;
    out.exceptions(std::ios::badbit | std::ios::failbit);
    out.open(path, std::ios::binary);
    if (!bytes.empty()) {
        out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    }
    out.close();
}

auto Read(const fs::path& path) -> Bytes {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("Cannot open test file.");
    }
    in.exceptions(std::ios::badbit);
    return Bytes(std::istreambuf_iterator<char>(in), {});
}

class DESTest : public ::testing::TestWithParam<Combination> {
protected:
    fs::path directory;

    void SetUp() override {
        const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
        const auto candidate = fs::temp_directory_path() / ("mai_des_" + std::to_string(stamp));
        ASSERT_TRUE(fs::create_directory(candidate));
        directory = candidate;
    }

    void TearDown() override {
        // Only remove a directory successfully created by this test.
        if (!directory.empty()) {
            std::error_code error;
            fs::remove_all(directory, error);
            EXPECT_FALSE(error) << error.message();
        }
    }
};

TEST_P(DESTest, MemoryRoundTrip) {
    const auto [mode, padding] = GetParam();
    Context context(key, mode, padding, params);
    for (const std::size_t size : {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 255}) {
        SCOPED_TRACE(size);
        const auto plain = RandomBytes(size);
        const auto cipher = context.EncryptAsync(plain).get();
        EXPECT_EQ(cipher.size(), size + (RequiresPadding(mode) ? 8 - size % 8 : 0));
        const auto expected = ExpectedPlain(plain, mode, padding);
        EXPECT_EQ(context.DecryptAsync(cipher).get(), expected);
        Context fresh(key, mode, padding, params);
        EXPECT_EQ(fresh.DecryptAsync(cipher).get(), expected);
    }
}

TEST_P(DESTest, FileRoundTrip) {
    const auto [mode, padding] = GetParam();
    Context context(key, mode, padding, params);
    const auto input = directory / "input file.bin";
    const auto encrypted = directory / "cipher.enc";
    const auto decrypted = directory / "restored.bin";
    // DES blocks are 8 bytes; the file buffer is 8192 bytes.
    for (const std::size_t size : {0, 1, 7, 8, 9, 8191, 8192, 8193, 16385}) {
        SCOPED_TRACE(size);
        const auto plain = RandomBytes(size);
        Write(input, plain);
        context.EncryptFileAsync(input, encrypted).get();
        EXPECT_EQ(fs::file_size(encrypted), size + (RequiresPadding(mode) ? 8 - size % 8 : 0));
        if (padding != PaddingMode::ISO_10126 || !RequiresPadding(mode)) {
            EXPECT_EQ(Read(encrypted), context.EncryptAsync(plain).get());
        }
        context.DecryptFileAsync(encrypted, decrypted).get();
        EXPECT_EQ(Read(input), plain);
        EXPECT_EQ(Read(decrypted), ExpectedPlain(plain, mode, padding));
    }
}

TEST_P(DESTest, BinaryDataAndZeroTails) {
    const auto [mode, padding] = GetParam();
    Context context(key, mode, padding, params);
    Bytes all_values(259);
    for (std::size_t i = 0; i < 256; ++i) {
        all_values[i] = static_cast<std::uint8_t>(i);
    }
    const auto input = directory / "input.bin";
    const auto encrypted = directory / "encrypted.bin";
    const auto decrypted = directory / "decrypted.bin";
    for (const auto& plain : {Bytes{}, Bytes(1, 0), Bytes(7, 0), Bytes(8, 0),
                              Bytes(9, 0), Bytes(150, 0), all_values}) {
        SCOPED_TRACE(plain.size());
        // Keep all original bytes and the entire zero padding, including a
        // full extra block for aligned input and the padding of an empty input.
        const auto expected = ExpectedPlain(plain, mode, padding);
        EXPECT_EQ(context.DecryptAsync(context.EncryptAsync(plain).get()).get(), expected);
        Write(input, plain);
        context.EncryptFileAsync(input, encrypted).get();
        context.DecryptFileAsync(encrypted, decrypted).get();
        EXPECT_EQ(Read(input), plain);
        EXPECT_EQ(Read(decrypted), expected);
    }
}

TEST_P(DESTest, FileErrors) {
    const auto [mode, padding] = GetParam();
    Context context(key, mode, padding, params);
    const auto input = directory / "input.bin";
    const auto output = directory / "output.bin";
    EXPECT_THROW(context.EncryptFileAsync(input, output).get(), std::runtime_error);
    Write(input, RandomBytes(9));
    EXPECT_THROW(context.EncryptFileAsync(input, directory / "missing" / "output.bin").get(), std::runtime_error);
    if (RequiresPadding(mode)) {
        EXPECT_THROW(context.DecryptFileAsync(input, output).get(), std::runtime_error);
    }
}

auto CombinationName(const ::testing::TestParamInfo<Combination>& info) -> std::string {
    constexpr std::array mode_names{"ECB", "CBC", "PCBC", "CFB", "OFB", "CTR", "RandomDelta"};
    // PaddingMode enumeration order: ANSI_X923, ISO_10126, PKCS7, Zeros.
    constexpr std::array padding_names{"ANSI_X923", "ISO_10126", "PKCS7", "Zeros"};
    const auto [mode, padding] = info.param;
    return std::string(mode_names[static_cast<std::size_t>(mode)]) + "_" +
           padding_names[static_cast<std::size_t>(padding)];
}

INSTANTIATE_TEST_SUITE_P(
    AllModesAndPaddings, DESTest,
    ::testing::Combine(
        ::testing::Values(CipherMode::ECB, CipherMode::CBC, CipherMode::PCBC, CipherMode::CFB,
                          CipherMode::OFB, CipherMode::CTR, CipherMode::RandomDelta),
        ::testing::Values(PaddingMode::Zeros, PaddingMode::ANSI_X923, PaddingMode::PKCS7, PaddingMode::ISO_10126)),
    CombinationName);

TEST(DES, KnownAnswerAndInPlaceBlocks) {
    const Bytes plain{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    const Bytes expected{0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05};
    DESAlgorithm des;
    des.SetEncryptionKey(key);
    des.SetDecryptionKey(key);
    auto block = plain;
    des.EncryptBlock(block, block);
    EXPECT_EQ(block, expected);
    des.DecryptBlock(block, block);
    EXPECT_EQ(block, plain);
}

TEST(DES, InvalidKeysIvAndCiphertext) {
    DESAlgorithm des;
    for (const std::size_t size : {0, 1, 7, 9}) {
        EXPECT_THROW(des.SetEncryptionKey(Bytes(size)), std::exception);
        EXPECT_THROW(des.SetDecryptionKey(Bytes(size)), std::exception);
        auto invalid = params;
        invalid.iv.resize(size);
        EXPECT_THROW((Context(key, CipherMode::CBC, PaddingMode::PKCS7, invalid)), std::invalid_argument);
    }
    for (auto mode : {CipherMode::ECB, CipherMode::CBC, CipherMode::PCBC}) {
        for (auto padding : {PaddingMode::Zeros, PaddingMode::ANSI_X923, PaddingMode::PKCS7, PaddingMode::ISO_10126}) {
            Context context(key, mode, padding, params);
            for (const std::size_t size : {0, 1, 7, 9}) {
                EXPECT_THROW(context.DecryptAsync(Bytes(size)).get(), std::invalid_argument);
            }
        }
    }
}

TEST(DES, MalformedPadding) {
    DESAlgorithm des;
    des.SetEncryptionKey(key);
    for (auto padding : {PaddingMode::ANSI_X923, PaddingMode::PKCS7, PaddingMode::ISO_10126}) {
        Context context(key, CipherMode::ECB, padding);
        for (const auto length : {0, 9, 255}) {
            Bytes invalid(8, 0), encrypted(8);
            invalid.back() = static_cast<std::uint8_t>(length);
            des.EncryptBlock(invalid, encrypted);
            EXPECT_THROW(context.DecryptAsync(encrypted).get(), std::runtime_error);
        }
    }
    for (auto padding : {PaddingMode::ANSI_X923, PaddingMode::PKCS7}) {
        Context context(key, CipherMode::ECB, padding);
        Bytes invalid(8, 0), encrypted(8);
        invalid[6] = 0x7F;
        invalid[7] = 2;
        des.EncryptBlock(invalid, encrypted);
        EXPECT_THROW(context.DecryptAsync(encrypted).get(), std::runtime_error);
    }
}

} // namespace
