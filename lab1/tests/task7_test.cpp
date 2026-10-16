#include <gtest/gtest.h>

#include <any>
#include <cstdint>

#include <lab1/cipher_context.h>
#include <lab1/deal_algorithm.h>

#include <array>
#include <chrono>
#include <charconv>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <random>
#include <string>
#include <string_view>
#include <tuple>

namespace {

namespace fs = std::filesystem;
using Bytes = std::vector<std::uint8_t>;
using Context = SymmetricCipherContext<DEALAlgorithm>;
using Combination = std::tuple<CipherMode, PaddingMode>;

const Bytes key{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

const CipherParams params{{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                           0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, {std::uint64_t{17}}};

auto RequiresPadding(CipherMode mode) -> bool {
    return mode == CipherMode::ECB || mode == CipherMode::CBC || mode == CipherMode::PCBC;
}

auto ExpectedPlain(Bytes bytes, CipherMode mode, PaddingMode padding) -> Bytes {
    if (RequiresPadding(mode) && padding == PaddingMode::Zeros) {
        bytes.resize(bytes.size() + 16 - bytes.size() % 16, 0);
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

class DEALTest : public ::testing::TestWithParam<Combination> {
protected:
    fs::path directory;

    void SetUp() override {
        const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
        const auto candidate = fs::temp_directory_path() / ("mai_deal_" + std::to_string(stamp));
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

TEST_P(DEALTest, MemoryRoundTrip) {
    const auto [mode, padding] = GetParam();
    Context context(key, mode, padding, params);
    // Every possible tail length, plus empty input and one/two full blocks.
    for (std::size_t size = 0; size <= 33; ++size) {
        SCOPED_TRACE(size);
        const auto plain = RandomBytes(size);
        const auto cipher = context.EncryptAsync(plain).get();
        EXPECT_EQ(cipher.size(), size + (RequiresPadding(mode) ? 16 - size % 16 : 0));
        const auto expected = ExpectedPlain(plain, mode, padding);
        EXPECT_EQ(context.DecryptAsync(cipher).get(), expected);
        Context fresh(key, mode, padding, params);
        EXPECT_EQ(fresh.DecryptAsync(cipher).get(), expected);
    }
}

TEST_P(DEALTest, FileRoundTrip) {
    const auto [mode, padding] = GetParam();
    Context context(key, mode, padding, params);
    const auto input = directory / "input file.bin";
    const auto encrypted = directory / "cipher.enc";
    const auto decrypted = directory / "restored.bin";
    // DEAL blocks are 16 bytes; the file buffer is 16384 bytes.
    for (const std::size_t size : {0, 1, 15, 16, 17, 16383, 16384, 16385, 32769}) {
        SCOPED_TRACE(size);
        const auto plain = RandomBytes(size);
        Write(input, plain);
        context.EncryptFileAsync(input, encrypted).get();
        EXPECT_EQ(fs::file_size(encrypted), size + (RequiresPadding(mode) ? 16 - size % 16 : 0));
        if (padding != PaddingMode::ISO_10126 || !RequiresPadding(mode)) {
            EXPECT_EQ(Read(encrypted), context.EncryptAsync(plain).get());
        }
        Context fresh(key, mode, padding, params);
        fresh.DecryptFileAsync(encrypted, decrypted).get();
        EXPECT_EQ(Read(input), plain);
        EXPECT_EQ(Read(decrypted), ExpectedPlain(plain, mode, padding));
    }
}

TEST_P(DEALTest, BinaryDataAndZeroTails) {
    const auto [mode, padding] = GetParam();
    Context context(key, mode, padding, params);
    Bytes all_values(259);
    for (std::size_t i = 0; i < 256; ++i) {
        all_values[i] = static_cast<std::uint8_t>(i);
    }
    const auto input = directory / "input.bin";
    const auto encrypted = directory / "encrypted.bin";
    const auto decrypted = directory / "decrypted.bin";
    for (const auto& plain : {Bytes{}, Bytes(1, 0), Bytes(15, 0), Bytes(16, 0),
                              Bytes(17, 0), Bytes(150, 0), all_values}) {
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

TEST_P(DEALTest, FileErrors) {
    const auto [mode, padding] = GetParam();
    Context context(key, mode, padding, params);
    const auto input = directory / "input.bin";
    const auto output = directory / "output.bin";
    EXPECT_THROW(context.EncryptFileAsync(input, output).get(), std::runtime_error);
    EXPECT_THROW(context.DecryptFileAsync(input, output).get(), std::runtime_error);
    Write(input, {});
    if (RequiresPadding(mode)) {
        EXPECT_THROW(context.DecryptFileAsync(input, output).get(), std::runtime_error);
    } else {
        context.DecryptFileAsync(input, output).get();
        EXPECT_TRUE(Read(output).empty());
    }
    Write(input, RandomBytes(9));
    EXPECT_THROW(context.EncryptFileAsync(input, directory / "missing" / "output.bin").get(), std::runtime_error);
    EXPECT_THROW(context.DecryptFileAsync(input, directory / "missing" / "output.bin").get(), std::runtime_error);
    if (RequiresPadding(mode)) {
        EXPECT_THROW(context.DecryptFileAsync(input, output).get(), std::runtime_error);
        DEALAlgorithm deal;
        deal.SetEncryptionKey(key);
        const Bytes invalid_padding(16, 0);
        Bytes ciphertext(16);
        auto block = invalid_padding;
        if (mode != CipherMode::ECB) {
            Xor(block, params.iv);
        }
        deal.EncryptBlock(block, ciphertext);
        Write(input, ciphertext);
        if (padding == PaddingMode::Zeros) {
            context.DecryptFileAsync(input, output).get();
            EXPECT_EQ(Read(output), invalid_padding);
        } else {
            EXPECT_THROW(context.DecryptFileAsync(input, output).get(), std::runtime_error);
        }
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
    AllModesAndPaddings, DEALTest,
    ::testing::Combine(
        ::testing::Values(CipherMode::ECB, CipherMode::CBC, CipherMode::PCBC, CipherMode::CFB,
                          CipherMode::OFB, CipherMode::CTR, CipherMode::RandomDelta),
        ::testing::Values(PaddingMode::Zeros, PaddingMode::ANSI_X923, PaddingMode::PKCS7, PaddingMode::ISO_10126)),
    CombinationName);

TEST(DEALContext, InvalidKeysIvAndCiphertext) {
    DEALAlgorithm deal;
    for (const std::size_t size : {0, 1, 8, 15, 17}) {
        EXPECT_THROW(deal.SetEncryptionKey(Bytes(size)), std::exception);
        EXPECT_THROW(deal.SetDecryptionKey(Bytes(size)), std::exception);
        auto invalid = params;
        invalid.iv.resize(size);
        EXPECT_THROW((Context(key, CipherMode::CBC, PaddingMode::PKCS7, invalid)), std::invalid_argument);
    }
    for (auto mode : {CipherMode::ECB, CipherMode::CBC, CipherMode::PCBC}) {
        for (auto padding : {PaddingMode::Zeros, PaddingMode::ANSI_X923, PaddingMode::PKCS7, PaddingMode::ISO_10126}) {
            Context context(key, mode, padding, params);
            for (const std::size_t size : {0, 1, 8, 15, 17}) {
                EXPECT_THROW(context.DecryptAsync(Bytes(size)).get(), std::invalid_argument);
            }
        }
    }
}

TEST(DEALContext, MalformedPadding) {
    DEALAlgorithm deal;
    deal.SetEncryptionKey(key);
    for (auto padding : {PaddingMode::ANSI_X923, PaddingMode::PKCS7, PaddingMode::ISO_10126}) {
        Context context(key, CipherMode::ECB, padding);
        for (const auto length : {0, 17, 255}) {
            Bytes invalid(16, 0), encrypted(16);
            invalid.back() = static_cast<std::uint8_t>(length);
            deal.EncryptBlock(invalid, encrypted);
            EXPECT_THROW(context.DecryptAsync(encrypted).get(), std::runtime_error);
        }
    }
    for (auto padding : {PaddingMode::ANSI_X923, PaddingMode::PKCS7}) {
        Context context(key, CipherMode::ECB, padding);
        Bytes invalid(16, 0), encrypted(16);
        invalid[14] = 0x7F;
        invalid[15] = 2;
        deal.EncryptBlock(invalid, encrypted);
        EXPECT_THROW(context.DecryptAsync(encrypted).get(), std::runtime_error);
    }
}

TEST(DEALContext, CounterCarryAndFullWidthProduct) {
    constexpr auto maximum = std::numeric_limits<std::uint64_t>::max();
    Bytes counter(16);
    counter.back() = 0xFF;
    AddToCounter(counter, maximum);
    Bytes expected(16);
    expected[7] = 1;
    expected[15] = 0xFE;
    EXPECT_EQ(counter, expected);

    counter.assign(16, 0);
    AddCounterProduct(counter, maximum, maximum);
    expected.assign(16, 0xFF);
    expected[7] = 0xFE;
    std::fill(expected.begin() + 8, expected.end(), 0);
    expected[15] = 1;
    EXPECT_EQ(counter, expected); // (2^64 - 1)^2 = 2^128 - 2^65 + 1.

    counter.assign(16, 0xFF);
    AddToCounter(counter, 1);
    EXPECT_EQ(counter, Bytes(16)); // Modulo 2^128.
}

TEST(DEALContext, CounterModesMatchSequentialReferenceAcrossChunks) {
    DEALAlgorithm deal;
    deal.SetEncryptionKey(key);
    for (auto mode : {CipherMode::CTR, CipherMode::RandomDelta}) {
        for (auto delta : {std::uint64_t{1}, std::numeric_limits<std::uint64_t>::max()}) {
            auto options = params;
            options.iv.assign(16, 0xFF);
            options.additional_args = {delta};
            Context context(key, mode, PaddingMode::Zeros, options);
            const Bytes plain(16 * 1030 + 7);
            Bytes expected(plain.size()), counter = options.iv;
            std::array<std::uint8_t, 16> stream{};
            for (std::size_t offset = 0; offset < plain.size(); offset += 16) {
                deal.EncryptBlock(counter, stream);
                std::copy_n(stream.begin(), std::min(std::size_t{16}, plain.size() - offset),
                            expected.begin() + offset);
                // Independent byte arithmetic, including carry past bit 64.
                auto increment = mode == CipherMode::CTR ? std::uint64_t{1} : delta;
                unsigned carry = 0;
                for (std::size_t i = counter.size(); i-- > 0;) {
                    const unsigned sum = counter[i] + static_cast<unsigned>(increment & 0xFF) + carry;
                    counter[i] = static_cast<std::uint8_t>(sum);
                    carry = sum >> 8;
                    increment >>= 8;
                }
            }
            EXPECT_EQ(context.EncryptAsync(plain).get(), expected);
            EXPECT_EQ(context.DecryptAsync(expected).get(), plain);
            auto strategy = CipherModeFactory::Create(mode, options);
            Bytes padded(16 * 1031), actual(padded.size());
            strategy->EncryptChunk(std::span(padded).first(16 * 1024),
                                   std::span(actual).first(16 * 1024), deal);
            strategy->EncryptChunk(std::span(padded).subspan(16 * 1024),
                                   std::span(actual).subspan(16 * 1024), deal);
            actual.resize(plain.size());
            EXPECT_EQ(actual, expected);
        }
    }
}

TEST(DEALContext, IndependentModeAnswers) {
    // Generated with Gladman's original DEAL C code and CNG DES, then composed
    // using the mode definitions. The plaintext is 00..10; padded modes use PKCS7.
    const std::pair<CipherMode, std::string_view> answers[]{
        {CipherMode::ECB, "47070f29f814c92b1ad7556fe98262fb6df01037027ad1fecda17424eddf0b79"},
        {CipherMode::CBC, "532e50a8ada7a6d7641d36e7abaabb70441681bfdd52d0c8ea52fd4ac465a08c"},
        {CipherMode::PCBC, "532e50a8ada7a6d7641d36e7abaabb70001efe2da91e42200ff9c90fbd940c5b"},
        {CipherMode::CFB, "5e49954e395ab94973693f450967ec321d"},
        {CipherMode::OFB, "5e49954e395ab94973693f450967ec3245"},
        {CipherMode::CTR, "5e49954e395ab94973693f450967ec32d2"},
        {CipherMode::RandomDelta, "5e49954e395ab94973693f450967ec32e3"}
    };
    Bytes plain(17);
    for (std::size_t i = 0; i < plain.size(); ++i) plain[i] = static_cast<std::uint8_t>(i);
    for (const auto& [mode, hex] : answers) {
        Bytes expected(hex.size() / 2);
        for (std::size_t i = 0; i < expected.size(); ++i) {
            unsigned byte{};
            const auto* first = hex.data() + 2 * i;
            const auto [end, error] = std::from_chars(first, first + 2, byte, 16);
            ASSERT_EQ(error, std::errc{});
            ASSERT_EQ(end, first + 2);
            expected[i] = static_cast<std::uint8_t>(byte);
        }
        Context context(key, mode, PaddingMode::PKCS7, params);
        EXPECT_EQ(context.EncryptAsync(plain).get(), expected) << static_cast<int>(mode);
        EXPECT_EQ(context.DecryptAsync(expected).get(), plain) << static_cast<int>(mode);
    }
}

} // namespace
