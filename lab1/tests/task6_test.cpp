#include <gtest/gtest.h>
#include <lab1/deal_algorithm.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <random>
#include <string_view>

namespace {

using Bytes = std::vector<std::uint8_t>;

auto Hex(std::string_view text) -> Bytes {
    Bytes bytes(text.size() / 2);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        unsigned value{};
        const auto* first = text.data() + 2 * i;
        const auto [end, error] = std::from_chars(first, first + 2, value, 16);
        if (error != std::errc{} || end != first + 2) {
            throw std::invalid_argument("Invalid test vector.");
        }
        bytes[i] = static_cast<std::uint8_t>(value);
    }
    return bytes;
}

struct Vector {
    std::string_view key, plain, cipher;
};

// Reference: Brian Gladman, deal.c (14 January 1999), with ordinary DES.
// https://www.schneier.com/wp-content/uploads/2015/03/DEAL-2.zip
// Frozen answers verified using the original C implementation with Windows CNG DES.
constexpr Vector vectors[]{
    {"000102030405060708090a0b0c0d0e0f", "00000000000000000000000000000000", "34af8d506cd6ee664c76a0e8ae9f6273"},
    {"000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff", "5e48974d3d5fbf4e7b60354e056ae23d"},
    {"00000000000000000000000000000000", "00000000000000000000000000000000", "37c38426079ac9de02cc32f106f43287"},
    {"ffffffffffffffffffffffffffffffff", "ffffffffffffffffffffffffffffffff", "284add48d94790c3f4b760eb430ff4c4"},
};

TEST(DEAL, IndependentKnownAnswers) {
    for (const auto& vector : vectors) {
        SCOPED_TRACE(vector.key);
        const auto key = Hex(vector.key), plain = Hex(vector.plain), expected = Hex(vector.cipher);
        DEALAlgorithm encryptor, decryptor;
        encryptor.SetEncryptionKey(key);
        decryptor.SetDecryptionKey(key);
        Bytes actual(16), restored(16);
        encryptor.EncryptBlock(plain, actual);
        EXPECT_EQ(actual, expected);
        decryptor.DecryptBlock(expected, restored);
        EXPECT_EQ(restored, plain);
        auto in_place = plain;
        encryptor.EncryptBlock(in_place, in_place);
        EXPECT_EQ(in_place, expected);
        decryptor.DecryptBlock(in_place, in_place);
        EXPECT_EQ(in_place, plain);
    }
}

TEST(DEAL, IndependentRoundKeys) {
    DealKeyExpander expander;
    const auto actual = expander.ExpandKey(Hex("000102030405060708090a0b0c0d0e0f"));
    const std::vector<Bytes> expected{
        Hex("3260266c2cf202e2"), Hex("79cf70cd1dac09a5"), Hex("4d29ed01607e2a58"),
        Hex("70dab168c2f349b8"), Hex("6f02d327070a6578"), Hex("91dcce2439827d3e")};
    EXPECT_EQ(actual, expected);
}

TEST(DEAL, DesAdapterKnownAnswerAndValidation) {
    DesToRoundFunctionAdapter adapter;
    const auto key = Hex("133457799bbcdff1");
    auto block = Hex("0123456789abcdef");
    adapter.ProcessBlock(block, key, block);
    EXPECT_EQ(block, Hex("85e813540f0ab405"));
    for (std::size_t size : {0, 1, 7, 9, 16}) {
        Bytes invalid(size), output(8);
        EXPECT_THROW(adapter.ProcessBlock(invalid, key, output), std::exception);
        EXPECT_THROW(adapter.ProcessBlock(output, invalid, output), std::exception);
        EXPECT_THROW(adapter.ProcessBlock(output, key, invalid), std::exception);
    }
}

TEST(DEAL, RejectsInvalidKeysAndUninitializedBlocks) {
    DealKeyExpander expander;
    DEALAlgorithm deal;
    EXPECT_EQ(deal.BlockSize(), 16);
    Bytes block(16);
    EXPECT_THROW(deal.EncryptBlock(block, block), std::runtime_error);
    EXPECT_THROW(deal.DecryptBlock(block, block), std::runtime_error);
    for (std::size_t size = 0; size <= 40; ++size) {
        if (size == 16) continue;
        SCOPED_TRACE(size);
        const Bytes invalid(size);
        EXPECT_THROW(expander.ExpandKey(invalid), std::exception);
        EXPECT_THROW(deal.SetEncryptionKey(invalid), std::exception);
        EXPECT_THROW(deal.SetDecryptionKey(invalid), std::exception);
    }
}

TEST(DEAL, RejectsInvalidBlockSizesWithoutWritingOutput) {
    DEALAlgorithm deal;
    deal.SetEncryptionKey(Hex(vectors[0].key));
    for (std::size_t size : {0, 1, 8, 15, 17, 32}) {
        Bytes invalid(size, 0xA5), block(16, 0x5A);
        const auto original_invalid = invalid, original_block = block;
        EXPECT_THROW(deal.EncryptBlock(invalid, block), std::exception);
        EXPECT_THROW(deal.DecryptBlock(invalid, block), std::exception);
        EXPECT_THROW(deal.EncryptBlock(block, invalid), std::exception);
        EXPECT_THROW(deal.DecryptBlock(block, invalid), std::exception);
        EXPECT_EQ(invalid, original_invalid);
        EXPECT_EQ(block, original_block);
    }
}

TEST(DEAL, RandomBlocksRekeyingAndOverlappingBuffers) {
    std::mt19937 engine(42);
    DEALAlgorithm encryptor, decryptor;
    for (int sample = 0; sample < 24; ++sample) {
        Bytes key(16), plain(16), encrypted(16), restored(16);
        for (auto& byte : key) byte = static_cast<std::uint8_t>(engine());
        for (auto& byte : plain) byte = static_cast<std::uint8_t>(engine());
        encryptor.SetEncryptionKey(key);
        decryptor.SetDecryptionKey(key);
        encryptor.EncryptBlock(plain, encrypted);
        decryptor.DecryptBlock(encrypted, restored);
        EXPECT_EQ(restored, plain);
        Bytes overlap(17);
        std::copy(plain.begin(), plain.end(), overlap.begin());
        encryptor.EncryptBlock(std::span(overlap).first(16), std::span(overlap).last(16));
        EXPECT_TRUE(std::equal(encrypted.begin(), encrypted.end(), overlap.begin() + 1));
        decryptor.DecryptBlock(std::span(overlap).last(16), std::span(overlap).first(16));
        EXPECT_TRUE(std::equal(plain.begin(), plain.end(), overlap.begin()));
    }
}

TEST(DEAL, EveryMasterKeyBitParticipatesInExpansion) {
    DealKeyExpander expander;
    Bytes key(16);
    const auto baseline = expander.ExpandKey(key);
    for (std::size_t bit = 0; bit < 128; ++bit) {
        key[bit / 8] ^= 1u << (bit % 8);
        EXPECT_NE(expander.ExpandKey(key), baseline) << bit;
        key[bit / 8] ^= 1u << (bit % 8);
    }
}

} // namespace
