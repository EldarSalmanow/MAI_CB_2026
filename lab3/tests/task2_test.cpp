#include <lab3/rijndael_algorithm.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <future>
#include <random>
#include <string_view>


using namespace crypto;
using namespace crypto::symmetric;

namespace {

    auto FromHex(
        std::string_view hex
    ) -> std::vector<std::uint8_t> {
        const auto nibble = [] (char digit) -> std::uint8_t {
            return static_cast<std::uint8_t>(digit <= '9' ? digit - '0' : digit - 'a' + 10);
        };

        std::vector<std::uint8_t> bytes(hex.size() / 2);

        for (std::size_t i = 0; i < bytes.size(); ++i) {
            bytes[i] = static_cast<std::uint8_t>((nibble(hex[2 * i]) << 4) | nibble(hex[2 * i + 1]));
        }

        return bytes;
    }

    struct RijndaelVector {
        BlockLength block_length;
        KeyLength key_length;
        std::string_view key;
        std::string_view plaintext;
        std::string_view ciphertext;
    };

    // AES: FIPS 197, Appendix C. Wider blocks: Brian Gladman's vectors, also published at
    // https://github.com/bcgit/bc-java/blob/main/core/src/test/java/org/bouncycastle/crypto/test/RijndaelTest.java
    const std::array<RijndaelVector, 9> kVectors = {{
        {
            BlockLength::Bits128, KeyLength::Bits128,
            "000102030405060708090a0b0c0d0e0f",
            "00112233445566778899aabbccddeeff",
            "69c4e0d86a7b0430d8cdb78070b4c55a"
        },
        {
            BlockLength::Bits128, KeyLength::Bits192,
            "000102030405060708090a0b0c0d0e0f1011121314151617",
            "00112233445566778899aabbccddeeff",
            "dda97ca4864cdfe06eaf70a0ec0d7191"
        },
        {
            BlockLength::Bits128, KeyLength::Bits256,
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "00112233445566778899aabbccddeeff",
            "8ea2b7ca516745bfeafc49904b496089"
        },
        {
            BlockLength::Bits192, KeyLength::Bits128,
            "2b7e151628aed2a6abf7158809cf4f3c",
            "3243f6a8885a308d313198a2e03707344a4093822299f31d",
            "b24d275489e82bb8f7375e0d5fcdb1f481757c538b65148a"
        },
        {
            BlockLength::Bits192, KeyLength::Bits192,
            "2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da5",
            "3243f6a8885a308d313198a2e03707344a4093822299f31d",
            "725ae43b5f3161de806a7c93e0bca93c967ec1ae1b71e1cf"
        },
        {
            BlockLength::Bits192, KeyLength::Bits256,
            "2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe",
            "3243f6a8885a308d313198a2e03707344a4093822299f31d",
            "0ebacf199e3315c2e34b24fcc7c46ef4388aa475d66c194c"
        },
        {
            BlockLength::Bits256, KeyLength::Bits128,
            "2b7e151628aed2a6abf7158809cf4f3c",
            "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c8",
            "7d15479076b69a46ffb3b3beae97ad8313f622f67fedb487de9f06b9ed9c8f19"
        },
        {
            BlockLength::Bits256, KeyLength::Bits192,
            "2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da5",
            "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c8",
            "5d7101727bb25781bf6715b0e6955282b9610e23a43c2eb062699f0ebf5887b2"
        },
        {
            BlockLength::Bits256, KeyLength::Bits256,
            "2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe",
            "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c8",
            "a49406115dfb30a40418aafa4869b7c6a886ff31602a7dd19c889dc64f7e4e7a"
        }
    }};

} // namespace

class RijndaelVectorTest : public ::testing::TestWithParam<RijndaelVector> {};

TEST_P(RijndaelVectorTest, EncryptsKnownVector) {
    const auto &vector = GetParam();
    const auto plaintext = FromHex(vector.plaintext);
    std::vector<std::uint8_t> ciphertext(plaintext.size());

    RijndaelAlgorithm algorithm(vector.block_length, vector.key_length, 0x1B, {});
    algorithm.SetEncryptionKey(FromHex(vector.key));
    algorithm.EncryptBlock(plaintext, ciphertext);

    EXPECT_EQ(ciphertext, FromHex(vector.ciphertext));
}

TEST_P(RijndaelVectorTest, DecryptsKnownVector) {
    const auto &vector = GetParam();
    const auto ciphertext = FromHex(vector.ciphertext);
    std::vector<std::uint8_t> plaintext(ciphertext.size());

    RijndaelAlgorithm algorithm(vector.block_length, vector.key_length, 0x1B, {});
    algorithm.SetDecryptionKey(FromHex(vector.key));
    algorithm.DecryptBlock(ciphertext, plaintext);

    EXPECT_EQ(plaintext, FromHex(vector.plaintext));
}

TEST_P(RijndaelVectorTest, SupportsInPlaceAndOverlappingBuffers) {
    const auto &vector = GetParam();
    const auto plaintext = FromHex(vector.plaintext);
    const auto ciphertext = FromHex(vector.ciphertext);

    RijndaelAlgorithm algorithm(vector.block_length, vector.key_length, 0x1B, {});
    algorithm.SetEncryptionKey(FromHex(vector.key));

    auto block = plaintext;
    algorithm.EncryptBlock(block, block);
    EXPECT_EQ(block, ciphertext);
    algorithm.DecryptBlock(block, block);
    EXPECT_EQ(block, plaintext);

    std::vector<std::uint8_t> buffer(plaintext.size() + 1);
    std::copy(plaintext.begin(), plaintext.end(), buffer.begin());

    const auto left = std::span<std::uint8_t>(buffer).first(plaintext.size());
    const auto right = std::span<std::uint8_t>(buffer).subspan(1);

    algorithm.EncryptBlock(left, right);
    EXPECT_TRUE(std::equal(right.begin(), right.end(), ciphertext.begin()));
    algorithm.DecryptBlock(right, left);
    EXPECT_TRUE(std::equal(left.begin(), left.end(), plaintext.begin()));
}

INSTANTIATE_TEST_SUITE_P(AllLengths, RijndaelVectorTest, ::testing::ValuesIn(kVectors));

TEST(RijndaelContextTest, SBoxesMatchKnownValuesAndAreMutuallyInverseForEveryModulus) {
    const galois::GFService service;

    for (const auto modulus : service.GenerateAllIrreduciblePolynomials()) {
        SCOPED_TRACE(static_cast<int>(modulus));

        const RijndaelContext context(BlockLength::Bits128, KeyLength::Bits128, modulus);
        const auto &inv_sbox = context.InvSBox();
        const auto &sbox = context.SBox();

        ASSERT_EQ(sbox.size(), 256U);
        ASSERT_EQ(inv_sbox.size(), 256U);
        EXPECT_EQ(sbox[0], 0x63);
        EXPECT_EQ(inv_sbox[0x63], 0);

        for (std::size_t i = 0; i < sbox.size(); ++i) {
            EXPECT_EQ(inv_sbox[sbox[i]], i);
            EXPECT_EQ(sbox[inv_sbox[i]], i);
        }

        if (modulus == 0x1B) {
            EXPECT_EQ(sbox[0x53], 0xED);
            EXPECT_EQ(sbox[0xFF], 0x16);
            EXPECT_EQ(inv_sbox[0xED], 0x53);
        }
    }
}

TEST(RijndaelContextTest, InitializesSBoxesSafelyDuringConcurrentAccess) {
    const RijndaelContext context(BlockLength::Bits128, KeyLength::Bits128, 0x1B);
    std::array<std::future<bool>, 8> results;

    for (std::size_t i = 0; i < results.size(); ++i) {
        results[i] = std::async(std::launch::async, [&context, i] {
            const auto &first = i % 2 == 0 ? context.SBox() : context.InvSBox();
            const auto &second = i % 2 == 0 ? context.InvSBox() : context.SBox();

            for (std::size_t j = 0; j < first.size(); ++j) {
                if (second[first[j]] != j) {
                    return false;
                }
            }

            return true;
        });
    }

    for (auto &result : results) {
        EXPECT_TRUE(result.get());
    }
}

TEST(RijndaelKeyExpanderTest, MatchesAes128RoundKeys) {
    const auto context = std::make_shared<RijndaelContext>(BlockLength::Bits128, KeyLength::Bits128, 0x1B);
    const RijndaelKeyExpander expander(context);
    const auto key = FromHex(kVectors[0].key);
    const auto keys = expander.ExpandKey(key);

    ASSERT_EQ(keys.size(), 11U);
    EXPECT_EQ(keys.front(), key);
    EXPECT_EQ(keys[1], FromHex("d6aa74fdd2af72fadaa678f1d6ab76fe"));
    EXPECT_EQ(keys.back(), FromHex("13111d7fe3944a17f307a78b4d2b30c5"));
}

TEST(RijndaelRoundFunctionTest, MatchesAes128FirstAndFinalRoundStates) {
    const auto context = std::make_shared<RijndaelContext>(BlockLength::Bits128, KeyLength::Bits128, 0x1B);
    const RijndaelKeyExpander expander(context);
    const auto keys = expander.ExpandKey(FromHex(kVectors[0].key));
    const RijndaelEncryptRound encrypt_round(context);
    const RijndaelDecryptRound decrypt_round(context);
    const IRoundFunction &encrypt_function = encrypt_round;
    const IRoundFunction &decrypt_function = decrypt_round;
    std::vector<std::uint8_t> output(16);

    encrypt_function.ProcessBlock(FromHex("00102030405060708090a0b0c0d0e0f0"), keys[1], output);
    EXPECT_EQ(output, FromHex("89d810e8855ace682d1843d8cb128fe4"));

    encrypt_round.ProcessFinalBlock(FromHex("bd6e7c3df2b5779e0b61216e8b10b689"), keys.back(), output);
    EXPECT_EQ(output, FromHex(kVectors[0].ciphertext));

    decrypt_function.ProcessBlock(FromHex("7ad5fda789ef4e272bca100b3d9ff59f"), keys[9], output);
    EXPECT_EQ(output, FromHex("54d990a16ba09ab596bbf40ea111702f"));

    decrypt_round.ProcessFinalBlock(FromHex("6353e08c0960e104cd70b751bacad0e7"), keys.front(), output);
    EXPECT_EQ(output, FromHex(kVectors[0].plaintext));
}

TEST(RijndaelRoundFunctionTest, SupportsInPlaceAndOverlappingBuffers) {
    const auto context = std::make_shared<RijndaelContext>(BlockLength::Bits128, KeyLength::Bits128, 0x1B);
    const RijndaelKeyExpander expander(context);
    const auto keys = expander.ExpandKey(FromHex(kVectors[0].key));
    const RijndaelEncryptRound encrypt_round(context);
    const RijndaelDecryptRound decrypt_round(context);

    std::vector<std::uint8_t> buffer(17);
    const auto left = std::span<std::uint8_t>(buffer).first(16);
    const auto right = std::span<std::uint8_t>(buffer).subspan(1);

    const auto encrypt_input = FromHex("00102030405060708090a0b0c0d0e0f0");
    const auto encrypt_expected = FromHex("89d810e8855ace682d1843d8cb128fe4");
    std::copy(encrypt_input.begin(), encrypt_input.end(), left.begin());
    encrypt_round.ProcessBlock(left, keys[1], right);
    EXPECT_TRUE(std::equal(right.begin(), right.end(), encrypt_expected.begin()));

    const auto decrypt_input = FromHex("7ad5fda789ef4e272bca100b3d9ff59f");
    const auto decrypt_expected = FromHex("54d990a16ba09ab596bbf40ea111702f");
    std::copy(decrypt_input.begin(), decrypt_input.end(), right.begin());
    decrypt_round.ProcessBlock(right, keys[9], left);
    EXPECT_TRUE(std::equal(left.begin(), left.end(), decrypt_expected.begin()));

    auto block = FromHex("bd6e7c3df2b5779e0b61216e8b10b689");
    encrypt_round.ProcessFinalBlock(block, keys.back(), block);
    EXPECT_EQ(block, FromHex(kVectors[0].ciphertext));

    block = FromHex("6353e08c0960e104cd70b751bacad0e7");
    decrypt_round.ProcessFinalBlock(block, keys.front(), block);
    EXPECT_EQ(block, FromHex(kVectors[0].plaintext));
}

TEST(RijndaelRoundFunctionTest, AppliesKnownRoundsToExistingState) {
    const auto context = std::make_shared<RijndaelContext>(BlockLength::Bits128, KeyLength::Bits128, 0x1B);
    const RijndaelKeyExpander expander(context);
    const auto keys = expander.ExpandKey(FromHex(kVectors[0].key));
    const RijndaelEncryptRound encrypt_round(context);
    const RijndaelDecryptRound decrypt_round(context);
    std::vector<std::uint8_t> output(16);

    RijndaelState encrypt_state(FromHex(kVectors[0].plaintext));
    encrypt_round.ApplyInitialKey(encrypt_state, keys.front());
    encrypt_state.Store(output);
    EXPECT_EQ(output, FromHex("00102030405060708090a0b0c0d0e0f0"));

    encrypt_round.ApplyRound(encrypt_state, keys[1]);
    encrypt_state.Store(output);
    EXPECT_EQ(output, FromHex("89d810e8855ace682d1843d8cb128fe4"));

    RijndaelState encrypt_final_state(FromHex("bd6e7c3df2b5779e0b61216e8b10b689"));
    encrypt_round.ApplyFinalRound(encrypt_final_state, keys.back());
    encrypt_final_state.Store(output);
    EXPECT_EQ(output, FromHex(kVectors[0].ciphertext));

    RijndaelState decrypt_state(FromHex(kVectors[0].ciphertext));
    decrypt_round.ApplyInitialKey(decrypt_state, keys.back());
    decrypt_state.Store(output);
    EXPECT_EQ(output, FromHex("7ad5fda789ef4e272bca100b3d9ff59f"));

    decrypt_round.ApplyRound(decrypt_state, keys[9]);
    decrypt_state.Store(output);
    EXPECT_EQ(output, FromHex("54d990a16ba09ab596bbf40ea111702f"));

    RijndaelState decrypt_final_state(FromHex("6353e08c0960e104cd70b751bacad0e7"));
    decrypt_round.ApplyFinalRound(decrypt_final_state, keys.front());
    decrypt_final_state.Store(output);
    EXPECT_EQ(output, FromHex(kVectors[0].plaintext));
}

TEST(RijndaelValidationTest, RejectsInvalidStatesAndKeysBeforeChangingState) {
    for (std::size_t size : {0U, 15U, 17U, 33U}) {
        EXPECT_THROW((void)RijndaelState(std::vector<std::uint8_t>(size)), std::invalid_argument);
    }

    const auto context = std::make_shared<RijndaelContext>(BlockLength::Bits128, KeyLength::Bits128, 0x1B);
    const RijndaelEncryptRound encrypt_round(context);
    const RijndaelDecryptRound decrypt_round(context);
    const std::array<const RijndaelRoundFunction *, 2> rounds = {&encrypt_round, &decrypt_round};
    const auto input = FromHex(kVectors[0].plaintext);
    const std::vector<std::uint8_t> key(16);
    std::vector<std::uint8_t> output(16);
    RijndaelState state(input);
    RijndaelState incompatible_state(std::vector<std::uint8_t>(24));

    for (const auto *round : rounds) {
        EXPECT_THROW(round->ApplyInitialKey(state, {}), std::invalid_argument);
        EXPECT_THROW(round->ApplyRound(state, {}), std::invalid_argument);
        EXPECT_THROW(round->ApplyFinalRound(state, {}), std::invalid_argument);
        EXPECT_THROW(round->ApplyInitialKey(incompatible_state, key), std::invalid_argument);
        EXPECT_THROW(round->ApplyRound(incompatible_state, key), std::invalid_argument);
        EXPECT_THROW(round->ApplyFinalRound(incompatible_state, key), std::invalid_argument);
    }

    EXPECT_THROW(state.Store(std::span<std::uint8_t>(output).first(15)), std::invalid_argument);
    state.Store(output);
    EXPECT_EQ(output, input);
}

TEST(RijndaelAlgorithmTest, RoundTripsMultipleBlocksForEveryLengthAndModulus) {
    const galois::GFService service;
    std::mt19937 generator(0x52494A4E);
    std::uniform_int_distribution<unsigned int> distribution(0, 255);
    const auto random_byte = [&] { return static_cast<std::uint8_t>(distribution(generator)); };

    for (const auto modulus : service.GenerateAllIrreduciblePolynomials()) {
        for (const auto &vector : kVectors) {
            SCOPED_TRACE(::testing::Message() << "Modulus: " << static_cast<int>(modulus)
                << ", block: " << static_cast<std::size_t>(vector.block_length)
                << ", key: " << static_cast<std::size_t>(vector.key_length));

            RijndaelAlgorithm algorithm(vector.block_length, vector.key_length, modulus, service);
            std::vector<std::uint8_t> key(static_cast<std::size_t>(vector.key_length));
            std::vector<std::uint8_t> plaintext(algorithm.BlockSize());
            std::vector<std::uint8_t> ciphertext(algorithm.BlockSize());
            std::vector<std::uint8_t> restored(algorithm.BlockSize());
            std::vector<std::uint8_t> repeated(algorithm.BlockSize());

            std::generate(key.begin(), key.end(), random_byte);
            algorithm.SetEncryptionKey(key);

            for (std::size_t i = 0; i < 4; ++i) {
                std::generate(plaintext.begin(), plaintext.end(), random_byte);

                algorithm.EncryptBlock(plaintext, ciphertext);
                algorithm.EncryptBlock(plaintext, repeated);
                EXPECT_EQ(repeated, ciphertext);

                algorithm.DecryptBlock(ciphertext, restored);
                EXPECT_EQ(restored, plaintext);
            }

            std::generate(key.begin(), key.end(), random_byte);
            algorithm.SetDecryptionKey(key);
            algorithm.EncryptBlock(plaintext, ciphertext);
            algorithm.DecryptBlock(ciphertext, restored);
            EXPECT_EQ(restored, plaintext);
        }
    }
}

TEST(RijndaelValidationTest, RejectsInvalidConfiguration) {
    EXPECT_THROW(
        RijndaelContext(static_cast<BlockLength>(0), KeyLength::Bits128, 0x1B),
        std::invalid_argument
    );
    EXPECT_THROW(
        RijndaelContext(BlockLength::Bits128, static_cast<KeyLength>(20), 0x1B),
        std::invalid_argument
    );
    EXPECT_THROW(
        RijndaelContext(BlockLength::Bits128, KeyLength::Bits128, 0x01),
        galois::ReducibleModulusException
    );
    EXPECT_THROW(RijndaelKeyExpander(nullptr), std::invalid_argument);
    EXPECT_THROW(RijndaelEncryptRound(nullptr), std::invalid_argument);
    EXPECT_THROW(RijndaelDecryptRound(nullptr), std::invalid_argument);
}

TEST(RijndaelValidationTest, RejectsMissingKeyAndInvalidBufferSizesWithoutChangingOutput) {
    RijndaelAlgorithm algorithm(BlockLength::Bits128, KeyLength::Bits128, 0x1B, {});
    const std::vector<std::uint8_t> key(16);
    const std::vector<std::uint8_t> block(16);
    std::vector<std::uint8_t> output(16, 0xAA);
    const auto original_output = output;

    EXPECT_THROW(algorithm.EncryptBlock(block, output), std::runtime_error);
    EXPECT_THROW(algorithm.DecryptBlock(block, output), std::runtime_error);
    EXPECT_THROW(algorithm.SetEncryptionKey({}), std::invalid_argument);
    EXPECT_THROW(algorithm.SetDecryptionKey(std::vector<std::uint8_t>(32)), std::invalid_argument);

    algorithm.SetEncryptionKey(key);
    EXPECT_THROW(algorithm.EncryptBlock({}, output), std::invalid_argument);
    EXPECT_THROW(algorithm.EncryptBlock(std::vector<std::uint8_t>(17), output), std::invalid_argument);
    EXPECT_THROW(algorithm.EncryptBlock(block, std::span<std::uint8_t>(output).first(15)), std::invalid_argument);
    EXPECT_THROW(algorithm.DecryptBlock({}, output), std::invalid_argument);
    EXPECT_THROW(algorithm.DecryptBlock(block, std::span<std::uint8_t>(output).first(15)), std::invalid_argument);

    const auto context = std::make_shared<RijndaelContext>(BlockLength::Bits128, KeyLength::Bits128, 0x1B);
    const RijndaelEncryptRound encrypt_round(context);
    const RijndaelDecryptRound decrypt_round(context);
    const std::array<const RijndaelRoundFunction *, 2> rounds = {&encrypt_round, &decrypt_round};

    for (const auto *round : rounds) {
        EXPECT_THROW(round->ProcessBlock({}, key, output), std::invalid_argument);
        EXPECT_THROW(round->ProcessBlock(block, {}, output), std::invalid_argument);
        EXPECT_THROW(round->ProcessFinalBlock({}, key, output), std::invalid_argument);
        EXPECT_THROW(round->ProcessFinalBlock(block, {}, output), std::invalid_argument);
        EXPECT_THROW(round->ProcessFinalBlock(block, key, std::span<std::uint8_t>(output).first(15)), std::invalid_argument);
    }

    EXPECT_EQ(output, original_output);
}

TEST(RijndaelAlgorithmTest, RetainsPreviousKeyAfterRejectedKeyChange) {
    RijndaelAlgorithm algorithm(BlockLength::Bits128, KeyLength::Bits128, 0x1B, {});
    algorithm.SetEncryptionKey(FromHex(kVectors[0].key));

    EXPECT_THROW(algorithm.SetEncryptionKey({}), std::invalid_argument);
    EXPECT_THROW(algorithm.SetDecryptionKey({}), std::invalid_argument);

    std::vector<std::uint8_t> ciphertext(16);
    algorithm.EncryptBlock(FromHex(kVectors[0].plaintext), ciphertext);
    EXPECT_EQ(ciphertext, FromHex(kVectors[0].ciphertext));
}
