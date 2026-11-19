#include <lab3/rijndael_algorithm.h>
#include <lab1/cipher_context.h>

#include <gtest/gtest.h>


using namespace crypto;
using namespace crypto::symmetric;

namespace {

    namespace fs = std::filesystem;

    using Bytes = std::vector<std::uint8_t>;
    using Context = SymmetricCipherContext<RijndaelAlgorithm>;

    constexpr std::array BLOCK_LENGTHS = {BlockLength::Bits128, BlockLength::Bits192, BlockLength::Bits256};
    constexpr std::array KEY_LENGTHS = {KeyLength::Bits128, KeyLength::Bits192, KeyLength::Bits256};
    constexpr std::array CIPHER_MODES = {
        CipherMode::ECB, CipherMode::CBC, CipherMode::PCBC,
        CipherMode::CFB, CipherMode::OFB, CipherMode::CTR, CipherMode::RandomDelta
    };
    constexpr std::array PADDING_MODES = {
        PaddingMode::Zeros, PaddingMode::ANSI_X923, PaddingMode::PKCS7, PaddingMode::ISO_10126
    };

    struct CipherCase {
        BlockLength block_length;
        KeyLength key_length;
        std::uint8_t modulus;
        CipherMode mode;
        PaddingMode padding;
        std::shared_ptr<const RijndaelAlgorithm> cipher;
    };

    auto ModeName(
        CipherMode mode
    ) -> std::string_view {
        switch (mode) {
            case CipherMode::ECB: return "ECB";
            case CipherMode::CBC: return "CBC";
            case CipherMode::PCBC: return "PCBC";
            case CipherMode::CFB: return "CFB";
            case CipherMode::OFB: return "OFB";
            case CipherMode::CTR: return "CTR";
            case CipherMode::RandomDelta: return "RandomDelta";
        }

        throw std::invalid_argument("Unknown test cipher mode!");
    }

    auto PaddingName(
        PaddingMode padding
    ) -> std::string_view {
        switch (padding) {
            case PaddingMode::Zeros: return "Zeros";
            case PaddingMode::ANSI_X923: return "ANSI_X923";
            case PaddingMode::PKCS7: return "PKCS7";
            case PaddingMode::ISO_10126: return "ISO_10126";
        }

        throw std::invalid_argument("Unknown test padding mode!");
    }

    auto RequiresPadding(
        CipherMode mode
    ) -> bool {
        return mode == CipherMode::ECB || mode == CipherMode::CBC || mode == CipherMode::PCBC;
    }

    auto AllCases() -> const std::vector<CipherCase> & {
        static const auto cases = [] {
            const galois::GFService service;
            const auto moduli = service.GenerateAllIrreduciblePolynomials();
            std::vector<CipherCase> result;
            result.reserve(BLOCK_LENGTHS.size() * KEY_LENGTHS.size() * moduli.size()
                * CIPHER_MODES.size() * PADDING_MODES.size());

            for (const auto block_length : BLOCK_LENGTHS) {
                for (const auto key_length : KEY_LENGTHS) {
                    for (const auto modulus : moduli) {
                        // Copies share immutable field settings and lazily initialized S-boxes.
                        const auto cipher = std::make_shared<const RijndaelAlgorithm>(
                            block_length, key_length, modulus, service
                        );

                        for (const auto mode : CIPHER_MODES) {
                            for (const auto padding : PADDING_MODES) {
                                result.push_back({block_length, key_length, modulus, mode, padding, cipher});
                            }
                        }
                    }
                }
            }

            return result;
        }();

        return cases;
    }

    template<typename Predicate>
    auto SelectCases(
        Predicate predicate
    ) -> std::vector<CipherCase> {
        std::vector<CipherCase> result;
        std::copy_if(AllCases().begin(), AllCases().end(), std::back_inserter(result), predicate);

        return result;
    }

    auto BoundaryCases() -> std::vector<CipherCase> {
        return SelectCases([] (const CipherCase &test_case) {
            return test_case.key_length == KeyLength::Bits256 && test_case.modulus == 0x1D;
        });
    }

    auto CaseName(
        const ::testing::TestParamInfo<CipherCase> &info
    ) -> std::string {
        const auto &test_case = info.param;
        std::ostringstream name;
        name << "Block" << static_cast<std::size_t>(test_case.block_length) * 8
             << "_Key" << static_cast<std::size_t>(test_case.key_length) * 8
             << "_Modulus" << std::hex << std::uppercase << std::setfill('0') << std::setw(2)
             << static_cast<unsigned int>(test_case.modulus)
             << '_' << ModeName(test_case.mode) << '_' << PaddingName(test_case.padding);

        return name.str();
    }

    auto RandomBytes(
        std::size_t size,
        std::uint32_t seed = 0x52494A4E
    ) -> Bytes {
        std::mt19937 generator(seed);
        Bytes bytes(size);

        for (auto &byte : bytes) {
            byte = static_cast<std::uint8_t>(generator() & 0xFFU);
        }

        return bytes;
    }

    auto FromHex(
        std::string_view hex
    ) -> Bytes {
        if (hex.size() % 2 != 0) {
            throw std::invalid_argument("Invalid test hexadecimal string!");
        }

        Bytes bytes(hex.size() / 2);

        for (std::size_t i = 0; i < bytes.size(); ++i) {
            unsigned int byte = 0;
            const auto *first = hex.data() + 2 * i;
            const auto [end, error] = std::from_chars(first, first + 2, byte, 16);

            if (error != std::errc{} || end != first + 2) {
                throw std::invalid_argument("Invalid test hexadecimal byte!");
            }

            bytes[i] = static_cast<std::uint8_t>(byte);
        }

        return bytes;
    }

    auto WriteFile(
        const fs::path &path,
        std::span<const std::uint8_t> bytes
    ) -> void {
        std::ofstream stream;
        stream.exceptions(std::ios::badbit | std::ios::failbit);
        stream.open(path, std::ios::binary | std::ios::trunc);

        if (!bytes.empty()) {
            stream.write(reinterpret_cast<const char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        }

        stream.close();
    }

    auto ReadFile(
        const fs::path &path
    ) -> Bytes {
        std::ifstream stream(path, std::ios::binary);

        if (!stream) {
            throw std::runtime_error("Failed to open a test file!");
        }

        stream.exceptions(std::ios::badbit);

        return Bytes(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
    }

    class TemporaryDirectory {
    public:
        TemporaryDirectory() {
            static std::atomic<std::uint64_t> sequence = 0;
            const auto timestamp = std::chrono::steady_clock::now().time_since_epoch().count();

            for (std::size_t attempt = 0; attempt < 16; ++attempt) {
                const auto candidate = fs::temp_directory_path()
                    / ("mai_rijndael_" + std::to_string(timestamp) + '_' + std::to_string(sequence.fetch_add(1)));

                if (fs::create_directory(candidate)) {
                    path_ = candidate;

                    return;
                }
            }

            throw std::runtime_error("Failed to create a temporary test directory!");
        }

        TemporaryDirectory(const TemporaryDirectory &) = delete;

    public:
        ~TemporaryDirectory() {
            // The path is assigned only after this instance creates the directory.
            std::error_code error;
            fs::remove_all(path_, error);
            EXPECT_FALSE(error) << "Failed to remove test directory: " << path_ << ": " << error.message();
        }

    public:
        auto Path() const -> const fs::path & {
            return path_;
        }

        auto operator=(const TemporaryDirectory &) -> TemporaryDirectory & = delete;

    private:
        fs::path path_;
    };

    class RijndaelContextTest : public ::testing::TestWithParam<CipherCase> {
    protected:
        auto SetUp() -> void override {
            block_size_ = static_cast<std::size_t>(GetParam().block_length);
            key_ = RandomBytes(static_cast<std::size_t>(GetParam().key_length), 0x4B455900U + GetParam().modulus);
            params_.iv = RandomBytes(block_size_, 0x49560000U + GetParam().modulus);
            params_.additional_args.emplace_back(std::uint64_t{17});
        }

        auto MakeContext() const -> Context {
            return MakeContext(params_);
        }

        auto MakeContext(
            const CipherParams &params
        ) const -> Context {
            return Context(key_, GetParam().mode, GetParam().padding, params, *GetParam().cipher);
        }

        auto ExpectedCiphertextSize(
            std::size_t size
        ) const -> std::size_t {
            return RequiresPadding(GetParam().mode) ? size + block_size_ - size % block_size_ : size;
        }

        auto ExpectedPlaintext(
            Bytes bytes
        ) const -> Bytes {
            if (RequiresPadding(GetParam().mode) && GetParam().padding == PaddingMode::Zeros) {
                bytes.resize(ExpectedCiphertextSize(bytes.size()), 0);
            }

            return bytes;
        }

        auto ExpectMatchingCiphertexts(
            const Bytes &first,
            const Bytes &second,
            std::size_t plaintext_size
        ) const -> void {
            ASSERT_EQ(first.size(), second.size());

            // ISO 10126 changes only the final padded plaintext block.
            const auto comparable_size = RequiresPadding(GetParam().mode) && GetParam().padding == PaddingMode::ISO_10126
                ? plaintext_size - plaintext_size % block_size_
                : first.size();

            EXPECT_TRUE(std::equal(first.begin(), first.begin() + static_cast<std::ptrdiff_t>(comparable_size), second.begin()));
        }

        auto InvalidPaddingCiphertext(
            const Bytes &padded_plaintext
        ) const -> Bytes {
            auto cipher = *GetParam().cipher;
            cipher.SetEncryptionKey(key_);
            auto block = padded_plaintext;

            if (GetParam().mode != CipherMode::ECB) {
                for (std::size_t i = 0; i < block.size(); ++i) {
                    block[i] ^= params_.iv[i];
                }
            }

            Bytes ciphertext(block_size_);
            cipher.EncryptBlock(block, ciphertext);

            return ciphertext;
        }

    protected:
        std::size_t block_size_ = 0;
        Bytes key_;
        CipherParams params_;
    };

    class RijndaelPaddingTest : public RijndaelContextTest {};
    class RijndaelBoundaryTest : public RijndaelContextTest {};
    class RijndaelCounterTest : public RijndaelContextTest {};

    TEST(RijndaelCoverageTest, IncludesEverySupportedCombination) {
        const galois::GFService service;

        EXPECT_EQ(service.GenerateAllIrreduciblePolynomials().size(), 30U);
        EXPECT_EQ(AllCases().size(), 3U * 3U * 30U * 7U * 4U);
    }

    TEST_P(RijndaelContextTest, MemoryRoundTripAndStateReset) {
        auto context = MakeContext();
        const std::array sizes = {
            std::size_t{0}, std::size_t{1}, block_size_ - 1, block_size_,
            block_size_ + 1, 2 * block_size_, 2 * block_size_ + 1
        };

        for (const auto size : sizes) {
            SCOPED_TRACE(size);
            const auto plaintext = RandomBytes(size);
            const auto ciphertext = context.EncryptAsync(plaintext).get();

            EXPECT_EQ(ciphertext.size(), ExpectedCiphertextSize(size));
            EXPECT_EQ(context.DecryptAsync(ciphertext).get(), ExpectedPlaintext(plaintext));
        }

        const auto plaintext = RandomBytes(2 * block_size_ + 3);
        const auto first = context.EncryptAsync(plaintext).get();
        auto fresh = MakeContext();
        EXPECT_EQ(fresh.DecryptAsync(first).get(), ExpectedPlaintext(plaintext));

        context.EncryptAsync(RandomBytes(block_size_ + 5, 123)).get();
        const auto repeated = context.EncryptAsync(plaintext).get();
        ExpectMatchingCiphertexts(first, repeated, plaintext.size());
        EXPECT_EQ(context.DecryptAsync(repeated).get(), ExpectedPlaintext(plaintext));
    }

    TEST_P(RijndaelContextTest, FileRoundTripAndMemoryCompatibility) {
        const TemporaryDirectory directory;
        const auto input = directory.Path() / "input file.bin";
        const auto encrypted = directory.Path() / "encrypted.bin";
        const auto restored = directory.Path() / "restored.bin";
        auto plaintext = RandomBytes(2 * block_size_ + 3);
        std::fill(plaintext.end() - 3, plaintext.end(), 0);
        plaintext.front() = 0xFF;
        WriteFile(input, plaintext);

        auto context = MakeContext();
        context.EncryptFileAsync(input, encrypted).get();
        EXPECT_EQ(fs::file_size(encrypted), ExpectedCiphertextSize(plaintext.size()));

        const auto file_ciphertext = ReadFile(encrypted);
        const auto memory_ciphertext = context.EncryptAsync(plaintext).get();
        ExpectMatchingCiphertexts(file_ciphertext, memory_ciphertext, plaintext.size());

        auto fresh = MakeContext();
        fresh.DecryptFileAsync(encrypted, restored).get();
        EXPECT_EQ(ReadFile(restored), ExpectedPlaintext(plaintext));
        EXPECT_EQ(fresh.DecryptAsync(file_ciphertext).get(), ExpectedPlaintext(plaintext));
        EXPECT_EQ(ReadFile(input), plaintext);
    }

    TEST_P(RijndaelPaddingTest, RejectsInvalidCiphertextLengths) {
        auto context = MakeContext();

        for (const auto size : {std::size_t{0}, block_size_ - 1, block_size_ + 1}) {
            SCOPED_TRACE(size);
            EXPECT_THROW(context.DecryptAsync(Bytes(size)).get(), std::invalid_argument);
        }
    }

    TEST_P(RijndaelPaddingTest, ValidatesPaddingLengthAndContents) {
        auto context = MakeContext();

        for (const auto length : {std::size_t{0}, block_size_ + 1}) {
            SCOPED_TRACE(length);
            Bytes invalid(block_size_, 0);
            invalid.back() = static_cast<std::uint8_t>(length);
            const auto ciphertext = InvalidPaddingCiphertext(invalid);

            if (GetParam().padding == PaddingMode::Zeros) {
                EXPECT_EQ(context.DecryptAsync(ciphertext).get(), invalid);
            } else {
                EXPECT_THROW(context.DecryptAsync(ciphertext).get(), std::runtime_error);
            }
        }

        Bytes invalid(block_size_, 0);
        invalid[block_size_ - 2] = 0x7F;
        invalid.back() = 2;
        const auto ciphertext = InvalidPaddingCiphertext(invalid);

        if (GetParam().padding == PaddingMode::Zeros) {
            EXPECT_EQ(context.DecryptAsync(ciphertext).get(), invalid);
        } else if (GetParam().padding == PaddingMode::ISO_10126) {
            invalid.resize(block_size_ - 2);
            EXPECT_EQ(context.DecryptAsync(ciphertext).get(), invalid);
        } else {
            EXPECT_THROW(context.DecryptAsync(ciphertext).get(), std::runtime_error);
        }
    }

    TEST_P(RijndaelBoundaryTest, EveryTailLengthAndAllByteValues) {
        auto context = MakeContext();

        for (std::size_t size = 0; size <= 2 * block_size_ + 1; ++size) {
            SCOPED_TRACE(size);
            const auto plaintext = RandomBytes(size);
            const auto ciphertext = context.EncryptAsync(plaintext).get();

            EXPECT_EQ(ciphertext.size(), ExpectedCiphertextSize(size));
            EXPECT_EQ(context.DecryptAsync(ciphertext).get(), ExpectedPlaintext(plaintext));
        }

        Bytes all_bytes(259, 0);

        for (std::size_t i = 0; i < 256; ++i) {
            all_bytes[i] = static_cast<std::uint8_t>(i);
        }

        EXPECT_EQ(context.DecryptAsync(context.EncryptAsync(all_bytes).get()).get(), ExpectedPlaintext(all_bytes));

        const Bytes zero_bytes(block_size_ + 3, 0);
        EXPECT_EQ(context.DecryptAsync(context.EncryptAsync(zero_bytes).get()).get(), ExpectedPlaintext(zero_bytes));
    }

    TEST_P(RijndaelBoundaryTest, FileBufferBoundaries) {
        const TemporaryDirectory directory;
        const auto input = directory.Path() / "input.bin";
        const auto encrypted = directory.Path() / "encrypted.bin";
        const auto restored = directory.Path() / "restored.bin";
        const auto buffer_size = 1024 * block_size_;
        const std::array sizes = {
            std::size_t{0}, block_size_, buffer_size - 1, buffer_size, buffer_size + 1, 2 * buffer_size + 1
        };
        auto context = MakeContext();
        auto decryptor = MakeContext();

        for (const auto size : sizes) {
            SCOPED_TRACE(size);
            const auto plaintext = RandomBytes(size);
            WriteFile(input, plaintext);
            context.EncryptFileAsync(input, encrypted).get();
            EXPECT_EQ(fs::file_size(encrypted), ExpectedCiphertextSize(size));

            const auto file_ciphertext = ReadFile(encrypted);
            ExpectMatchingCiphertexts(file_ciphertext, context.EncryptAsync(plaintext).get(), size);

            decryptor.DecryptFileAsync(encrypted, restored).get();
            EXPECT_EQ(ReadFile(restored), ExpectedPlaintext(plaintext));
            EXPECT_EQ(ReadFile(input), plaintext);
        }
    }

    TEST_P(RijndaelBoundaryTest, ReportsFileErrorsThroughFutures) {
        const TemporaryDirectory directory;
        const auto input = directory.Path() / "input.bin";
        const auto output = directory.Path() / "output.bin";
        const auto missing = directory.Path() / "missing.bin";
        const auto invalid_output = directory.Path() / "missing directory" / "output.bin";
        auto context = MakeContext();

        EXPECT_THROW(context.EncryptFileAsync(missing, output).get(), std::runtime_error);
        EXPECT_THROW(context.DecryptFileAsync(missing, output).get(), std::runtime_error);
        WriteFile(input, RandomBytes(block_size_));
        EXPECT_THROW(context.EncryptFileAsync(input, invalid_output).get(), std::runtime_error);
        EXPECT_THROW(context.DecryptFileAsync(input, invalid_output).get(), std::runtime_error);

        WriteFile(input, {});

        if (RequiresPadding(GetParam().mode)) {
            EXPECT_THROW(context.DecryptFileAsync(input, output).get(), std::runtime_error);

            WriteFile(input, RandomBytes(block_size_ - 1));
            EXPECT_THROW(context.DecryptFileAsync(input, output).get(), std::runtime_error);

            const Bytes invalid(block_size_, 0);
            WriteFile(input, InvalidPaddingCiphertext(invalid));

            if (GetParam().padding == PaddingMode::Zeros) {
                context.DecryptFileAsync(input, output).get();
                EXPECT_EQ(ReadFile(output), invalid);
            } else {
                EXPECT_THROW(context.DecryptFileAsync(input, output).get(), std::runtime_error);
            }
        } else {
            context.DecryptFileAsync(input, output).get();
            EXPECT_TRUE(ReadFile(output).empty());
        }
    }

    TEST_P(RijndaelBoundaryTest, ValidatesKeysIvAndModeParameters) {
        for (const auto size : {std::size_t{0}, key_.size() - 1, key_.size() + 1}) {
            SCOPED_TRACE(size);
            EXPECT_THROW((Context(Bytes(size), GetParam().mode, GetParam().padding, params_, *GetParam().cipher)), std::invalid_argument);
        }

        for (const auto size : {std::size_t{0}, block_size_ - 1, block_size_ + 1}) {
            auto invalid = params_;
            invalid.iv.resize(size);

            if (GetParam().mode == CipherMode::ECB) {
                EXPECT_NO_THROW((void)MakeContext(invalid));
            } else {
                EXPECT_THROW((void)MakeContext(invalid), std::invalid_argument);
            }
        }

        EXPECT_THROW((Context(key_, static_cast<CipherMode>(-1), GetParam().padding, params_, *GetParam().cipher)), std::runtime_error);
        EXPECT_THROW((Context(key_, GetParam().mode, static_cast<PaddingMode>(-1), params_, *GetParam().cipher)), std::runtime_error);

        if (GetParam().mode == CipherMode::RandomDelta) {
            auto invalid = params_;
            invalid.additional_args.clear();
            EXPECT_THROW((void)MakeContext(invalid), std::runtime_error);
            invalid.additional_args.emplace_back(std::string("invalid delta"));
            EXPECT_THROW((void)MakeContext(invalid), std::bad_any_cast);
        }
    }

    TEST_P(RijndaelBoundaryTest, UsesIvAndIgnoresPaddingForStreamModes) {
        auto context = MakeContext();
        auto alternative = params_;
        alternative.iv.front() ^= 0x80;
        auto other = MakeContext(alternative);
        const auto plaintext = RandomBytes(block_size_ + 3);
        const auto first = context.EncryptAsync(plaintext).get();
        const auto second = other.EncryptAsync(plaintext).get();
        const bool same_first_block = std::equal(first.begin(), first.begin() + static_cast<std::ptrdiff_t>(block_size_), second.begin());

        EXPECT_EQ(same_first_block, GetParam().mode == CipherMode::ECB);

        if (!RequiresPadding(GetParam().mode)) {
            for (const auto padding : PADDING_MODES) {
                Context different_padding(key_, GetParam().mode, padding, params_, *GetParam().cipher);

                EXPECT_EQ(different_padding.EncryptAsync(plaintext).get(), first);
                EXPECT_EQ(different_padding.DecryptAsync(first).get(), plaintext);
            }
        }
    }

    TEST_P(RijndaelCounterTest, MatchesSequentialCountersAcrossFileChunksAndCarries) {
        const TemporaryDirectory directory;
        const auto input = directory.Path() / "input.bin";
        const auto output = directory.Path() / "encrypted.bin";
        auto cipher = *GetParam().cipher;
        cipher.SetEncryptionKey(key_);
        const Bytes plaintext(1027 * block_size_ + 5, 0);
        WriteFile(input, plaintext);

        const auto deltas = GetParam().mode == CipherMode::CTR
            ? std::vector<std::uint64_t>{1}
            : std::vector<std::uint64_t>{0, 1, 17, std::numeric_limits<std::uint64_t>::max()};

        for (const auto delta : deltas) {
            SCOPED_TRACE(delta);
            auto params = params_;
            params.iv.assign(block_size_, 0xFF);
            params.additional_args = {delta};
            auto context = MakeContext(params);
            auto counter = params.iv;
            Bytes stream(block_size_);
            Bytes expected(plaintext.size());

            for (std::size_t offset = 0; offset < plaintext.size(); offset += block_size_) {
                cipher.EncryptBlock(counter, stream);
                const auto count = std::min(block_size_, plaintext.size() - offset);
                std::copy_n(stream.begin(), count, expected.begin() + static_cast<std::ptrdiff_t>(offset));

                // Independent repeated addition checks carry beyond 64 bits and full counter wrap.
                auto increment = GetParam().mode == CipherMode::CTR ? std::uint64_t{1} : delta;
                unsigned int carry = 0;

                for (std::size_t i = counter.size(); i-- > 0;) {
                    const auto sum = static_cast<unsigned int>(counter[i])
                        + static_cast<unsigned int>(increment & 0xFFU) + carry;
                    counter[i] = static_cast<std::uint8_t>(sum);
                    carry = sum >> 8;
                    increment >>= 8;
                }
            }

            EXPECT_EQ(context.EncryptAsync(plaintext).get(), expected);
            EXPECT_EQ(context.DecryptAsync(expected).get(), plaintext);
            context.EncryptFileAsync(input, output).get();
            EXPECT_EQ(ReadFile(output), expected);
        }
    }

    INSTANTIATE_TEST_SUITE_P(AllCombinations, RijndaelContextTest, ::testing::ValuesIn(AllCases()), CaseName);

    INSTANTIATE_TEST_SUITE_P(
        AllPaddedCombinations, RijndaelPaddingTest,
        ::testing::ValuesIn(SelectCases([] (const CipherCase &test_case) { return RequiresPadding(test_case.mode); })),
        CaseName
    );

    INSTANTIATE_TEST_SUITE_P(BlockSizesModesAndPaddings, RijndaelBoundaryTest, ::testing::ValuesIn(BoundaryCases()), CaseName);

    INSTANTIATE_TEST_SUITE_P(
        BlockSizesModesAndPaddings, RijndaelCounterTest,
        ::testing::ValuesIn(SelectCases([] (const CipherCase &test_case) {
            return test_case.key_length == KeyLength::Bits256 && test_case.modulus == 0x1D
                && (test_case.mode == CipherMode::CTR || test_case.mode == CipherMode::RandomDelta);
        })),
        CaseName
    );

    TEST(RijndaelModeTest, MatchesNistSp80038aVectorsInBothDirections) {
        // NIST SP 800-38A, Appendix F: ECB, CBC, CFB128, OFB and CTR with AES-128.
        // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
        const auto key = FromHex("2b7e151628aed2a6abf7158809cf4f3c");
        const auto plaintext = FromHex(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
        );
        const std::array<std::pair<CipherMode, std::string_view>, 5> vectors = {{
            {CipherMode::ECB,
                "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf"
                "43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4"},
            {CipherMode::CBC,
                "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
                "73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7"},
            {CipherMode::CFB,
                "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b"
                "26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6"},
            {CipherMode::OFB,
                "3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed825"
                "9740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e"},
            {CipherMode::CTR,
                "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff"
                "5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee"}
        }};
        RijndaelAlgorithm cipher(BlockLength::Bits128, KeyLength::Bits128, 0x1B, galois::GFService{});
        cipher.SetEncryptionKey(key);
        cipher.SetDecryptionKey(key);

        for (const auto &[mode, hex] : vectors) {
            SCOPED_TRACE(ModeName(mode));
            CipherParams params;
            params.iv = FromHex(mode == CipherMode::CTR
                ? "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
                : "000102030405060708090a0b0c0d0e0f");
            const auto expected = FromHex(hex);
            auto strategy = CipherModeFactory::Create(mode, params);
            Bytes ciphertext(plaintext.size());
            Bytes restored(plaintext.size());

            strategy->EncryptChunk(plaintext, ciphertext, cipher);
            EXPECT_EQ(ciphertext, expected);
            strategy->ResetState();
            strategy->DecryptChunk(expected, restored, cipher);
            EXPECT_EQ(restored, plaintext);
        }
    }

    TEST(RijndaelModeTest, DefaultContextRemainsUsable) {
        const auto key = RandomBytes(16);
        const auto plaintext = RandomBytes(37);
        RijndaelAlgorithm cipher(BlockLength::Bits128, KeyLength::Bits128, 0x1B, galois::GFService{});
        Context context(key, CipherMode::ECB, PaddingMode::PKCS7, {}, cipher);

        EXPECT_EQ(context.DecryptAsync(context.EncryptAsync(plaintext).get()).get(), plaintext);
    }

} // namespace
