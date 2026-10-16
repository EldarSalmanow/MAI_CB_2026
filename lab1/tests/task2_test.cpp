#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <numeric>
#include <random>
#include <string>
#include <vector>

#include <lab1/block_cipher.h>
#include <lab1/cipher_context.h>

// =========================================================================
// 1. MOCK-АЛГОРИТМ ДЛЯ ТЕСТОВ (ПРОСТОЙ XOR-ШИФР 8 БАЙТ)
// =========================================================================
class DummyBlockCipher : public ISymmetricBlockCipher {
private:
    std::vector<std::uint8_t> m_key;
    static constexpr std::size_t BLOCK_SIZE = 8;

public:
    void EncryptBlock(std::span<const std::uint8_t> input, std::span<std::uint8_t> output) const override {
        for (std::size_t i = 0; i < BLOCK_SIZE; ++i) {
            output[i] = input[i] ^ m_key[i % m_key.size()];
        }
    }

    void DecryptBlock(std::span<const std::uint8_t> input, std::span<std::uint8_t> output) const override {
        // Так как XOR симметричен, дешифрование аналогично
        for (std::size_t i = 0; i < BLOCK_SIZE; ++i) {
            output[i] = input[i] ^ m_key[i % m_key.size()];
        }
    }

    void SetEncryptionKey(std::span<const std::uint8_t> key) override {
        m_key.assign(key.begin(), key.end());
    }

    void SetDecryptionKey(std::span<const std::uint8_t> key) override {
        m_key.assign(key.begin(), key.end());
    }

    std::size_t BlockSize() const override {
        return BLOCK_SIZE;
    }
};


// =========================================================================
// 2. БАЗОВАЯ НАСТРОЙКА (FIXTURE ДЛЯ ТЕСТОВ)
// =========================================================================
class CipherContextTest : public ::testing::Test {
protected:
    std::vector<std::uint8_t> key = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    std::vector<std::uint8_t> iv  = {0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11};
    CipherParams params;

    void SetUp() override {
        params.iv = iv;
        params.additional_args.emplace_back(static_cast<std::uint64_t>(1));
    }

    // Вспомогательный метод для проверки [Де]Шифрования
    void TestSymmetricProperty(CipherMode mode, PaddingMode padding, const std::vector<std::uint8_t>& plaintext) {
        SymmetricCipherContext<DummyBlockCipher> ctx(key, mode, padding, params);

        // Шифруем (асинхронно ждем завершения через .get())
        auto ciphertext = ctx.EncryptAsync(plaintext).get();

        // Дешифруем
        auto decrypted = ctx.DecryptAsync(ciphertext).get();

        // Оригинальный текст должен совпадать с расшифрованным
        EXPECT_EQ(plaintext, decrypted);
    }
};

// =========================================================================
// 3. ТЕСТЫ НА ИСКЛЮЧЕНИЯ И ПРОВЕРКИ
// =========================================================================
TEST_F(CipherContextTest, ThrowsOnInvalidIVSize) {
    CipherParams bad_params;
    bad_params.iv = {0x00, 0x01}; // Размер 2, а блочный шифр требует 8

    EXPECT_THROW({
        SymmetricCipherContext<DummyBlockCipher> ctx(key, CipherMode::CBC, PaddingMode::PKCS7, bad_params);
    }, std::invalid_argument);
}

// =========================================================================
// 4. ТЕСТЫ РЕЖИМОВ НАБИВКИ (PADDING MODES)
// =========================================================================
TEST_F(CipherContextTest, PaddingPKCS7) {
    // 3 байта (требуется 5 байт набивки до 8)
    std::vector<std::uint8_t> plain = {0xAA, 0xBB, 0xCC};
    TestSymmetricProperty(CipherMode::ECB, PaddingMode::PKCS7, plain);
}

TEST_F(CipherContextTest, PaddingANSI_X923) {
    std::vector<std::uint8_t> plain = {0x01, 0x02, 0x03, 0x04, 0x05};
    TestSymmetricProperty(CipherMode::ECB, PaddingMode::ANSI_X923, plain);
}

TEST_F(CipherContextTest, PaddingISO_10126) {
    std::vector<std::uint8_t> plain = {0xFF, 0xEE};
    TestSymmetricProperty(CipherMode::ECB, PaddingMode::ISO_10126, plain);
}

TEST_F(CipherContextTest, PaddingZeros) {
    std::vector<std::uint8_t> plain = {0x01, 0x02, 0x03, 0x04};
    SymmetricCipherContext<DummyBlockCipher> ctx(key, CipherMode::ECB, PaddingMode::Zeros, params);
    const auto cipher = ctx.EncryptAsync(plain).get();
    const std::vector<std::uint8_t> expected = {0x01, 0x02, 0x03, 0x04, 0, 0, 0, 0};
    EXPECT_EQ(ctx.DecryptAsync(cipher).get(), expected);
}

TEST_F(CipherContextTest, NoPaddingNeededIfAligned) {
    std::vector<std::uint8_t> plain = {1, 2, 3, 4, 5, 6, 7, 8}; // Ровно 1 блок
    TestSymmetricProperty(CipherMode::ECB, PaddingMode::PKCS7, plain);
}

// =========================================================================
// 5. ТЕСТЫ РЕЖИМОВ ШИФРОВАНИЯ (CIPHER MODES)
// =========================================================================
TEST_F(CipherContextTest, ModeECB) {
    std::vector<std::uint8_t> plain(32); // 4 полных блока
    std::iota(plain.begin(), plain.end(), 0); // Заполняем 0, 1, 2, 3...

    TestSymmetricProperty(CipherMode::ECB, PaddingMode::PKCS7, plain);
}

TEST_F(CipherContextTest, ModeCBC) {
    std::vector<std::uint8_t> plain(40);
    std::iota(plain.begin(), plain.end(), 10);

    TestSymmetricProperty(CipherMode::CBC, PaddingMode::PKCS7, plain);
}

TEST_F(CipherContextTest, ModePCBC) {
    std::vector<std::uint8_t> plain(24);
    std::iota(plain.begin(), plain.end(), 100);

    TestSymmetricProperty(CipherMode::PCBC, PaddingMode::PKCS7, plain);
}

TEST_F(CipherContextTest, ModeRandomDelta) {
    std::vector<std::uint8_t> plain(45); // Не кратно 8
    std::iota(plain.begin(), plain.end(), 50);

    TestSymmetricProperty(CipherMode::RandomDelta, PaddingMode::PKCS7, plain);
}

// =========================================================================
// 6. ТЕСТЫ ПОТОКОВЫХ РЕЖИМОВ (STREAM MODES)
// Потоковые режимы не должны использовать Padding! Размер входа = размеру выхода.
// =========================================================================
TEST_F(CipherContextTest, StreamModeCFB) {
    std::vector<std::uint8_t> plain = {0x01, 0x02, 0x03, 0x04, 0x05}; // 5 байт
    SymmetricCipherContext<DummyBlockCipher> ctx(key, CipherMode::CFB, PaddingMode::PKCS7, params);

    auto cipher = ctx.EncryptAsync(plain).get();
    EXPECT_EQ(cipher.size(), 5); // Размер не должен измениться

    auto decrypted = ctx.DecryptAsync(cipher).get();
    EXPECT_EQ(decrypted, plain);
}

TEST_F(CipherContextTest, StreamModeOFB) {
    std::vector<std::uint8_t> plain(15); // 15 байт (1 блок + 7 байт)
    std::iota(plain.begin(), plain.end(), 1);

    SymmetricCipherContext<DummyBlockCipher> ctx(key, CipherMode::OFB, PaddingMode::PKCS7, params);

    auto cipher = ctx.EncryptAsync(plain).get();
    EXPECT_EQ(cipher.size(), 15);

    auto decrypted = ctx.DecryptAsync(cipher).get();
    EXPECT_EQ(decrypted, plain);
}

TEST_F(CipherContextTest, StreamModeCTR) {
    std::vector<std::uint8_t> plain(100); // Большой массив (не кратный 8)
    std::iota(plain.begin(), plain.end(), 0);

    SymmetricCipherContext<DummyBlockCipher> ctx(key, CipherMode::CTR, PaddingMode::PKCS7, params);

    auto cipher = ctx.EncryptAsync(plain).get();
    EXPECT_EQ(cipher.size(), 100);

    auto decrypted = ctx.DecryptAsync(cipher).get();
    EXPECT_EQ(decrypted, plain);
}

// =========================================================================
// 7. ТЕСТЫ РАБОТЫ С ФАЙЛАМИ (FILE I/O)
// =========================================================================
TEST_F(CipherContextTest, FileEncryptionDecryption) {
    std::filesystem::path plain_file = "test_plain.bin";
    std::filesystem::path cipher_file = "test_cipher.bin";
    std::filesystem::path decrypted_file = "test_decrypted.bin";

    // 1. Создаем исходный файл (например, 1 МБ случайных данных)
    std::size_t file_size = 1024 * 1024;
    std::random_device device;
    std::mt19937 engine(device());
    std::uniform_int_distribution<std::uint16_t> distribution(0, 255);
    std::vector<std::uint8_t> file_data(file_size, 0);
    for (std::size_t i = 0; i < file_size; ++i) {
        file_data[i] = distribution(engine);
    }

    {
        std::ofstream out(plain_file, std::ios::binary);
        out.write(reinterpret_cast<const char*>(file_data.data()), file_data.size());
    }

    // 2. Инициализируем контекст (выберем CBC)
    SymmetricCipherContext<DummyBlockCipher> ctx(key, CipherMode::CBC, PaddingMode::PKCS7, params);

    // 3. Шифруем файл асинхронно
    ctx.EncryptFileAsync(plain_file, cipher_file).get(); // Ждем завершения

    // Проверяем, что зашифрованный файл существует и его размер правильный
    ASSERT_TRUE(std::filesystem::exists(cipher_file));
    EXPECT_EQ(std::filesystem::file_size(cipher_file), file_size + 8); // +8 для Padding ПКCS7

    // 4. Дешифруем файл асинхронно
    ctx.DecryptFileAsync(cipher_file, decrypted_file).get(); // Ждем завершения

    // 5. Читаем дешифрованный файл и сверяем с оригиналом
    std::vector<std::uint8_t> decrypted_data(file_size);
    {
        std::ifstream in(decrypted_file, std::ios::binary);
        in.read(reinterpret_cast<char*>(decrypted_data.data()), file_size);
    }

    EXPECT_EQ(file_data, decrypted_data);

    // Убираем за собой мусор
    std::filesystem::remove(plain_file);
    std::filesystem::remove(cipher_file);
    std::filesystem::remove(decrypted_file);
}
