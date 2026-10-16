#include <gtest/gtest.h>

#include <cstdint>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <lab1/cipher_context.h>
#include <lab1/des_algorithm.h>

// =========================================================================
// 1. ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ДЛЯ КРИПТОАНАЛИЗА
// =========================================================================

// Конвертация HEX-строки в массив байтов
std::vector<std::uint8_t> HexToBytes(const std::string& hex) {
    std::vector<std::uint8_t> bytes;
    for (std::size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        std::uint8_t byte = static_cast<std::uint8_t>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// Конвертация массива байтов в HEX-строку (для удобного вывода ошибок)
std::string BytesToHex(const std::vector<std::uint8_t>& bytes) {
    std::ostringstream oss;
    for (auto b : bytes) {
        oss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return oss.str();
}

// =========================================================================
// 2. KAT ТЕСТЫ (KNOWN ANSWER TESTS) - ОФИЦИАЛЬНЫЕ ВЕКТОРЫ FIPS 46-3
// =========================================================================

class DESKnownAnswerTest : public ::testing::TestWithParam<std::tuple<std::string, std::string, std::string>> {};

// Параметризованный тест, который прогоняет официальные векторы
TEST_P(DESKnownAnswerTest, EncryptDecryptMatchesStandardVectors) {
    // Распаковываем параметры: Ключ, Открытый текст, Ожидаемый шифротекст
    auto [hex_key, hex_plain, hex_expected_cipher] = GetParam();

    std::vector<std::uint8_t> key = HexToBytes(hex_key);
    std::vector<std::uint8_t> plaintext = HexToBytes(hex_plain);
    std::vector<std::uint8_t> expected_ciphertext = HexToBytes(hex_expected_cipher);

    DESAlgorithm des;
    std::vector<std::uint8_t> actual_ciphertext(8);
    std::vector<std::uint8_t> actual_decrypted(8);

    // 1. Проверка ШИФРОВАНИЯ
    des.SetEncryptionKey(key);
    des.EncryptBlock(plaintext, actual_ciphertext);

    // Сравниваем в виде HEX-строк, чтобы в случае ошибки сразу видеть, где биты "поехали"
    EXPECT_EQ(BytesToHex(actual_ciphertext), BytesToHex(expected_ciphertext)) 
        << "Ошибка шифрования для вектора с ключом: " << hex_key;

    // 2. Проверка ДЕШИФРОВАНИЯ
    des.SetDecryptionKey(key);
    des.DecryptBlock(actual_ciphertext, actual_decrypted);

    EXPECT_EQ(BytesToHex(actual_decrypted), BytesToHex(plaintext))
        << "Ошибка дешифрования для вектора с ключом: " << hex_key;
}

// Официальные тестовые векторы (NIST)
INSTANTIATE_TEST_SUITE_P(
    StandardVectors,
    DESKnownAnswerTest,
    ::testing::Values(
        // Формат: { Ключ, Открытый текст (PT), Шифротекст (CT) }
        
        // Вектор 1: Нулевой ключ и нулевой текст
        std::make_tuple("0000000000000000", "0000000000000000", "8CA64DE9C1B123A7"),
        
        // Вектор 2: Единичные биты
        std::make_tuple("FFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFF", "7359B2163E4EDC58"),
        
        // Вектор 3: Известный классический вектор
        std::make_tuple("133457799BBCDFF1", "0123456789ABCDEF", "85E813540F0AB405"),
        
        // Вектор 4: Еще один классический
        std::make_tuple("0123456789ABCDEF", "0000000000000000", "D5D44FF720683D0D"),
        
        // Вектор 5: Попеременные биты
        std::make_tuple("0101010101010101", "0101010101010101", "994d4dc157b96c52")
    )
);


// =========================================================================
// 3. ТЕСТЫ НА ИСКЛЮЧЕНИЯ И ГРАНИЧНЫЕ УСЛОВИЯ
// =========================================================================

TEST(DESAlgorithmTest, ThrowsOnInvalidKeySize) {
    DESAlgorithm des;
    std::vector<std::uint8_t> short_key = {0x01, 0x02, 0x03}; // Слишком короткий ключ

    EXPECT_THROW({
        des.SetEncryptionKey(short_key);
    }, std::runtime_error);
}

// =========================================================================
// 4. ТЕСТ ИНТЕГРАЦИИ (ЗАДАНИЕ 4 + ЗАДАНИЕ 2)
// Проверяем, как наш свеженаписанный DES работает внутри Контекста.
// =========================================================================

TEST(DESAlgorithmTest, IntegrationWithSymmetricCipherContext) {
    // Используем классический вектор в качестве ключа
    std::vector<std::uint8_t> key = HexToBytes("133457799BBCDFF1");
    std::vector<std::uint8_t> iv  = HexToBytes("1122334455667788");
    
    CipherParams params;
    params.iv = iv;

    // Инициализируем Контекст (Задание 2), передавая ему наш DESAlgorithm (Задание 4)
    SymmetricCipherContext<DESAlgorithm> desContext(
        key, CipherMode::CBC, PaddingMode::PKCS7, params
    );

    // Большой открытый текст (30 байт, не кратно 8, потребуется Padding)
    std::string text = "This is a secret message to test DES CBC.";
    std::vector<std::uint8_t> plaintext(text.begin(), text.end());

    // 1. Асинхронное шифрование (Контекст сам разобьет на блоки, добавит паддинг, применит XOR с IV и вызовет DES)
    auto ciphertext = desContext.EncryptAsync(plaintext).get();
    
    // Длина 30 байт -> после PKCS7 паддинга должна стать 32 байта (кратно 8)
    EXPECT_EQ(ciphertext.size(), 48);
    // Зашифрованные данные не должны совпадать с исходными
    EXPECT_NE(ciphertext, plaintext);

    // 2. Асинхронное дешифрование
    auto decrypted = desContext.DecryptAsync(ciphertext).get();

    // 3. Расшифрованный текст должен идеально совпасть с исходным
    EXPECT_EQ(decrypted, plaintext);
}

// =========================================================================
// 5. ТЕСТ РЕЖИМА CTR ДЛЯ DES
// Проверка потокового режима (не добавляет Padding, использует только EncryptBlock)
// =========================================================================

TEST(DESAlgorithmTest, StreamModeCTR) {
    std::vector<std::uint8_t> key = HexToBytes("0123456789ABCDEF");
    std::vector<std::uint8_t> iv  = HexToBytes("0000000000000000"); // Счетчик с нуля
    
    CipherParams params;
    params.iv = iv;

    SymmetricCipherContext<DESAlgorithm> desContext(
        key, CipherMode::CTR, PaddingMode::PKCS7, params
    );

    // Размер ровно 13 байт
    std::vector<std::uint8_t> plaintext = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD
    };

    // Шифруем
    auto ciphertext = desContext.EncryptAsync(plaintext).get();
    
    // В режиме CTR размер шифротекста обязан быть равен размеру открытого текста!
    EXPECT_EQ(ciphertext.size(), 13);

    // Дешифруем
    auto decrypted = desContext.DecryptAsync(ciphertext).get();

    EXPECT_EQ(decrypted, plaintext);
}
