#include <lab2/rsa.h>

#include <boost/multiprecision/cpp_int.hpp>
#include <gtest/gtest.h>


using namespace crypto;
using namespace crypto::math;
using namespace crypto::rsa;

// ==============================================================================
// ФИКСТУРА ДЛЯ ПАРАМЕТРИЗОВАННЫХ ТЕСТОВ (Testing all Primality Types)
// ==============================================================================

class RSAServiceParameterizedTest
    : public ::testing::TestWithParam<RSAService::PrimalityTestType> {
protected:
    // Используем небольшую длину битов (например, 128 бит на простое число, N = 256 бит),
    // чтобы юнит-тесты выполнялись быстро, но при этом проверяли всю логику.
    std::size_t bit_length = 128;
    double min_probability = 0.999;

    // Сообщение для тестов
    BigInt message{"12345678901234567890987654321"};
};

// ==============================================================================
// ТЕСТ 1: Полный цикл шифрования и дешифрования
// ==============================================================================
TEST_P(RSAServiceParameterizedTest, EndToEndEncryptionDecryption) {
    RSAService::PrimalityTestType test_type = GetParam();

    RSAService rsa_service(test_type, min_probability, bit_length);

    // Генерация ключей
    KeyPair key_pair = rsa_service.GetKeyGenerator().GenerateKeyPair();

    // Проверка, что модуль n одинаковый в обоих ключах
    EXPECT_EQ(key_pair.public_key.n, key_pair.private_key.n);
    EXPECT_GT(key_pair.public_key.n, 0);
    EXPECT_GT(key_pair.public_key.e, 1);
    EXPECT_GT(key_pair.private_key.d, 1);

    // Шифрование
    BigInt ciphertext = rsa_service.Encrypt(message, key_pair.public_key);
    EXPECT_NE(ciphertext, message) << "Ciphertext should not equal plaintext!";

    // Дешифрование
    BigInt decrypted_message = rsa_service.Decrypt(ciphertext, key_pair.private_key);

    // Проверка успешности
    EXPECT_EQ(decrypted_message, message) << "Decrypted message does not match original!";
}

// ==============================================================================
// ТЕСТ 2: Произвольное количество генераций (и уникальность ключей)
// ==============================================================================
TEST_P(RSAServiceParameterizedTest, MultipleSequentialKeyGenerations) {
    RSAService::PrimalityTestType test_type = GetParam();
    RSAService rsa_service(test_type, min_probability, bit_length);

    auto key_pair_1 = rsa_service.GetKeyGenerator().GenerateKeyPair();
    auto key_pair_2 = rsa_service.GetKeyGenerator().GenerateKeyPair();
    auto key_pair_3 = rsa_service.GetKeyGenerator().GenerateKeyPair();

    // Модули сгенерированных ключей должны отличаться с вероятностью стремящейся к 1
    EXPECT_NE(key_pair_1.public_key.n, key_pair_2.public_key.n);
    EXPECT_NE(key_pair_2.public_key.n, key_pair_3.public_key.n);
    EXPECT_NE(key_pair_1.public_key.n, key_pair_3.public_key.n);
}

// ==============================================================================
// ТЕСТ 3: Устойчивость к атаке Винера (Свойства закрытого ключа)
// ==============================================================================
TEST_P(RSAServiceParameterizedTest, WienerAttackResistance) {
    RSAService::PrimalityTestType test_type = GetParam();
    RSAService rsa_service(test_type, min_probability, bit_length);

    KeyPair key_pair = rsa_service.GetKeyGenerator().GenerateKeyPair();

    const BigInt& d = key_pair.private_key.d;
    const BigInt& n = key_pair.private_key.n;

    // Теорема Винера: если d < (1/3) * N^(1/4), система уязвима к атаке.
    // Чтобы не считать дробные корни, возводим обе части неравенства d > (1/3)*N^(1/4)
    // в 4 степень. Получаем: d^4 > (1/81)*N  =>  81 * d^4 > N.
    BigInt d_pow_4 = d * d * d * d;
    BigInt wiener_bound = 81 * d_pow_4;

    EXPECT_GT(wiener_bound, n)
        << "Private exponent 'd' is too small! System is vulnerable to Wiener's attack.";
}

// ==============================================================================
// ТЕСТ 4: Краевые значения сообщений (0, 1, N-1)
// ==============================================================================
TEST_P(RSAServiceParameterizedTest, EdgeCasesMessages) {
    RSAService::PrimalityTestType test_type = GetParam();
    RSAService rsa_service(test_type, min_probability, bit_length);

    KeyPair key_pair = rsa_service.GetKeyGenerator().GenerateKeyPair();
    const BigInt& n = key_pair.public_key.n;

    std::vector<BigInt> edge_messages = {
        0,
        1,
        n - 1 // Максимально возможное сообщение
    };

    for (const auto& msg : edge_messages) {
        BigInt ciphertext = rsa_service.Encrypt(msg, key_pair.public_key);
        BigInt decrypted = rsa_service.Decrypt(ciphertext, key_pair.private_key);
        EXPECT_EQ(msg, decrypted) << "Failed to handle edge case message: " << msg;
    }
}

// ==============================================================================
// РЕГИСТРАЦИЯ ПАРАМЕТРИЗОВАННЫХ ТЕСТОВ
// ==============================================================================
// GTest автоматически запустит все тесты с префиксом TEST_P трижды —
// подставив по очереди Fermat, SolovayStrassen и MillerRabin.

INSTANTIATE_TEST_SUITE_P(
    RSAAlgorithms,
    RSAServiceParameterizedTest,
    ::testing::Values(
        RSAService::PrimalityTestType::Fermat,
        RSAService::PrimalityTestType::SolovayStrassen,
        RSAService::PrimalityTestType::MillerRabin
    ),
    // Опционально: лямбда для красивого вывода имен тестов в консоли вместо чисел
    [](const ::testing::TestParamInfo<RSAServiceParameterizedTest::ParamType>& info) {
        switch (info.param) {
            case RSAService::PrimalityTestType::Fermat: return "Fermat";
            case RSAService::PrimalityTestType::SolovayStrassen: return "SolovayStrassen";
            case RSAService::PrimalityTestType::MillerRabin: return "MillerRabin";
            default: return "Unknown";
        }
    }
);