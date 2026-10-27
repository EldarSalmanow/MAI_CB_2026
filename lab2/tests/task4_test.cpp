#include <lab2/wiener_attack.h>

#include <boost/multiprecision/cpp_int.hpp>
#include <gtest/gtest.h>

#include <algorithm>


using namespace crypto;
using namespace crypto::math;
using namespace crypto::rsa;
using namespace crypto::attacks;


class WienerAttackTest : public ::testing::Test {
protected:
    // Длина битов для генерации (достаточная для работы атаки и быстрая для тестов)
    std::size_t bit_length = 256;
    double min_probability = 0.999;
    RSAService::PrimalityTestType test_type = RSAService::PrimalityTestType::MillerRabin;

    WienerAttackService attack_service;
};

// ==============================================================================
// ТЕСТ 1: Проверка уязвимости сгенерированного ключа
// ==============================================================================
TEST_F(WienerAttackTest, VulnerableGeneratorProducesTrulyVulnerableKey) {
    VulnerableKeyPairGenerator vulnerable_gen(test_type, min_probability, bit_length);
    KeyPair key_pair = vulnerable_gen.GenerateKeyPair();

    const BigInt& d = key_pair.private_key.d;
    const BigInt& n = key_pair.private_key.n;

    // Условие уязвимости к атаке Винера: d < (1/3) * N^(1/4)
    // В целых числах: 81 * d^4 < N
    BigInt d_pow_4 = d * d * d * d;
    BigInt wiener_bound = 81 * d_pow_4;

    EXPECT_LT(wiener_bound, n)
        << "Generated key is not vulnerable to Wiener's attack! (81 * d^4 >= n)";
}

// ==============================================================================
// ТЕСТ 2: Успешное выполнение атаки на уязвимый ключ
// ==============================================================================
TEST_F(WienerAttackTest, AttackRecoversSecretKeyAndPhi) {
    VulnerableKeyPairGenerator vulnerable_gen(test_type, min_probability, bit_length);
    KeyPair key_pair = vulnerable_gen.GenerateKeyPair();

    // Запуск атаки
    auto attack_result = attack_service.Execute(key_pair.public_key);

    // 1. Атака должна быть успешной
    ASSERT_TRUE(attack_result.has_value())
        << "Wiener's attack failed to find the private key on a vulnerable keypair!";

    // 2. Найденная экспонента d должна строго совпадать с приватным d
    EXPECT_EQ(attack_result->d, key_pair.private_key.d)
        << "Found decryption exponent 'd' does not match the actual private key!";

    // 3. Проверка корректности phi(N): e * d = 1 (mod phi(N))
    const BigInt& e = key_pair.public_key.e;
    const BigInt& d = attack_result->d;
    const BigInt& phi_n = attack_result->phi_n;

    EXPECT_GT(phi_n, 0);
    EXPECT_EQ((e * d) % phi_n, BigInt(1))
        << "Condition (e * d = 1 mod phi(N)) is violated for recovered phi(N)!";

    // 4. Проверка коллекции подходящих дробей
    EXPECT_FALSE(attack_result->fractions.empty())
        << "Collection of continuous fractions convergents must not be empty!";

    // Знаменатель одной из дробей (k/d) обязан быть равен recovered 'd'
    bool found_d_in_fractions = std::any_of(
        attack_result->fractions.begin(),
        attack_result->fractions.end(),
        [&d](const Fraction &f) {
            return f.denominator == d;
        }
    );
    EXPECT_TRUE(found_d_in_fractions)
        << "The true 'd' was not found among the denominators of convergents!";
}

// ==============================================================================
// ТЕСТ 3: Расшифровка сообщения ключом, найденным через атаку Винера
// ==============================================================================
TEST_F(WienerAttackTest, DecryptMessageUsingAttackedKey) {
    VulnerableKeyPairGenerator vulnerable_gen(test_type, min_probability, bit_length);
    KeyPair key_pair = vulnerable_gen.GenerateKeyPair();

    RSAService rsa_service(test_type, min_probability, bit_length);

    // Исходное сообщение
    BigInt message(421337);

    // Зашифровали сообщение легитимным публичным ключом
    BigInt ciphertext = rsa_service.Encrypt(message, key_pair.public_key);

    // Провели атаку злоумышленником
    auto attack_result = attack_service.Execute(key_pair.public_key);
    ASSERT_TRUE(attack_result.has_value());

    // Злоумышленник формирует приватный ключ из найденного d
    PrivateKey cracked_private_key{
        .d = attack_result->d,
        .n = key_pair.public_key.n
    };

    // Злоумышленник расшифровывает перехваченное сообщение
    BigInt cracked_message = rsa_service.Decrypt(ciphertext, cracked_private_key);

    EXPECT_EQ(cracked_message, message)
        << "The recovered key failed to decrypt the message correctly!";
}

// ==============================================================================
// ТЕСТ 4: Атака терпит неудачу на защищенных ключах (Safe Key)
// ==============================================================================
TEST_F(WienerAttackTest, AttackFailsOnStandardSecureKey) {
    // Создаем стандартный сервис RSA из Задания 3, который защищен от атаки Винера
    RSAService secure_rsa(test_type, min_probability, bit_length);
    KeyPair secure_key_pair = secure_rsa.GetKeyGenerator().GenerateKeyPair();

    // Запуск атаки на защищенный ключ
    auto attack_result = attack_service.Execute(secure_key_pair.public_key);

    // Атака обязана вернуть std::nullopt
    EXPECT_FALSE(attack_result.has_value())
        << "Wiener's attack must not succeed on a secure RSA key!";
}