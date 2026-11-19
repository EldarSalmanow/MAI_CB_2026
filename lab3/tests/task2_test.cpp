#include <lab2/primality_test.h>

#include <boost/multiprecision/cpp_int.hpp>
#include <gtest/gtest.h>


using namespace crypto;
using namespace crypto::math;
using namespace crypto::primality;


// ==============================================================================
// Тесты для вероятностных тестов простоты
// ==============================================================================

// Фикстура для типизированных тестов
template <typename T>
class PrimalityTests : public ::testing::Test {
protected:
    T test_algo;
    double high_prob = 0.999; // Требуемая надежность
};

// Регистрируем типы, которые будут тестироваться
using PrimalityAlgoTypes = ::testing::Types<
    FermatTest,
    SolovayStrassenTest,
    MillerRabinTest
>;

TYPED_TEST_SUITE(PrimalityTests, PrimalityAlgoTypes);


TYPED_TEST(PrimalityTests, IdentifiesKnownPrimes) {
    // Классические простые числа
    std::vector<BigInt> primes = {
        5, 7, 11, 13, 17, 19, 23, 29, 31,
        97, 101, 7919,
        // Большое простое число
        BigInt("100000000000000000039")
    };

    for (const auto& p : primes) {
        EXPECT_TRUE(this->test_algo.IsPrime(p, this->high_prob))
            << "Test failed to identify prime: " << p;
    }
}

TYPED_TEST(PrimalityTests, IdentifiesKnownComposites) {
    // Классические составные числа
    std::vector<BigInt> composites = {
        9, 15, 21, 25, 27, 33, 100, 9999,
        // Большое составное число
        BigInt("100000000000000000041")
    };

    for (const auto& c : composites) {
        EXPECT_FALSE(this->test_algo.IsPrime(c, this->high_prob))
            << "Test failed to identify composite: " << c;
    }
}

TYPED_TEST(PrimalityTests, EdgeCasesSmallNumbers) {
    // Тесты простоты обычно требуют специфичной обработки для 2 и 3,
    // так как генерация базы [2, n-2] для них ломается.
    EXPECT_TRUE(this->test_algo.IsPrime(2, this->high_prob));
    EXPECT_TRUE(this->test_algo.IsPrime(3, this->high_prob));
    EXPECT_FALSE(this->test_algo.IsPrime(4, this->high_prob));
}


// ==============================================================================
// СПЕЦИФИЧЕСКИЕ ТЕСТЫ (Числа Кармайкла)
// ==============================================================================

// Числа Кармайкла (например, 561) — это псевдопростые числа, на которых тест Ферма
// часто ошибается и говорит "Простое" (возвращает true).
// Однако Миллер-Рабин и Соловей-Штрассен должны безошибочно определять их как составные.

TEST(PrimalitySpecificTest, CarmichaelNumbersHandledByAdvancedTests) {
    BigInt carmichael(561); // 3 * 11 * 17
    double prob = 0.999;

    MillerRabinTest mr_test;
    SolovayStrassenTest ss_test;

    // Современные тесты обязаны ловить числа Кармайкла
    EXPECT_FALSE(mr_test.IsPrime(carmichael, prob))
        << "Miller-Rabin failed on Carmichael number 561";

    EXPECT_FALSE(ss_test.IsPrime(carmichael, prob))
        << "Solovay-Strassen failed on Carmichael number 561";

    // Примечание: Мы намеренно не ассертим поведение FermatTest здесь,
    // так как он концептуально уязвим к числам Кармайкла, если рандомайзер
    // выберет базу, взаимно простую с 561.
}