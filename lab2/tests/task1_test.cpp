#include <lab2/math.h>

#include <gtest/gtest.h>

#include <string>


using namespace crypto;
using namespace crypto::math;
using namespace crypto::math::detail;

// ==============================================================================
// Тесты для Символа Лежандра
// ==============================================================================
TEST(CryptoMathTest, LegendreSymbol) {
    // p = 7 (простое)
    BigInt p(7);
    EXPECT_EQ(LegendreSymbol(0, p), 0);  // a = 0 mod p
    EXPECT_EQ(LegendreSymbol(1, p), 1);  // Квадратичный вычет (1^2 = 1 mod 7)
    EXPECT_EQ(LegendreSymbol(2, p), 1);  // Квадратичный вычет (3^2 = 9 = 2 mod 7)
    EXPECT_EQ(LegendreSymbol(3, p), -1); // Квадратичный невычет

    // Большие числа
    BigInt big_a{"12345678901234567890"};
    BigInt big_p{"100000000000000000039"}; // Простое число
    // Просто проверяем, что метод не падает и возвращает корректный тип значений (-1, 0, 1)
    auto res = LegendreSymbol(big_a, big_p);
    EXPECT_TRUE(res == 1 || res == -1 || res == 0);
}

// ==============================================================================
// Тесты для Символа Якоби
// ==============================================================================
TEST(CryptoMathTest, JacobiSymbol) {
    // n = 15 (составное: 3 * 5)
    BigInt n(15);
    EXPECT_EQ(JacobiSymbol(0, n), 0);
    EXPECT_EQ(JacobiSymbol(1, n), 1);
    EXPECT_EQ(JacobiSymbol(2, n), 1);
    EXPECT_EQ(JacobiSymbol(3, n), 0);  // НОД(3, 15) != 1
    EXPECT_EQ(JacobiSymbol(7, n), -1);

    // Свойства Якоби для отрицательных чисел
    EXPECT_EQ(JacobiSymbol(-1, 15), -1); // (-1/15) = (-1/3)*(-1/5) = (-1)*(1) = -1
}

// ==============================================================================
// Тесты для НОД (Обычный Евклид и Бинарный)
// ==============================================================================
template <typename ImplT>
void TestGCD() {
    EXPECT_EQ(GCD<ImplT>(48, 18), BigInt(6));
    EXPECT_EQ(GCD<ImplT>(101, 103), BigInt(1)); // Взаимно простые
    EXPECT_EQ(GCD<ImplT>(15, 0), BigInt(15));
    EXPECT_EQ(GCD<ImplT>(0, 22), BigInt(22));
    EXPECT_EQ(GCD<ImplT>(0, 0), BigInt(0));

    // Длинная арифметика
    BigInt a{"1234567890123456789000"};
    BigInt b{"9876543210987654321000"};
    EXPECT_EQ(GCD<ImplT>(a, b), BigInt("90000000009000"));
}

TEST(CryptoMathTest, GCDEuclidian) {
    TestGCD<GCDEuclidianImpl>();
}

TEST(CryptoMathTest, GCDBinaryEuclidian) {
    TestGCD<GCDBinaryEuclidianImpl>();
}

// ==============================================================================
// Тесты для Расширенного алгоритма Евклида
// ==============================================================================
TEST(CryptoMathTest, GCDExtendedEuclidian) {
    BigInt a(30);
    BigInt b(20);

    auto [gcd, x, y] = GCD<GCDExtendedEuclidianImpl>(a, b);

    EXPECT_EQ(gcd, BigInt(10));
    // Проверка соотношения Безу: a*x + b*y = gcd
    EXPECT_EQ(a * x + b * y, gcd);

    // Взаимно простые числа
    a = 99; b = 78;
    auto [gcd2, x2, y2] = GCD<GCDExtendedEuclidianImpl>(a, b);
    EXPECT_EQ(gcd2, BigInt(3));
    EXPECT_EQ(a * x2 + b * y2, gcd2);
}

// ==============================================================================
// Тесты для НОК (LCM)
// ==============================================================================
TEST(CryptoMathTest, LCM) {
    EXPECT_EQ(LCM(21, 6), BigInt(42));
    EXPECT_EQ(LCM(15, 20), BigInt(60));
    EXPECT_EQ(LCM(0, 5), BigInt(0));
}

// ==============================================================================
// Тесты для Возведения в степень по модулю
// ==============================================================================
TEST(CryptoMathTest, PowMod) {
    EXPECT_EQ(PowMod(2, 3, 5), BigInt(3));     // 2^3 mod 5 = 8 mod 5 = 3
    EXPECT_EQ(PowMod(5, 0, 11), BigInt(1));    // 5^0 mod 11 = 1

    // Малая теорема Ферма: a^(p-1) = 1 mod p
    EXPECT_EQ(PowMod(7, 12, 13), BigInt(1));

    // Большие числа
    BigInt base{"9876543210987654321"};
    BigInt exp{"1234567890123456789"};
    BigInt mod{"100000000000000000039"};

    // Просто проверяем, что не падает (для точной проверки нужен эталонный калькулятор,
    // но логика возведения в квадрат и умножения отработает)
    BigInt result = PowMod(base, exp, mod);
    EXPECT_TRUE(result >= 0 && result < mod);
}

// ==============================================================================
// Тесты для функции Эйлера (3 способа реализации)
// ==============================================================================
template <typename ImplT>
void TestEulerFunction() {
    EXPECT_EQ(EulerFunction<ImplT>(1), BigInt(1));
    EXPECT_EQ(EulerFunction<ImplT>(2), BigInt(1));
    EXPECT_EQ(EulerFunction<ImplT>(9), BigInt(6));
    EXPECT_EQ(EulerFunction<ImplT>(10), BigInt(4));
    EXPECT_EQ(EulerFunction<ImplT>(13), BigInt(12)); // Для простого p: p-1
}

TEST(CryptoMathTest, EulerFunctionDefinition) {
    TestEulerFunction<EulerFunctionDefinitionImpl>();
}

TEST(CryptoMathTest, EulerFunctionMAT) {
    TestEulerFunction<EulerFunctionMATImpl>();

    // Тест большого числа (MAT должен справляться быстрее других)
    // 10403 = 101 * 103 (оба простые). Ф(10403) = 100 * 102 = 10200
    EXPECT_EQ(EulerFunction<EulerFunctionMATImpl>(10403), BigInt(10200));
}

TEST(CryptoMathTest, EulerFunctionDFT) {
    TestEulerFunction<EulerFunctionDFTImpl>();
}

// ==============================================================================
// Тесты для функции Кармайкла
// ==============================================================================
TEST(CryptoMathTest, CarmichaelFunction) {
    EXPECT_EQ(CarmichaelFunction(1), BigInt(1));
    EXPECT_EQ(CarmichaelFunction(8), BigInt(2));  // Ф(8)=4, но L(8)=2
    EXPECT_EQ(CarmichaelFunction(9), BigInt(6));  // Ф(9)=6, L(9)=6
    EXPECT_EQ(CarmichaelFunction(15), BigInt(4)); // Ф(15)=8, L(15)=4
    EXPECT_EQ(CarmichaelFunction(21), BigInt(6)); // Ф(21)=12, L(21)=6

    // Для нечетного простого p: L(p) = p - 1
    EXPECT_EQ(CarmichaelFunction(13), BigInt(12));
}

// ==============================================================================
// Тесты для утилитарной функции IsEven
// ==============================================================================
TEST(CryptoMathTest, IsEven) {
    EXPECT_TRUE(IsEven(0));
    EXPECT_TRUE(IsEven(2));
    EXPECT_TRUE(IsEven(100456));
    EXPECT_FALSE(IsEven(1));
    EXPECT_FALSE(IsEven(3));
    EXPECT_FALSE(IsEven(100457));

    // Проверка с большими числами
    EXPECT_TRUE(IsEven(BigInt("12345678901234567890")));
    EXPECT_FALSE(IsEven(BigInt("12345678901234567891")));
}

// ==============================================================================
// Тесты для генерации случайных чисел
// ==============================================================================

TEST(CryptoMathTest, GenerateRandomInRange) {
    BigInt min("100000000000000000000");
    BigInt max("999999999999999999999");

    // Проверяем несколько раз, чтобы убедиться в стабильности генерации
    for (int i = 0; i < 50; ++i) {
        BigInt rand_val = GenerateRandomInRange(min, max);
        EXPECT_GE(rand_val, min) << "Random value is less than minimum!";
        EXPECT_LE(rand_val, max) << "Random value is greater than maximum!";
    }

    // Пограничный случай: диапазон из одного числа
    BigInt single_val(42);
    EXPECT_EQ(GenerateRandomInRange(single_val, single_val), single_val);
}

TEST(CryptoMathRandomTest, GenerateRandomOddWithBitLength) {
    std::vector<std::size_t> bit_lengths = {8, 16, 64, 128, 512, 1024};

    for (std::size_t bits : bit_lengths) {
        BigInt rand_val = GenerateRandomOddWithBitLength(bits);

        // 1. Проверка на нечетность (младший бит равен 1)
        EXPECT_FALSE(IsEven(rand_val)) << "Generated number is not odd!";

        // 2. Проверка битовой длины.
        // Функция msb() возвращает индекс старшего установленного бита (начиная с 0).
        // Поэтому битовая длина равна msb(rand_val) + 1.
        std::size_t actual_bits = boost::multiprecision::msb(rand_val) + 1;
        EXPECT_EQ(actual_bits, bits) << "Generated number has incorrect bit length!";
    }
}
