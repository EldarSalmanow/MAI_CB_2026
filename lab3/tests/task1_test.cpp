#include <lab3/galois_field.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <set>
#include <vector>


using namespace crypto;
using namespace crypto::galois;

class GF28ServiceTest : public ::testing::Test {
protected:
    const GFService service;

    // Стандартный неприводимый полином из AES: x^8 + x^4 + x^3 + x + 1 (0x11B -> 0x1B)
    static constexpr std::uint8_t kAesModulus = 0x1B;
    // Еще один известный неприводимый полином: x^8 + x^4 + x^3 + x^2 + 1 (0x11D -> 0x1D)
    static constexpr std::uint8_t kAltModulus = 0x1D;
};

// ==============================================================================
// ТЕСТ 1: Сложение в GF(2^8)
// ==============================================================================
TEST_F(GF28ServiceTest, Add) {
    EXPECT_EQ(service.Add(0x57, 0x83), 0xD4);
    EXPECT_EQ(service.Add(0x53, 0xCA), 0x99);

    // Свойства поля характеристики 2: a + a = 0, a + 0 = a, коммутативность
    for (int a = 0; a <= 0xFF; ++a) {
        auto ua = static_cast<std::uint8_t>(a);
        EXPECT_EQ(service.Add(ua, ua), 0x00);
        EXPECT_EQ(service.Add(ua, 0x00), ua);
        EXPECT_EQ(service.Add(0x00, ua), ua);
    }
    EXPECT_EQ(service.Add(0xAB, 0xCD), service.Add(0xCD, 0xAB));
}

// ==============================================================================
// ТЕСТ 2: Степень полинома (Degree)
// ==============================================================================
TEST_F(GF28ServiceTest, Degree) {
    EXPECT_EQ(service.Degree(0x01), 0); // 1
    EXPECT_EQ(service.Degree(0x02), 1); // x
    EXPECT_EQ(service.Degree(0x03), 1); // x + 1
    EXPECT_EQ(service.Degree(0x04), 2); // x^2
    EXPECT_EQ(service.Degree(0x57), 6); // x^6 + x^4 + x^2 + x + 1
    EXPECT_EQ(service.Degree(0x80), 7); // x^7
    EXPECT_EQ(service.Degree(0xFF), 7); // x^7 + ... + 1
}

// ==============================================================================
// ТЕСТ 3: Деление с остатком (DivMod)
// ==============================================================================
TEST_F(GF28ServiceTest, DivMod) {
    // (x^3 + x + 1) / (x + 1) = (x^2 + x) mod (x + 1), остаток 1
    auto [q1, r1] = service.DivMod(0x0B, 0x03);
    EXPECT_EQ(q1, 0x06);
    EXPECT_EQ(r1, 0x01);

    // (x^4 + x^2 + 1) / (x^2 + x + 1) = (x^2 + x + 1), остаток 0
    auto [q2, r2] = service.DivMod(0x15, 0x07);
    EXPECT_EQ(q2, 0x07);
    EXPECT_EQ(r2, 0x00);

    // Делимое меньшей степени, чем делитель
    auto [q3, r3] = service.DivMod(0x05, 0x09);
    EXPECT_EQ(q3, 0x00);
    EXPECT_EQ(r3, 0x05);

    // Проверка инварианта: q * b + r == a и deg(r) < deg(b)
    for (std::uint8_t a : {0x00, 0x01, 0x13, 0x57, 0xAB, 0xFF}) {
        for (std::uint8_t b : {0x01, 0x03, 0x07, 0x1B, 0x80}) {
            auto [q, r] = service.DivMod(a, b);
            EXPECT_EQ(service.Add(service.MultiplyUnchecked(q, b, 0x00), r), a);
            if (r != 0) {
                EXPECT_LT(service.Degree(r), service.Degree(b));
            }
        }
    }
}

// ==============================================================================
// ТЕСТ 4: Умножение в GF(2^8) (Multiply и MultiplyUnchecked)
// ==============================================================================
TEST_F(GF28ServiceTest, MultiplyKnownVectorsAndProperties) {
    // Векторы из спецификации FIPS 197 (AES)
    EXPECT_EQ(service.Multiply(0x57, 0x13, kAesModulus), 0xFE);
    EXPECT_EQ(service.Multiply(0x57, 0x83, kAesModulus), 0xC1);
    EXPECT_EQ(service.Multiply(0x02, 0x87, kAesModulus), 0x15);
    EXPECT_EQ(service.Multiply(0x03, 0x6E, kAesModulus), 0xB2);

    // Работа с другим неприводимым модулем (0x1D)
    // x^7 * x = x^8 = x^4 + x^3 + x^2 + 1 (0x1D)
    EXPECT_EQ(service.Multiply(0x80, 0x02, kAltModulus), 0x1D);

    // Нейтральный элемент и умножение на 0
    EXPECT_EQ(service.Multiply(0x57, 0x01, kAesModulus), 0x57);
    EXPECT_EQ(service.Multiply(0x01, 0x57, kAesModulus), 0x57);
    EXPECT_EQ(service.Multiply(0x57, 0x00, kAesModulus), 0x00);

    // Коммутативность и дистрибутивность
    std::uint8_t a = 0x53, b = 0xCA, c = 0x19;
    EXPECT_EQ(
        service.Multiply(a, b, kAesModulus),
        service.Multiply(b, a, kAesModulus)
    );
    EXPECT_EQ(
        service.Multiply(a, service.Add(b, c), kAesModulus),
        service.Add(
            service.Multiply(a, b, kAesModulus),
            service.Multiply(a, c, kAesModulus)
        )
    );
}

TEST_F(GF28ServiceTest, MultiplyThrowsOnReducibleModulus) {
    // Приводимые полиномы степени 8:
    // 0x00 (x^8), 0x01 (x^8+1), 0x02 (x^8+x), 0x1A (делится на x+1), 0xFF (делится на x^2+x+1)
    for (std::uint8_t bad_mod : {0x00, 0x01, 0x02, 0x1A, 0xFF}) {
        EXPECT_THROW(
            service.Multiply(0x57, 0x13, bad_mod),
            ReducibleModulusException
        ) << "Expected ReducibleModulusException for modulus: 0x" << std::hex << int(bad_mod);
    }
}

TEST_F(GF28ServiceTest, MultiplyUncheckedDoesNotThrowAndMatchesMultiply) {
    // На неприводимом модуле совпадает с Multiply
    EXPECT_EQ(
        service.MultiplyUnchecked(0x57, 0x83, kAesModulus),
        service.Multiply(0x57, 0x83, kAesModulus)
    );

    // На приводимом модуле не бросает исключение
    EXPECT_NO_THROW({
        auto res = service.MultiplyUnchecked(0x57, 0x13, 0x01);
        (void)res;
    });
}

// ==============================================================================
// ТЕСТ 5: Обратный элемент в GF(2^8)
// ==============================================================================
TEST_F(GF28ServiceTest, InverseKnownVectorsAndExhaustiveCheck) {
    // Известные векторы для модуля AES (0x1B)
    EXPECT_EQ(service.Inverse(0x01, kAesModulus), 0x01);
    EXPECT_EQ(service.Inverse(0x53, kAesModulus), 0xCA);
    EXPECT_EQ(service.Inverse(0xCA, kAesModulus), 0x53);
    EXPECT_EQ(service.Inverse(0x02, kAesModulus), 0x8D);

    // Исчерпывающая проверка всех 255 ненулевых элементов поля для двух модулей
    for (std::uint8_t mod : {kAesModulus, kAltModulus}) {
        for (int i = 1; i <= 0xFF; ++i) {
            auto a = static_cast<std::uint8_t>(i);
            std::uint8_t inv = service.Inverse(a, mod);
            EXPECT_EQ(service.Multiply(a, inv, mod), 0x01)
                << "Failed inverse check for a=0x" << std::hex << int(a)
                << " mod 0x" << int(mod);
        }
    }
}

TEST_F(GF28ServiceTest, InverseThrowsOnReducibleModulus) {
    for (std::uint8_t bad_mod : {0x00, 0x01, 0x02, 0x1A, 0xFF}) {
        EXPECT_THROW(
            service.Inverse(0x53, bad_mod),
            ReducibleModulusException
        ) << "Expected ReducibleModulusException for modulus: 0x" << std::hex << int(bad_mod);
    }
}

// ==============================================================================
// ТЕСТ 6: Проверка неприводимости и генерация всех 30 полиномов
// ==============================================================================
TEST_F(GF28ServiceTest, IsIrreducible) {
    // Известные неприводимые полиномы степени 8 над GF(2)
    std::vector<std::uint8_t> irreducibles = {
        0x1B, 0x1D, 0x2B, 0x2D, 0x63, 0xF5
    };
    for (std::uint8_t p : irreducibles) {
        EXPECT_TRUE(service.IsIrreducible(p))
            << "Polynomial 0x" << std::hex << int(p) << " must be irreducible!";
    }

    // Известные приводимые полиномы степени 8 над GF(2)
    std::vector<std::uint8_t> reducibles = {
        0x00, // x^8
        0x01, // x^8 + 1 = (x + 1)^8
        0x02, // x^8 + x = x(x^7 + 1)
        0x1A, // четное число слагаемых -> делится на (x + 1)
        0x1C, // четное число слагаемых -> делится на (x + 1)
        0xFF  // x^8 + x^7 + ... + 1 -> делится на (x^2 + x + 1)
    };
    for (std::uint8_t p : reducibles) {
        EXPECT_FALSE(service.IsIrreducible(p))
            << "Polynomial 0x" << std::hex << int(p) << " must be reducible!";
    }
}

TEST_F(GF28ServiceTest, GenerateAllIrreduciblePolynomials) {
    std::vector<std::uint8_t> all_irreducibles = service.GenerateAllIrreduciblePolynomials();

    // По условию задачи неприводимых полиномов степени 8 ровно 30
    ASSERT_EQ(all_irreducibles.size(), 30U);

    // Все элементы в коллекции должны быть уникальными
    std::set<std::uint8_t> unique_set(all_irreducibles.begin(), all_irreducibles.end());
    EXPECT_EQ(unique_set.size(), 30U);

    // Каждый элемент обязан проходить проверку IsIrreducible
    for (std::uint8_t p : all_irreducibles) {
        EXPECT_TRUE(service.IsIrreducible(p));
    }

    // Сверяем с полным перебором 0..255
    std::size_t manual_count = 0;
    for (int i = 0; i <= 0xFF; ++i) {
        if (service.IsIrreducible(static_cast<std::uint8_t>(i))) {
            ++manual_count;
            EXPECT_TRUE(unique_set.contains(static_cast<std::uint8_t>(i)));
        }
    }
    EXPECT_EQ(manual_count, 30U);

    // Стандартный полином AES обязан присутствовать
    EXPECT_TRUE(unique_set.contains(kAesModulus));
}

// ==============================================================================
// ТЕСТ 7: Факторизация полинома произвольной степени (Factorize)
// ==============================================================================
// Примечание: тесты ниже предполагают упаковку полинома в байты (как и в остальном сервисе),
// например: 0x09 -> x^3 + 1. Если в вашей реализации BinaryPolynomial хранит по одному биту
// на байт (например, {1, 0, 0, 1}), адаптируйте тестовые векторы.
TEST_F(GF28ServiceTest, Factorize) {
    auto sort_factors = [](std::vector<BinaryPolynomial>& factors) {
        std::sort(factors.begin(), factors.end());
    };

    // 1. Неприводимый полином: x^2 + x + 1 (0x07)
    {
        BinaryPolynomial poly{0x07};
        auto factors = service.Factorize(poly);
        ASSERT_EQ(factors.size(), 1U);
        EXPECT_EQ(factors[0], poly);
    }

    // 2. Квадрат неприводимого: x^2 + 1 = (x + 1)^2  ->  0x05 = 0x03 * 0x03
    {
        BinaryPolynomial poly{0x05};
        auto factors = service.Factorize(poly);
        std::vector<BinaryPolynomial> expected{{0x03}, {0x03}};
        EXPECT_EQ(factors, expected);
    }

    // 3. Произведение различных неприводимых: x^3 + 1 = (x + 1)(x^2 + x + 1) -> 0x09 = 0x03 * 0x07
    {
        BinaryPolynomial poly{0x09};
        auto factors = service.Factorize(poly);
        std::vector<BinaryPolynomial> expected{{0x03}, {0x07}};
        sort_factors(factors);
        sort_factors(expected);
        EXPECT_EQ(factors, expected);
    }

    // 4. x^4 + x^2 + 1 = (x^2 + x + 1)^2 -> 0x15 = 0x07 * 0x07
    {
        BinaryPolynomial poly{0x15};
        auto factors = service.Factorize(poly);
        std::vector<BinaryPolynomial> expected{{0x07}, {0x07}};
        EXPECT_EQ(factors, expected);
    }

    // 5. Полином степени 8 (неприводимый AES полином x^8 + x^4 + x^3 + x + 1)
    // В little-endian по байтам это {0x1B, 0x01} (в big-endian {0x01, 0x1B}).
    // Проверяем, что для полинома степени >= 8 возвращается корректное непустое разложение.
    {
        BinaryPolynomial aes_poly_le{0x1B, 0x01};
        auto factors = service.Factorize(aes_poly_le);
        EXPECT_FALSE(factors.empty());
    }
}