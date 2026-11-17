#include <bit>
#include <lab3/galois_field.h>


namespace crypto::galois {

    auto GFService::Add(
        std::uint8_t a,
        std::uint8_t b
    ) const -> std::uint8_t {
        return static_cast<std::uint8_t>(a ^ b);
    }

    auto GFService::Multiply(
        std::uint8_t a,
        std::uint8_t b,
        std::uint8_t modulus
    ) const -> std::uint8_t {
        if (!IsIrreducible(modulus)) {
            throw ReducibleModulusException();
        }

        return MultiplyUnchecked(a, b, modulus);
    }

    auto GFService::MultiplyUnchecked(
        std::uint8_t a,
        std::uint8_t b,
        std::uint8_t modulus
    ) const -> std::uint8_t {
        std::uint8_t result = 0;

        while (b != 0) {
            if (b & 1U) {
                result = Add(result, a);
            }

            const bool high_bit_set = (a & 0x80U) != 0;
            a = static_cast<std::uint8_t>(a << 1U);

            if (high_bit_set) {
                a = Add(a, modulus);
            }

            b >>= 1U;
        }

        return result;

        // std::uint8_t result = 0;
        // for (; b > 0; b >>= 1) {
        //     if (!(b & 1)) {
        //         result = Add(result, a);
        //     }
        //
        //     const bool high_bit = a & (1 << 7);
        //
        //     a <<= 1;
        //
        //     if (high_bit) {
        //         a ^= modulus;
        //     }
        // }
        //
        // return result;
    }

    auto GFService::DivMod(
        std::uint8_t a,
        std::uint8_t b
    ) const -> std::tuple<std::uint8_t, std::uint8_t> {
        if (b == 0) {
            throw std::invalid_argument("[ERROR] Division by zero polynomial!");
        }

        std::uint8_t q = 0, r = a;

        for (const std::uint8_t deg_b = Degree(b); r != 0 && Degree(r) >= deg_b;) {
            const auto shift = static_cast<std::uint8_t>(Degree(r) - deg_b);

            q |= static_cast<std::uint8_t>(1U << shift);
            r = Add(r, static_cast<std::uint8_t>(b << shift));
        }

        return {q, r};

        // if (b == 0) {
        //     throw std::runtime_error("[ERROR] Division by zero!");
        // }
        //
        // std::uint8_t q = 0, r = a;
        //
        // for (std::uint8_t deg_b = Degree(b); Degree(r) >= deg_b;) {
        //     const std::uint8_t shift = Degree(r) - deg_b;
        //
        //     q = Add(q, 1 << shift);
        //     r = Add(r, b << shift);
        // }
        //
        // return {q, r};
    }

    auto GFService::Inverse(
        std::uint8_t a,
        std::uint8_t modulus
    ) const -> std::uint8_t {
        if (!IsIrreducible(modulus)) {
            throw ReducibleModulusException();
        }

        std::uint8_t result = 1;

        for (std::uint8_t i = 0; i < 254; ++i) {
            result = MultiplyUnchecked(result, a, modulus);
        }

        return result;
    }

    auto GFService::IsIrreducible(
        std::uint8_t polynomial
    ) const -> bool {
        if ((polynomial & 1) == 0) {
            return false;
        }

        for (std::uint8_t d = 3; d < 32; d += 2) {
            // Сдвигаем делитель d так, чтобы его старший бит встал на позицию x^8
            const std::uint8_t shift = static_cast<std::uint8_t>(8U - Degree(d));

            // Первый шаг деления: x^8 сокращается с x^8,
            // а младшие 8 бит сдвинутого d складываются (XOR) с polynomial
            const std::uint8_t after_first_step = Add(polynomial, static_cast<std::uint8_t>(d << shift));

            auto [_, remainder] = DivMod(after_first_step, d);

            if (remainder == 0) {
                return false;
            }
        }

        return true;
    }

    auto GFService::GenerateAllIrreduciblePolynomials() const -> std::vector<std::uint8_t> {
        std::vector<std::uint8_t> result;

        for (std::uint16_t b = 1; b <= 255; b += 2) {
            if (IsIrreducible(b)) {
                result.emplace_back(b);
            }
        }

        return result;
    }

    auto GFService::Factorize(
        const BinaryPolynomial &polynomial
    ) const -> std::vector<BinaryPolynomial> {
        return {};
    }

    auto GFService::Degree(
        std::uint8_t a
    ) const -> std::uint8_t {
        if (a == 0) {
            return -1;
        }

        return std::bit_width(a) - 1;
    }
}
