#include <lab2/math.h>

#include <numbers>


namespace crypto::math {

    namespace detail {

        auto GCDEuclidianImpl::GCD(
            BigInt a,
            BigInt b
        ) -> BigInt {
            while (b > 0) {
                a %= b;

                std::swap(a, b);
            }

            return a;
        }

        auto GCDExtendedEuclidianImpl::GCD(
            const BigInt &a,
            const BigInt &b
        ) -> std::tuple<BigInt, BigInt, BigInt> {
            if (b == 0) {
                return std::make_tuple(a, 1, 0);
            }

            auto [gcd, x_tmp, y_tmp] = GCD(b, a % b);

            auto x = y_tmp;
            auto y = x_tmp - a / b  * y_tmp;

            return std::make_tuple(gcd, x, y);
        }

        auto GCDBinaryEuclidianImpl::GCD(
            const BigInt &a,
            const BigInt &b
        ) -> BigInt {
            if (a == b) {
                return a;
            }

            if (a == 0) {
                return b;
            }

            if (b == 0) {
                return a;
            }

            const auto even_a = IsEven(a), even_b = IsEven(b);
            if (even_a && even_b) {
                return GCD(a >> 1, b >> 1) << 1;
            } else if (even_a && !even_b) {
                return GCD(a >> 1, b);
            } else if (!even_a && even_b) {
                return GCD(a, b >> 1);
            } else {
                const auto diff = (a > b) ? (a - b) : (b - a);
                const auto min_value = (a < b) ? a : b;

                return GCD(diff, min_value);
            }
        }

        auto EulerFunctionDefinitionImpl::EulerFunction(
            BigInt n
        ) -> BigInt {
            BigInt result = 0;

            for (BigInt i = 1; i <= n; ++i) {
                result += GCD<GCDBinaryEuclidianImpl>(i, n) == 1;
            }

            return result;
        }

        auto EulerFunctionMATImpl::EulerFunction(
            BigInt n
        ) -> BigInt {
            BigInt result = n;

            for (BigInt i = 2; i * i <= n; ++i) {
                if (n % i == 0) {
                    while (n % i == 0) {
                        n /= i;
                    }

                    result -= result / i;
                }
            }

            if (n > 1) {
                result -= result / n;
            }

            return result;
        }

        auto EulerFunctionDFTImpl::EulerFunction(
            const BigInt &n
        ) -> BigInt {
            auto sum = 0.0;

            const auto tmp_n = n.convert_to<double>();

            for (BigInt i = 1; i <= n; ++i) {
                const auto tmp_i = i.convert_to<double>();

                const auto gcd = GCD<GCDBinaryEuclidianImpl>(i, n).convert_to<double>();
                const auto cosine = std::cos(2.0 * std::numbers::pi * tmp_i / tmp_n);

                sum += gcd * cosine;
            }

            return std::lround(sum);
        }

    }

    auto LegendreSymbol(
        const BigInt &a,
        const BigInt &p
    ) -> std::int32_t {
        if (a % p == 0) {
            return 0;
        }

        const auto result = PowMod(a, (p - 1) / 2, p);

        if (result == p - 1) {
            return -1;
        }

        return result.convert_to<std::int32_t>();
    }

    auto JacobiSymbol(
        BigInt a,
        BigInt n
    ) -> std::int32_t {
        if (n <= 0 || IsEven(n)) {
            return 0;
        }

        std::int32_t result = 1;

        a %= n;
        if (a < 0) {
            a += n;
        }

        while (a != 0) {
            while (IsEven(a)) {
                a >>= 1;

                BigInt rem = n % 8;
                if (rem == 3 || rem == 5) {
                    result = -result;
                }
            }

            std::swap(a, n);

            if ((a % 4 == 3) && (n % 4 == 3)) {
                result = -result;
            }

            a %= n;
        }

        if (n == 1) {
            return result;
        }

        return 0;
    }

    auto LCM(
        const BigInt &a,
        const BigInt &b
    ) -> BigInt {
        if (a == 0 || b == 0) {
            return 0;
        }

        return a / GCD<detail::GCDBinaryEuclidianImpl>(a, b) * b;
    }

    auto PowMod(
        BigInt a,
        BigInt n,
        const BigInt &m
    ) -> BigInt {
        BigInt result = 1;
        a %= m;

        while (n > 0) {
            if (!IsEven(n)) {
                result = (result * a) % m;
            }

            a = (a * a) % m;
            n >>= 1;
        }

        return result;
    }

    auto CarmichaelFunction(
        const BigInt &n
    ) -> BigInt {
        if (n <= 0) {
            return 0;
        }

        if (n == 1) {
            return 1;
        }

        BigInt temp = n, result = 1;

        if (temp % 2 == 0) {
            std::size_t k = 0;

            while (temp % 2 == 0) {
                temp /= 2;

                ++k;
            }

            BigInt lambda_2 = 1;
            if (k == 1) {
                lambda_2 = 1;
            } else if (k == 2) {
                lambda_2 = 2;
            } else {
                lambda_2 = BigInt(1) << (k - 2);
            }

            result = LCM(result, lambda_2);
        }

        for (BigInt i = 3; i * i <= temp; i += 2) {
            if (temp % i == 0) {
                BigInt p_pow = 1;

                temp /= i;

                while (temp % i == 0) {
                    temp /= i;

                    p_pow *= i;
                }

                BigInt lambda_p = p_pow * (i - 1);

                result = LCM(result, lambda_p);
            }
        }

        if (temp > 1) {
            BigInt lambda_p = temp - 1;

            result = LCM(result, lambda_p);
        }

        return result;
    }

    auto IsEven(
        const BigInt &n
    ) -> bool {
        return !(n & 1);
    }

}

void t() {
    auto r = crypto::math::GCD<crypto::math::detail::GCDExtendedEuclidianImpl>(1, 103);
}
