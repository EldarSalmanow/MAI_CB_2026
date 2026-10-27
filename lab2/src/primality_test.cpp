#include <lab2/primality_test.h>


namespace crypto::primality {

    auto AbstractPrimalityTest::IsPrime(
        const BigInt &number,
        double min_probability
    ) const -> bool {
        if (number <= 1) {
            return false;
        }

        if (number == 2 || number == 3) {
            return true;
        } else if (math::IsEven(number)) {
            return false;
        }

        const auto error = 1 - min_probability;
        const auto iteration_error = GetSingleIterationErrorProbability();

        auto k = static_cast<std::uint64_t>(std::ceil(std::log(error) / std::log(iteration_error)));
        k = std::max(k, 1ull);

        for (std::uint64_t i = 0; i < k; ++i) {
            if (!RunSingleIteration(number)) {
                return false;
            }
        }

        return true;
    }

    auto AbstractPrimalityTest::GenerateRandomBase(
        const BigInt &number
    ) const -> BigInt {
        return math::GenerateRandomInRange(2, number - 2);
    }

    auto FermatTest::RunSingleIteration(
        const BigInt &number
    ) const -> bool {
        const auto random_number = GenerateRandomBase(number);

        const auto pow_mod = math::PowMod(random_number, number - 1, number);

        return pow_mod == 1;
    }

    auto FermatTest::GetSingleIterationErrorProbability() const -> double {
        return 0.5;
    }

    auto SolovayStrassenTest::RunSingleIteration(
        const BigInt &number
    ) const -> bool {
        const auto random_number = GenerateRandomBase(number);

        const auto jacobi_symbol = math::JacobiSymbol(random_number, number);

        if (jacobi_symbol == 0) {
            return false;
        }

        const auto pow_mod = math::PowMod(random_number, (number - 1) / 2, number);

        switch (jacobi_symbol) {
            case 1: {
                return pow_mod == 1;
            }
            case -1: {
                return pow_mod == number - 1;
            }
            default: {
                // for linter. all jacobi symbol cases are handled

                return false;
            }
        }
    }

    auto SolovayStrassenTest::GetSingleIterationErrorProbability() const -> double {
        return 0.5;
    }

    auto MillerRabinTest::RunSingleIteration(
        const BigInt &number
    ) const -> bool {
        BigInt d = number - 1, s = 1;

        while (math::IsEven(d)) {
            d >>= 1;

            ++s;
        }

        const auto random_number = GenerateRandomBase(number);

        auto pow_mod = math::PowMod(random_number, d, number);

        if (pow_mod == 1 || pow_mod == number - 1) {
            return true;
        }

        for (BigInt i = 1; i <= s - 1; ++i) {
            pow_mod = (pow_mod * pow_mod) % number;

            if (pow_mod == number - 1) {
                return true;
            } else if (pow_mod == 1) {
                return false;
            }
        }

        return false;
    }

    auto MillerRabinTest::GetSingleIterationErrorProbability() const -> double {
        return 0.25;
    }

}
