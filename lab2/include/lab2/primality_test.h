#ifndef MAI_CB_2026_PRIMALITY_TEST_H
#define MAI_CB_2026_PRIMALITY_TEST_H

#include <lab2/math.h>


namespace crypto::primality {

    class IPrimalityTest {
    public:
        virtual ~IPrimalityTest() = default;

    public:
        virtual auto IsPrime(
            const BigInt &number,
            double min_probability
        ) const -> bool = 0;
    };

    class AbstractPrimalityTest : public IPrimalityTest {
    public:
        auto IsPrime(
            const BigInt &number,
            double min_probability
        ) const -> bool override;

    protected:
        auto GenerateRandomBase(
            const BigInt &number
        ) const -> BigInt;

    protected:
        virtual auto RunSingleIteration(
            const BigInt &number
        ) const -> bool = 0;

        virtual auto GetSingleIterationErrorProbability() const -> double = 0;
    };

    class FermatTest : public AbstractPrimalityTest {
    protected:
        auto RunSingleIteration(
            const BigInt &number
        ) const -> bool override;

        auto GetSingleIterationErrorProbability() const -> double override;
    };

    class SolovayStrassenTest : public AbstractPrimalityTest {
    protected:
        auto RunSingleIteration(
            const BigInt &number
        ) const -> bool override;

        auto GetSingleIterationErrorProbability() const -> double override;
    };

    class MillerRabinTest : public AbstractPrimalityTest {
    protected:
        auto RunSingleIteration(
            const BigInt &number
        ) const -> bool override;

        auto GetSingleIterationErrorProbability() const -> double override;
    };

}

#endif //MAI_CB_2026_PRIMALITY_TEST_H
