#ifndef MAI_CB_2026_MATH_H
#define MAI_CB_2026_MATH_H

#include <boost/multiprecision/cpp_int.hpp>


namespace crypto::math {

    using BigInt = boost::multiprecision::cpp_int;

    namespace detail {

        struct GCDEuclidianImpl {

            static auto GCD(
                BigInt a,
                BigInt b
            ) -> BigInt;

        };

        struct GCDExtendedEuclidianImpl {

            static auto GCD(
                const BigInt &a,
                const BigInt &b
            ) -> std::tuple<BigInt, BigInt, BigInt>;

        };

        struct GCDBinaryEuclidianImpl {

            static auto GCD(
                const BigInt &a,
                const BigInt &b
            ) -> BigInt;

        };

        // by definition
        struct EulerFunctionDefinitionImpl {

            static auto EulerFunction(
                BigInt n
            ) -> BigInt;

        };

        // MAT - Main Arithmetic Theorem
        struct EulerFunctionMATImpl {

            static auto EulerFunction(
                BigInt n
            ) -> BigInt;

        };

        // DFT - discrete Furier Transform
        struct EulerFunctionDFTImpl {

            static auto EulerFunction(
                const BigInt &n
            ) -> BigInt;

        };

    }

    auto LegendreSymbol(
        const BigInt &a,
        const BigInt &p
    ) -> std::int32_t;

    auto JacobiSymbol(
        BigInt a,
        BigInt n
    ) -> std::int32_t;

    template<typename ImplT>
    auto GCD(
        const BigInt &a,
        const BigInt &b
    ) -> decltype(auto)  {
        return ImplT::GCD(a, b);
    }

    auto LCM(
        const BigInt &a,
        const BigInt &b
    ) -> BigInt;

    auto PowMod(
        BigInt a,
        BigInt n,
        const BigInt &m
    ) -> BigInt;

    template<typename ImplT, typename ...ArgsT>
    auto EulerFunction(
        ArgsT &&...arguments
    ) -> decltype(auto) {
        return ImplT::EulerFunction(std::forward<ArgsT>(arguments)...);
    }

    auto CarmichaelFunction(
        const BigInt &n
    ) -> BigInt;

    auto IsEven(
        const BigInt &n
    ) -> bool;

}

#endif //MAI_CB_2026_MATH_H