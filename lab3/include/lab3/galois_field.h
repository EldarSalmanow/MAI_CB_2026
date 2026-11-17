#ifndef MAI_CB_2026_GALOIS_FIELD_H
#define MAI_CB_2026_GALOIS_FIELD_H

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>


namespace crypto::galois {

    class ReducibleModulusException : public std::invalid_argument {
    public:
        explicit ReducibleModulusException(
            const std::string &message = "[ERROR] Provided polynomial modulus is reducible!"
        ) : std::invalid_argument(message) {}
    };

    using BinaryPolynomial = std::vector<std::uint8_t>;

    class GFService {
    public:
        GFService() = default;

    public:
        ~GFService() = default;

    public:
        auto Add(
            std::uint8_t a,
            std::uint8_t b
        ) const -> std::uint8_t;

        auto Multiply(
            std::uint8_t a,
            std::uint8_t b,
            std::uint8_t modulus
        ) const -> std::uint8_t;

        auto MultiplyUnchecked(
            std::uint8_t a,
            std::uint8_t b,
            std::uint8_t modulus
        ) const -> std::uint8_t;

        auto DivMod(
            std::uint8_t a,
            std::uint8_t b
        ) const -> std::tuple<std::uint8_t, std::uint8_t>;

        auto Inverse(
            std::uint8_t a,
            std::uint8_t modulus
        ) const -> std::uint8_t;

        auto Degree(
            std::uint8_t a
        ) const -> std::uint8_t;

        auto IsIrreducible(
            std::uint8_t polynomial
        ) const -> bool;

        auto GenerateAllIrreduciblePolynomials() const -> std::vector<std::uint8_t>;

        auto Factorize(
            const BinaryPolynomial &polynomial
        ) const -> std::vector<BinaryPolynomial>;
    };

} // namespace crypto::galois

#endif //MAI_CB_2026_GALOIS_FIELD_H
