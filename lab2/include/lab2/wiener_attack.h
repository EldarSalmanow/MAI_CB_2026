#ifndef MAI_CB_2026_WIENER_ATTACK_H
#define MAI_CB_2026_WIENER_ATTACK_H

#include <lab2/rsa.h>

#include <optional>


namespace crypto::attacks {

    struct Fraction {
        BigInt numerator;
        BigInt denominator;
    };

    struct WienerAttackResult {
        BigInt d;
        BigInt phi_n;
        std::vector<Fraction> fractions;
    };

    class WienerAttackService {
    public:
        auto Execute(
            const rsa::PublicKey &public_key
        ) const -> std::optional<WienerAttackResult>;
    };

    class VulnerableKeyPairGenerator {
    public:
        VulnerableKeyPairGenerator(
            rsa::RSAService::PrimalityTestType test_type,
            double min_probability,
            std::size_t bit_length
        );

    public:
        auto GenerateKeyPair() const -> rsa::KeyPair;

    private:
        rsa::RSAService::PrimalityTestType test_type_;
        double min_probability_;
        std::size_t bit_length_;
    };

} // namespace crypto::attacks

#endif //MAI_CB_2026_WIENER_ATTACK_H
