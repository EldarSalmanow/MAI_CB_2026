#include <lab2/primality_test.h>
#include <lab2/wiener_attack.h>


namespace crypto::attacks {

    auto WienerAttackService::Execute(
        const rsa::PublicKey &public_key
    ) const -> std::optional<WienerAttackResult> {
        auto a = public_key.e, b = public_key.n;

        std::vector<Fraction> fractions;
        fractions.emplace_back(0, 1);
        fractions.emplace_back(1, 0);

        for (std::uint64_t i = 2; b > 0; ++i) {
            BigInt q = a / b;

            BigInt tmp = a % b;
            a = b;
            b = tmp;

            const auto prev_1 = fractions[i - 1], prev_2 = fractions[i - 2];
            fractions.emplace_back(
                q * prev_1.numerator + prev_2.numerator,
                q * prev_1.denominator + prev_2.denominator
            );

            const auto current = fractions[i];
            if (current.numerator == 0) {
                continue;
            } else if ((public_key.e * current.denominator - 1) % current.numerator != 0) {
                continue;
            }

            const auto potential_euler = (public_key.e * current.denominator - 1) / current.numerator;

            if (potential_euler <= 0 || potential_euler >= public_key.n) {
                continue;
            }

            const auto B = public_key.n - potential_euler + 1;
            const auto D = B * B - 4 * public_key.n;

            if (D < 0) {
                continue;
            }

            const auto S = boost::multiprecision::sqrt(D);

            if ((S * S == D) && ((B + S) % 2 == 0)) {
                return WienerAttackResult {
                    current.denominator,
                    potential_euler,
                    fractions
                };
            }
        }

        return std::nullopt;
    }

    VulnerableKeyPairGenerator::VulnerableKeyPairGenerator(
        rsa::RSAService::PrimalityTestType test_type,
        double min_probability,
        std::size_t bit_length
    ) : test_type_(test_type),
        min_probability_(min_probability),
        bit_length_(bit_length) {}

    auto VulnerableKeyPairGenerator::GenerateKeyPair() const -> rsa::KeyPair {
        std::unique_ptr<primality::IPrimalityTest> primality_test;

        switch (test_type_) {
            case rsa::RSAService::PrimalityTestType::Fermat: {
                primality_test = std::make_unique<primality::FermatTest>();

                break;
            }
            case rsa::RSAService::PrimalityTestType::SolovayStrassen: {
                primality_test = std::make_unique<primality::SolovayStrassenTest>();

                break;
            }
            case rsa::RSAService::PrimalityTestType::MillerRabin: {
                primality_test = std::make_unique<primality::MillerRabinTest>();

                break;
            }
        }

        BigInt p = 0;
        bool p_is_ok = false;
        while (!p_is_ok) {
            p = math::GenerateRandomOddWithBitLength(bit_length_);

            p_is_ok = primality_test->IsPrime(p, min_probability_);
        }

        BigInt q = 0;
        bool q_is_ok = false;
        while (!q_is_ok) {
            q = math::GenerateRandomOddWithBitLength(bit_length_);

            if (!primality_test->IsPrime(q, min_probability_)) {
                continue;
            }

            const auto diff = (p > q) ? (p - q) : (q - p);

            q_is_ok = diff >= (BigInt(1) << (bit_length_ / 2));
        }

        const auto n = p * q;

        const auto phi = (p - 1) * (q - 1);

        const auto wiener = boost::multiprecision::sqrt(boost::multiprecision::sqrt(n)) / 3;

        BigInt e = 0, d = 0;
        bool e_d_is_not_ok = false;
        while (!e_d_is_not_ok) {
            bool d_is_not_ok = false;
            while (!d_is_not_ok) {
                d = math::GenerateRandomInRange(3, wiener - 1);

                d_is_not_ok = math::GCD<math::detail::GCDEuclidianImpl>(d, phi) == 1;
            }

            bool e_is_not_ok = true;
            auto [gcd, x, y] = math::GCD<math::detail::GCDExtendedEuclidianImpl>(d, phi);
            e = x;

            if (e < 0) {
                e += phi;
            }

            e_d_is_not_ok = e_is_not_ok && d_is_not_ok;
        }

        return rsa::KeyPair {
            .public_key = rsa::PublicKey {
                .e = e,
                .n = n
            },
            .private_key = rsa::PrivateKey {
                .d = d,
                .n = n
            }
        };
    }

}
