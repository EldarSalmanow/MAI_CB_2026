#include <lab2/primality_test.h>
#include <lab2/rsa.h>


namespace crypto::rsa {

    RSAService::KeyGenerator::KeyGenerator(
        PrimalityTestType test_type,
        double min_probability,
        std::size_t bit_length
    ) : test_type_(test_type),
        min_probability_(min_probability),
        bit_length_(bit_length) {}

    auto RSAService::KeyGenerator::GenerateKeyPair() const -> KeyPair {
        std::unique_ptr<primality::IPrimalityTest> primality_test;

        switch (test_type_) {
            case PrimalityTestType::Fermat: {
                primality_test = std::make_unique<primality::FermatTest>();

                break;
            }
            case PrimalityTestType::SolovayStrassen: {
                primality_test = std::make_unique<primality::SolovayStrassenTest>();

                break;
            }
            case PrimalityTestType::MillerRabin: {
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

        const auto L = math::LCM(p - 1, q - 1);

        const auto wiener = boost::multiprecision::sqrt(boost::multiprecision::sqrt(n)) / 3;

        BigInt e = 0, d = 0;
        bool e_d_is_ok = false;
        while (!e_d_is_ok) {
            bool e_is_ok = false;
            while (!e_is_ok) {
                e = math::GenerateRandomInRange(3, L - 1);

                e_is_ok = math::GCD<math::detail::GCDEuclidianImpl>(e, L) == 1;
            }

            bool d_is_ok = false;
            auto [gcd, x, y] = math::GCD<math::detail::GCDExtendedEuclidianImpl>(e, L);
            d = x;

            if (d < 0) {
                d += L;
            }

            d_is_ok = d > wiener;

            e_d_is_ok = e_is_ok && d_is_ok;
        }

        return KeyPair {
            .public_key = PublicKey {
                .e = e,
                .n = n
            },
            .private_key = PrivateKey {
                .d = d,
                .n = n
            }
        };
    }

    RSAService::RSAService(
        PrimalityTestType test_type,
        double min_probability,
        std::size_t bit_length
    ) : key_generator_(test_type, min_probability, bit_length) {}

    auto RSAService::Encrypt(
        const BigInt &message,
        const PublicKey &public_key
    ) const -> BigInt {
        return math::PowMod(message, public_key.e, public_key.n);
    }

    auto RSAService::Decrypt(
        const BigInt &ciphertext,
        const PrivateKey &private_key
    ) const -> BigInt {
        return math::PowMod(ciphertext, private_key.d, private_key.n);
    }

    auto RSAService::GetKeyGenerator() const -> const KeyGenerator & {
        return key_generator_;
    }

}
