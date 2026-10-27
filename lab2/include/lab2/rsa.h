#ifndef MAI_CB_2026_RSA_H
#define MAI_CB_2026_RSA_H

#include <lab2/math.h>


namespace crypto::rsa {

    struct PublicKey {
        BigInt e;
        BigInt n;
    };

    struct PrivateKey {
        BigInt d;
        BigInt n;
    };

    struct KeyPair {
        PublicKey public_key;
        PrivateKey private_key;
    };

    class RSAService {
    public:
        enum class PrimalityTestType {
            Fermat,
            SolovayStrassen,
            MillerRabin
        };

        class KeyGenerator {
        public:
            KeyGenerator(
                PrimalityTestType test_type,
                double min_probability,
                std::size_t bit_length
            );

        public:
            auto GenerateKeyPair() const -> KeyPair;

        private:
            PrimalityTestType test_type_;
            double min_probability_;
            std::size_t bit_length_;
        };

    public:
        RSAService(
            PrimalityTestType test_type,
            double min_probability,
            std::size_t bit_length
        );

    public:
        auto Encrypt(
            const BigInt &message,
            const PublicKey &public_key
        ) const -> BigInt;

        auto Decrypt(
            const BigInt &ciphertext,
            const PrivateKey &private_key
        ) const -> BigInt;

    public:
        auto GetKeyGenerator() const -> const KeyGenerator &;

    private:
        KeyGenerator key_generator_;
    };

} // namespace crypto::rsa

#endif //MAI_CB_2026_RSA_H
