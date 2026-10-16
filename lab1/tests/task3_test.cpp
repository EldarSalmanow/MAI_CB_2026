#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <vector>

#include <lab1/cipher_context.h>
#include <lab1/feistel_network.h>

// =========================================================================
// 1. MOCK-ОБЪЕКТЫ ДЛЯ СЕТИ ФЕЙСТЕЛЯ
// =========================================================================

// Заглушка расширителя ключа. 
// Генерирует заданное количество раундовых ключей, где каждый байт ключа равен номеру раунда.
class MockKeyExpander : public IKeyExpander {
private:
    std::size_t m_rounds;
    std::size_t m_round_key_size;
public:
    MockKeyExpander(std::size_t rounds, std::size_t round_key_size) 
        : m_rounds(rounds), m_round_key_size(round_key_size) {}

    std::vector<std::vector<std::uint8_t>> ExpandKey(std::span<const std::uint8_t> base_key) const override {
        std::vector<std::vector<std::uint8_t>> keys;
        // Генерируем ключи (например, ключ 1 раунда: 0x11, ключ 2 раунда: 0x22 и т.д.)
        for (std::size_t i = 1; i <= m_rounds; ++i) {
            keys.push_back(std::vector<std::uint8_t>(m_round_key_size, static_cast<std::uint8_t>(i * 0x11)));
        }
        return keys;
    }
};

// Заглушка раундовой функции F.
// Простая реализация: F(R, K) = R XOR K
class MockRoundFunction : public IRoundFunction {
public:
    void ProcessBlock(
        std::span<const std::uint8_t> input_block,
        std::span<const std::uint8_t> round_key,
        std::span<std::uint8_t> output_block
    ) const override {
        for (std::size_t i = 0; i < input_block.size(); ++i) {
            output_block[i] = input_block[i] ^ round_key[i % round_key.size()];
        }
    }
};


// =========================================================================
// 2. БАЗОВАЯ НАСТРОЙКА И ТЕСТЫ НА ИСКЛЮЧЕНИЯ
// =========================================================================

template<std::size_t Size>
concept ValidFeistelBlockSize = requires { typename FeistelNetwork<Size>; };

// static_assert(!ValidFeistelBlockSize<0>);
// static_assert(!ValidFeistelBlockSize<7>);
static_assert(ValidFeistelBlockSize<4> && ValidFeistelBlockSize<8> && ValidFeistelBlockSize<16>);

TEST(FeistelNetworkTest, InPlaceRoundTrip16ByteBlock) {
    FeistelNetwork<16> network(
        std::make_unique<MockKeyExpander>(6, 8),
        std::make_unique<MockRoundFunction>()
    );
    network.SetEncryptionKey(std::vector<std::uint8_t>{0});
    EXPECT_EQ(network.BlockSize(), 16);
    const std::vector<std::uint8_t> plain{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    auto block = plain;
    std::vector<std::uint8_t> expected(16);
    network.EncryptBlock(plain, expected);
    network.EncryptBlock(block, block);
    EXPECT_EQ(block, expected);
    network.DecryptBlock(block, block);
    EXPECT_EQ(block, plain);
}

TEST(FeistelNetworkTest, ThrowsOnUninitializedKey) {
    FeistelNetwork<8> network(
        std::make_unique<MockKeyExpander>(4, 4),
        std::make_unique<MockRoundFunction>()
    );

    std::vector<std::uint8_t> input(8, 0x00);
    std::vector<std::uint8_t> output(8, 0x00);

    // Пытаемся зашифровать до вызова SetEncryptionKey
    EXPECT_THROW({
        network.EncryptBlock(input, output);
    }, std::runtime_error);
}

TEST(FeistelNetworkTest, ThrowsOnInvalidInputSize) {
    FeistelNetwork<8> network(
        std::make_unique<MockKeyExpander>(4, 4),
        std::make_unique<MockRoundFunction>()
    );

    std::vector<std::uint8_t> key = {0x00};
    network.SetEncryptionKey(key);

    std::vector<std::uint8_t> bad_input(5, 0x00); // Ожидается 8 байт
    std::vector<std::uint8_t> output(8, 0x00);

    EXPECT_THROW({
        network.EncryptBlock(bad_input, output);
    }, std::runtime_error);
}

// =========================================================================
// 3. ТЕСТ РУЧНОЙ ТРАССИРОВКИ (KNOWN ANSWER TEST)
// Мы вручную просчитали 2 раунда Сети Фейстеля и сверяем байты.
// Этот тест гарантирует, что половины L и R меняются местами правильно!
// =========================================================================
TEST(FeistelNetworkTest, ManualMathTrace2Rounds) {
    // Настраиваем сеть на 4 байта (L = 2 байта, R = 2 байта) и 2 раунда
    FeistelNetwork<4> network(
        std::make_unique<MockKeyExpander>(2, 2),
        std::make_unique<MockRoundFunction>()
    );

    // Устанавливаем ключ. MockKeyExpander сгенерирует: 
    // K1 = {0x11, 0x11}, K2 = {0x22, 0x22}
    std::vector<std::uint8_t> key = {0x00};
    network.SetEncryptionKey(key);

    // Входной блок: {0x01, 0x02, 0x03, 0x04}
    // L0 = {0x01, 0x02}, R0 = {0x03, 0x04}
    std::vector<std::uint8_t> input = {0x01, 0x02, 0x03, 0x04};
    std::vector<std::uint8_t> output(4);

    network.EncryptBlock(input, output);

    /* --- Математика 1 раунда ---
       F(R0, K1) = {0x03^0x11, 0x04^0x11} = {0x12, 0x15}
       L1 = R0 = {0x03, 0x04}
       R1 = L0 ^ F = {0x01^0x12, 0x02^0x15} = {0x13, 0x17}
       
       --- Математика 2 раунда ---
       F(R1, K2) = {0x13^0x22, 0x17^0x22} = {0x31, 0x35}
       L2 = R1 = {0x13, 0x17}
       R2 = L1 ^ F = {0x03^0x31, 0x04^0x35} = {0x32, 0x31}
       
       --- Финал сети Фейстеля ---
       Выход = R2 || L2 = {0x32, 0x31, 0x13, 0x17}
    */
    std::vector<std::uint8_t> expected_cipher = {0x32, 0x31, 0x13, 0x17};
    EXPECT_EQ(output, expected_cipher);

    // Теперь проверяем дешифрование (оно должно работать в обратную сторону)
    std::vector<std::uint8_t> decrypted(4);
    network.SetDecryptionKey(key);
    network.DecryptBlock(output, decrypted);
    
    EXPECT_EQ(decrypted, input);
}

// =========================================================================
// 4. ТЕСТ СИММЕТРИИ (МНОГО РАУНДОВ)
// Имитируем глубину шифра DES (16 раундов) и проверяем обратимость.
// =========================================================================
TEST(FeistelNetworkTest, Symmetry16Rounds) {
    FeistelNetwork<8> network(
        std::make_unique<MockKeyExpander>(16, 4), // 16 раундов, ключ 4 байта
        std::make_unique<MockRoundFunction>()
    );

    std::vector<std::uint8_t> key = {0xAA, 0xBB, 0xCC}; // Заглушка, MockExpander её игнорит
    
    std::vector<std::uint8_t> input = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};
    std::vector<std::uint8_t> encrypted(8);
    std::vector<std::uint8_t> decrypted(8);

    network.SetEncryptionKey(key);
    network.EncryptBlock(input, encrypted);

    // Шифротекст должен кардинально отличаться от оригинала
    EXPECT_NE(input, encrypted); 

    network.SetDecryptionKey(key);
    network.DecryptBlock(encrypted, decrypted);

    // Но после дешифровки всё должно вернуться к исходному виду
    EXPECT_EQ(input, decrypted);
}

// =========================================================================
// 5. ИНТЕГРАЦИОННЫЙ ТЕСТ (Задание 3 + Задание 2)
// Докажем, что Сеть Фейстеля идеально встраивается в наш Контекст Шифрования!
// =========================================================================

// Для передачи в шаблон SymmetricCipherContext нам нужен класс с конструктором по умолчанию
// Именно так будет выглядеть ваш DESAlgorithm в задании 4.
class DummyDesSimulation : public FeistelNetwork<8> {
public:
    DummyDesSimulation() : FeistelNetwork<8>(
        std::make_unique<MockKeyExpander>(16, 4), 
        std::make_unique<MockRoundFunction>()
    ) {}
};

TEST(FeistelNetworkTest, IntegrationWithContext) {
    std::vector<std::uint8_t> key = {1, 2, 3, 4};
    CipherParams params;
    params.iv = {0, 0, 0, 0, 0, 0, 0, 0}; // 8 нулей

    // Запускаем сеть Фейстеля внутри режима CBC с набивкой PKCS7
    SymmetricCipherContext<DummyDesSimulation> ctx(
        key, CipherMode::CBC, PaddingMode::PKCS7, params
    );

    std::vector<std::uint8_t> plaintext = {0x01, 0x02, 0x03}; // 3 байта (нужен Padding)
    
    // Асинхронное шифрование через контекст!
    auto ciphertext = ctx.EncryptAsync(plaintext).get();
    
    // Блок 8 байт (т.к. 3 + 5 байт PKCS7 padding)
    EXPECT_EQ(ciphertext.size(), 8); 

    auto decrypted = ctx.DecryptAsync(ciphertext).get();
    
    EXPECT_EQ(decrypted, plaintext);
}
