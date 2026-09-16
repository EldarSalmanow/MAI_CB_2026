#include <gtest/gtest.h>
#include <vector>
#include <cstdint>
#include <stdexcept>

#include <lab1/utils.h>

class PermuteBitsTest : public ::testing::Test {
protected:
    void ExpectVectorsEqual(const std::vector<uint8_t>& expected, const std::vector<uint8_t>& actual) {
        ASSERT_EQ(expected.size(), actual.size()) << "Размеры массивов не совпадают!";
        for (size_t i = 0; i < expected.size(); ++i) {
            EXPECT_EQ(expected[i], actual[i]) << "Несовпадение в байте по индексу " << i;
        }
    }
};

TEST_F(PermuteBitsTest, EmptyInputYieldsEmptyOutput) {
    std::vector<uint8_t> empty_bytes;
    std::vector<uint64_t> empty_p_block;
    
    auto result = PermuteBits(empty_bytes, empty_p_block, BitOrder::LsbToMsb, IndexBase::ZeroBased);

    EXPECT_TRUE(result.empty());
}

// TEST_F(PermuteBitsTest, ThrowsOnOutOfBoundsIndex) {
//     std::vector<uint8_t> input = { 0xFF }; // Всего 8 бит (индексы 0-7)
//     std::vector<uint64_t> p_block = { 8 }; // Пытаемся прочитать 9-й бит!
//
//     EXPECT_THROW({
//         PermuteBits(input, p_block, BitOrder::LsbToMsb, IndexBase::ZeroBased);
//     }, std::out_of_range) << "Функция должна бросать исключение при выходе за границы входного массива!";
// }

TEST_F(PermuteBitsTest, LsbZeroBased_CrossBytePermutation) {
    std::vector<uint8_t> input = { 0x0F, 0xF0 };
    std::vector<uint64_t> p_block = {
        8, 9, 10, 11, 12, 13, 14, 15,
        0, 1, 2,  3,  4,  5,  6,  7
    };
    
    auto result = PermuteBits(input, p_block, BitOrder::LsbToMsb, IndexBase::ZeroBased);

    std::vector<uint8_t> expected = { 0xF0, 0x0F };
    ExpectVectorsEqual(expected, result);
}

TEST_F(PermuteBitsTest, GlobalMsbOneBased_Extraction) {
    std::vector<uint8_t> input = { 0x01, 0x80 };
    std::vector<uint64_t> p_block = { 1, 16 };

    auto result = PermuteBits(input, p_block, BitOrder::MsbToLsb, IndexBase::OneBased);

    std::vector<uint8_t> expected = { 0x03 };
    ExpectVectorsEqual(expected, result);
}

TEST_F(PermuteBitsTest, Expansion_DuplicatesBits) {
    std::vector<uint8_t> input = { 0x01 };
    std::vector<uint64_t> p_block(16, 0);
    
    auto result = PermuteBits(input, p_block, BitOrder::LsbToMsb, IndexBase::ZeroBased);

    std::vector<uint8_t> expected = { 0xFF, 0xFF };
    ExpectVectorsEqual(expected, result);
}

TEST_F(PermuteBitsTest, Compression_NonMultipleOfEight) {
    std::vector<uint8_t> input = { 0xFF, 0xFF };
    std::vector<uint64_t> p_block = { 0, 1, 2 };
    
    auto result = PermuteBits(input, p_block, BitOrder::LsbToMsb, IndexBase::ZeroBased);

    std::vector<uint8_t> expected = { 0x07 };
    ExpectVectorsEqual(expected, result);
}

TEST_F(PermuteBitsTest, Stress_LeftShiftByteArray) {
    std::vector<uint8_t> input = { 0xDE, 0xAD, 0xBE, 0xEF };
    std::vector<uint64_t> p_block;

    for (uint64_t i = 1; i < 32; ++i) {
        p_block.push_back(i);
    }
    p_block.push_back(0);
    
    auto result = PermuteBits(input, p_block, BitOrder::LsbToMsb, IndexBase::ZeroBased);

    ASSERT_EQ(4, result.size());
}
