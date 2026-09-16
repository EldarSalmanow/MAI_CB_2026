#include <iostream>

#include <lab1/utils.h>


int main() {
    std::vector<std::uint8_t> bytes = {3}; // 00000011
    std::vector<std::uint64_t> p_block = {2, 4, 2, 1, 3}; // 00001101 = 8 + 4 + 1 = 13
    auto result = PermuteBits(bytes, p_block, BitOrder::LsbToMsb, IndexBase::OneBased);

    for (const auto &byte : result) {
        std::cout << static_cast<std::uint32_t>(byte) << " ";
    }

    return 0;
}
