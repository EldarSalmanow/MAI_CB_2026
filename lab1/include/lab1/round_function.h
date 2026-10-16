#ifndef MAI_CB_2026_ROUND_FUNCTION_H
#define MAI_CB_2026_ROUND_FUNCTION_H

#include <span>


class IRoundFunction {
public:
    virtual ~IRoundFunction() = default;

public:
    virtual auto ProcessBlock(
        std::span<const std::uint8_t> input_block,
        std::span<const std::uint8_t> round_key,
        std::span<std::uint8_t> output_block
    ) const -> void = 0;
};

#endif //MAI_CB_2026_ROUND_FUNCTION_H