#ifndef MAI_CB_2026_KEY_EXPANDER_H
#define MAI_CB_2026_KEY_EXPANDER_H

#include <span>
#include <vector>


class IKeyExpander {
public:
    virtual ~IKeyExpander() = default;

public:
    virtual auto ExpandKey(
        std::span<const std::uint8_t> base_key
    ) const -> std::vector<std::vector<std::uint8_t>> = 0;
};

#endif //MAI_CB_2026_KEY_EXPANDER_H