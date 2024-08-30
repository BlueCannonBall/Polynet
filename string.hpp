#ifndef _POLYNET_STRING_HPP
#define _POLYNET_STRING_HPP

#include <memory>
#include <stddef.h>
#include <string>
#include <string_view>

namespace pn {
    // A derivative of std::basic_string_view that is always null-terminated
    template <typename CharT, typename Traits = std::char_traits<CharT>>
    class BasicStringView : public std::basic_string_view<CharT, Traits> {
    public:
        constexpr BasicStringView() = default;
        constexpr BasicStringView(const CharT* str):
            std::basic_string_view<CharT, Traits>(str) {}
        BasicStringView(decltype(nullptr)) = delete;
        template <typename T>
        BasicStringView(const T& str):
            std::basic_string_view<CharT, Traits>(str.c_str(), str.size()) {}

        const CharT* c_str() const {
            return this->data();
        }

        template <typename Alloc = std::allocator<CharT>>
        std::basic_string<CharT, Traits, Alloc> substr(size_t pos = 0) const {
            return std::basic_string_view<CharT, Traits>::substr(pos);
        }

        template <typename Alloc = std::allocator<CharT>>
        std::basic_string<CharT, Traits, Alloc> substr(size_t pos, size_t count) const {
            auto ret = std::basic_string_view<CharT, Traits>::substr(pos, count);
            return std::basic_string<CharT, Traits, Alloc>(ret.begin(), ret.end());
        }

    private:
        // This function destroyes the guarantee of null-termination
        using std::basic_string_view<CharT, Traits>::remove_suffix;
    };

    using StringView = BasicStringView<char>;
    using WStringView = BasicStringView<wchar_t>;
    using U16StringView = BasicStringView<char16_t>;
    using U32StringView = BasicStringView<char32_t>;
} // namespace pn

#endif
