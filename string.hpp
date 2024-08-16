#ifndef _POLYNET_STRING_HPP
#define _POLYNET_STRING_HPP

#include <cstddef>
#include <string>
#include <string_view>

namespace pn {
    // A derivative of std::basic_string_view that is always null-terminated
    template <typename CharT, typename Traits = std::char_traits<CharT>>
    class BasicStringView : public std::basic_string_view<CharT, Traits> {
    public:
        BasicStringView():
            std::basic_string_view<CharT, Traits>() {}
        BasicStringView(const CharT* str):
            std::basic_string_view<CharT, Traits>(str) {}
        BasicStringView(std::nullptr_t) = delete;
        template <typename T>
        BasicStringView(const T& str):
            BasicStringView(str.c_str()) {}

        typename std::basic_string_view<CharT, Traits>::const_pointer c_str() const {
            return this->data();
        }

    private:
        // Some of std::basic_string_view's member functions are incompatible with our guarantee of null-termination
        using std::basic_string_view<CharT, Traits>::remove_suffix;
    };

    using StringView = BasicStringView<char>;
    using WStringView = BasicStringView<wchar_t>;
    using U16StringView = BasicStringView<char16_t>;
    using U32StringView = BasicStringView<char32_t>;
} // namespace pn

#endif
