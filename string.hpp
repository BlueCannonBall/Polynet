#ifndef POLYNET_STRING_HPP_
#define POLYNET_STRING_HPP_

#include <memory>
#include <stddef.h>
#include <string>
#include <string_view>
#include <type_traits>

namespace pn {
    // A derivative of std::basic_string_view that is always null-terminated
    template <typename CharT, typename Traits = std::char_traits<CharT>>
    class BasicStringView : public std::basic_string_view<CharT, Traits> {
    protected:
        static constexpr const CharT* empty_string() {
            static_assert(
                std::is_same_v<CharT, char> ||
                    std::is_same_v<CharT, wchar_t> ||
                    std::is_same_v<CharT, char16_t> ||
                    std::is_same_v<CharT, char32_t>,
                "CharT must be char, wchar_t, char16_t, or char32_t");

            if constexpr (std::is_same_v<CharT, char>) {
                return "";
            } else if constexpr (std::is_same_v<CharT, wchar_t>) {
                return L"";
            } else if constexpr (std::is_same_v<CharT, char16_t>) {
                return u"";
            } else if constexpr (std::is_same_v<CharT, char32_t>) {
                return U"";
            } else {
                return nullptr;
            }
        }

    public:
        constexpr BasicStringView(const CharT* str = empty_string()):
            std::basic_string_view<CharT, Traits>(str) {}
        BasicStringView(decltype(nullptr)) = delete;
        template <typename T>
        BasicStringView(const T& str):
            std::basic_string_view<CharT, Traits>(str.c_str(), str.size()) {}

        const CharT* c_str() const {
            return this->data();
        }

        std::basic_string_view<CharT, Traits> substr(size_t pos = 0) const {
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
