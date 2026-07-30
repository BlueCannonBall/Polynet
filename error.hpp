#ifndef POLYNET_ERROR_HPP_
#define POLYNET_ERROR_HPP_

#include "string.hpp"
#include <errno.h>
#include <expected>
#include <string>
#include <system_error>
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#endif

namespace pn {
    enum ErrorType {
        PN_ERROR_NONE,
        PN_ERROR_INVALID_ADDRESS,
        PN_ERROR_USER_CALLBACK,
        PN_ERROR_SSL,
    };

    const std::error_category& polynet_category();
    const std::error_category& winsock_category();
    const std::error_category& address_info_category();
    const std::error_category& ssl_category();

    inline std::error_code polynet_error_code(ErrorType error) {
        return {error, polynet_category()};
    }

    inline std::error_code socket_error_code(int error) {
#ifdef _WIN32
        return {error, winsock_category()};
#else
        // POSIX errno values have portable std::errc equivalents
        return {error, std::generic_category()};
#endif
    }

    inline std::error_code last_socket_error_code() {
#ifdef _WIN32
        return socket_error_code(WSAGetLastError());
#else
        return socket_error_code(errno);
#endif
    }

    inline std::error_code address_info_error_code(int error) {
        return {error, address_info_category()};
    }

    inline std::error_code ssl_error_code(unsigned long error) {
        return {(int) error, ssl_category()};
    }

    struct Error {
        std::error_code code = polynet_error_code(PN_ERROR_NONE);
        StringView operation;

        constexpr operator bool() const {
            return code.value();
        }

        std::string message() const {
            return operation.empty() ? code.message() : std::string(operation) + ": " + code.message();
        }
    };

    template <typename T>
    using Result = std::expected<T, Error>;

    using Status = Result<void>;

    inline Error make_socket_error(int error, StringView operation = {}) {
        return {socket_error_code(error), operation};
    }

    inline Error make_last_socket_error(StringView operation = {}) {
        return {last_socket_error_code(), operation};
    }

    inline Error make_address_info_error(int error, StringView operation = {}) {
        return {address_info_error_code(error), operation};
    }

    inline Error make_invalid_address_error(StringView operation = {}) {
        return {polynet_error_code(PN_ERROR_INVALID_ADDRESS), operation};
    }

    inline Error make_user_callback_error(StringView operation = {}) {
        return {polynet_error_code(PN_ERROR_USER_CALLBACK), operation};
    }

    inline Error make_ssl_error(unsigned long error, StringView operation = {}) {
        return {error ? ssl_error_code(error) : polynet_error_code(PN_ERROR_SSL), operation};
    }
} // namespace pn

#endif
