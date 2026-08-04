#include "error.hpp"
#include <string>
#ifndef _WIN32
    #include <netdb.h>
#else
    #include <windows.h>
#endif

namespace pn {
    namespace detail {
        class PolynetCategory : public std::error_category {
        public:
            const char* name() const noexcept override {
                return "polynet";
            }

            std::string message(int error) const override {
                switch (error) {
                case PN_ERROR_NONE: return "Success";
                case PN_ERROR_INVALID_ADDRESS: return "Invalid address";
                case PN_ERROR_USER_CALLBACK: return "User callback failed";
                case PN_ERROR_TLS: return "TLS error";
                case PN_ERROR_ALREADY_INITIALIZED: return "Already initialized";
                default: return "Unknown Polynet error " + std::to_string(error);
                }
            }
        };

        class WinsockCategory : public std::error_category {
        public:
            const char* name() const noexcept override {
                return "winsock";
            }

            std::string message(int error) const override {
#ifdef _WIN32
                char buf[1024];

                DWORD size = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                    nullptr,
                    error,
                    0,
                    buf,
                    sizeof buf,
                    nullptr);
                if (!size) {
                    return "Unknown Winsock error " + std::to_string(error);
                }

                while (size && (buf[size - 1] == '\r' || buf[size - 1] == '\n')) {
                    --size;
                }

                return std::string(buf, size);
#else
                return "Winsock error " + std::to_string(error);
#endif
            }

            std::error_condition default_error_condition(int error) const noexcept override {
#ifdef _WIN32
                switch (error) {
                case WSAEINTR: return std::make_error_condition(std::errc::interrupted);
                case WSAEBADF: return std::make_error_condition(std::errc::bad_file_descriptor);
                case WSAEACCES: return std::make_error_condition(std::errc::permission_denied);
                case WSAEFAULT: return std::make_error_condition(std::errc::bad_address);
                case WSAEINVAL: return std::make_error_condition(std::errc::invalid_argument);
                case WSAEMFILE: return std::make_error_condition(std::errc::too_many_files_open);
                case WSAEWOULDBLOCK: return std::make_error_condition(std::errc::operation_would_block);
                case WSAEINPROGRESS: return std::make_error_condition(std::errc::operation_in_progress);
                case WSAEALREADY: return std::make_error_condition(std::errc::connection_already_in_progress);
                case WSAENOTSOCK: return std::make_error_condition(std::errc::not_a_socket);
                case WSAEDESTADDRREQ: return std::make_error_condition(std::errc::destination_address_required);
                case WSAEMSGSIZE: return std::make_error_condition(std::errc::message_size);
                case WSAEPROTOTYPE: return std::make_error_condition(std::errc::wrong_protocol_type);
                case WSAENOPROTOOPT: return std::make_error_condition(std::errc::no_protocol_option);
                case WSAEPROTONOSUPPORT: return std::make_error_condition(std::errc::protocol_not_supported);
                case WSAEOPNOTSUPP: return std::make_error_condition(std::errc::operation_not_supported);
                case WSAEAFNOSUPPORT: return std::make_error_condition(std::errc::address_family_not_supported);
                case WSAEADDRINUSE: return std::make_error_condition(std::errc::address_in_use);
                case WSAEADDRNOTAVAIL: return std::make_error_condition(std::errc::address_not_available);
                case WSAENETDOWN: return std::make_error_condition(std::errc::network_down);
                case WSAENETUNREACH: return std::make_error_condition(std::errc::network_unreachable);
                case WSAENETRESET: return std::make_error_condition(std::errc::network_reset);
                case WSAECONNABORTED: return std::make_error_condition(std::errc::connection_aborted);
                case WSAECONNRESET: return std::make_error_condition(std::errc::connection_reset);
                case WSAENOBUFS: return std::make_error_condition(std::errc::no_buffer_space);
                case WSAEISCONN: return std::make_error_condition(std::errc::already_connected);
                case WSAENOTCONN: return std::make_error_condition(std::errc::not_connected);
                case WSAETIMEDOUT: return std::make_error_condition(std::errc::timed_out);
                case WSAECONNREFUSED: return std::make_error_condition(std::errc::connection_refused);
                case WSAELOOP: return std::make_error_condition(std::errc::too_many_symbolic_link_levels);
                case WSAENAMETOOLONG: return std::make_error_condition(std::errc::filename_too_long);
                case WSAEHOSTUNREACH: return std::make_error_condition(std::errc::host_unreachable);
                case WSAENOTEMPTY: return std::make_error_condition(std::errc::directory_not_empty);
                case WSAECANCELLED:
                case WSA_E_CANCELLED: return std::make_error_condition(std::errc::operation_canceled);
                }
#endif
                return std::error_condition(error, *this);
            }
        };

        class AddressInfoCategory : public std::error_category {
        public:
            const char* name() const noexcept override {
                return "getaddrinfo";
            }

            std::string message(int error) const override {
                return gai_strerror(error);
            }
        };

    } // namespace detail

    const std::error_category& polynet_category() noexcept {
        static const detail::PolynetCategory category;
        return category;
    }

    const std::error_category& winsock_category() noexcept {
        static const detail::WinsockCategory category;
        return category;
    }

    const std::error_category& address_info_category() noexcept {
        static const detail::AddressInfoCategory category;
        return category;
    }
} // namespace pn
