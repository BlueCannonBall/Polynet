#include "polynet.hpp"

namespace pn {
    namespace detail {
        thread_local int last_error = PN_OK;
        thread_local int last_gai_error = PN_OK;
        thread_local int last_socket_error = PN_OK;
    } // namespace detail

#ifdef _WIN32
    WSADATA wsa_data;
#endif

    std::string strerror(int error) {
        const static std::string error_strings[] = {
            "Success",                                       // PN_ESUCCESS
            "Socket error",                                  // PN_ESOCKET
            "getaddrinfo failed",                            // PN_EAI
            "All addresses returned by getaddrinfo are bad", // PN_EBADADDRS
        };

        if (error >= 0 && error < 4) {
            return error_strings[error];
        } else {
            return "Unknown error";
        }
    }

    std::string socket_strerror(int error) {
#ifdef _WIN32
        char error_string[512];

        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            error,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            error_string,
            sizeof(error_string),
            NULL);

        for (size_t i = 0; i < sizeof(error_string); i++) {
            if (error_string[i] == '\n') {
                if (error_string[i + 1] == '\0') {
                    error_string[i] = '\0';
                    break;
                } else {
                    error_string[i] = ' ';
                }
            }
        }

        return error_string;
#else
        return ::strerror(error);
#endif
    }

    std::string universal_strerror(int error) {
        std::string base_error = strerror(error);
        std::string specific_error;

        switch (error) {
            case PN_ESOCKET: {
                specific_error = socket_strerror();
                break;
            }

            case PN_EAI: {
                specific_error = gai_strerror();
                break;
            }

            default: {
                return base_error;
            }
        }

        return base_error + ": " + specific_error;
    }

    int tcp::Server::listen(const std::function<bool(Connection&, void*)>& cb, int backlog, void* data) { // This function BLOCKS
        if (this->backlog != backlog || this->backlog == -1) {
            if (::listen(this->fd, backlog) == PN_ERROR) {
                detail::set_last_socket_error(detail::get_last_system_error());
                detail::set_last_error(PN_ESOCKET);
                return PN_ERROR;
            }
            this->backlog = backlog;
        }

        for (;;) {
            Connection conn;
            if ((conn.fd = accept(this->fd, &conn.addr, &conn.addrlen)) == PN_INVALID_SOCKFD) {
                detail::set_last_socket_error(detail::get_last_system_error());
                detail::set_last_error(PN_ESOCKET);
                return PN_ERROR;
            }

            if (!cb(conn, data)) { // Connections CANNOT be accepted while the callback is blocking
                break;
            }
        }

        return PN_OK;
    }
} // namespace pn
