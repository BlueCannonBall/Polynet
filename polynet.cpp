#include "polynet.hpp"
#include <cassert>
#include <cmath>
#include <cstring>
#include <stdexcept>
#include <type_traits>

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
            "inet_pton failed",                              // PN_EPTON
        };

        if (error >= 0 && error <= 4) {
            return error_strings[error];
        } else {
            return "Unknown error";
        }
    }

    std::string socket_strerror(int error) {
        char buf[1024];
#ifdef _WIN32
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            error,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            buf,
            1024,
            nullptr);

        for (size_t i = 0; i < 1024; ++i) {
            if (buf[i] == '\n') {
                if (buf[i + 1] == '\0') {
                    buf[i] = '\0';
                    break;
                } else {
                    buf[i] = ' ';
                }
            }
        }

        return buf;
#else
        auto result = strerror_r(error, buf, 1024);
        if (std::is_same<decltype(result), int>::value) {
            assert(result == PN_OK);
            return buf;
        } else if (std::is_same<decltype(result), char*>::value) {
            return result;
        } else {
            throw std::logic_error("Invalid result type");
        }
#endif
    }

    std::string universal_strerror(int error) {
        std::string base_error = strerror(error);
        std::string specific_error;

        switch (error) {
        case PN_ESOCKET:
            specific_error = socket_strerror();
            break;

        case PN_EAI:
            specific_error = gai_strerror();
            break;

        default:
            return base_error;
        }

        return base_error + ": " + specific_error;
    }

    ssize_t tcp::BufReceiver::recv(pn::tcp::Connection& conn, void* buf, size_t len, int flags) {
        if (len > this->buf.size()) {
            if (!this->buf.empty()) {
                memcpy(buf, this->buf.data(), this->buf.size());
            } else if (len > this->size || ((flags & MSG_WAITALL) && len > 1)) {
                return conn.recv(buf, len, flags);
            } else {
                ssize_t result;
                this->buf.resize(this->size);
                if ((result = conn.recv(this->buf.data(), this->size, flags & ~MSG_WAITALL)) == PN_ERROR) {
                    return PN_ERROR;
                }
                this->buf.resize(result);

                memcpy(buf, this->buf.data(), std::min<long long>(len, result));
                if (!(flags & MSG_PEEK)) this->buf.erase(this->buf.begin(), this->buf.begin() + std::min<long long>(len, result));
                return std::min<long long>(len, result);
            }

            if (flags & MSG_WAITALL) {
                ssize_t result;
                if ((result = conn.recv((char*) buf + this->buf.size(), len - this->buf.size(), flags)) == PN_ERROR) {
                    return PN_ERROR;
                }

                result += this->buf.size();
                if (!(flags & MSG_PEEK)) this->buf.clear();
                return result;
            } else {
                ssize_t ret = this->buf.size();
                if (!(flags & MSG_PEEK)) this->buf.clear();
                return ret;
            }
        } else if (len < this->buf.size()) {
            memcpy(buf, this->buf.data(), len);
            if (!(flags & MSG_PEEK)) this->buf.erase(this->buf.begin(), this->buf.begin() + len);
            return len;
        } else {
            memcpy(buf, this->buf.data(), this->buf.size());
            if (!(flags & MSG_PEEK)) this->buf.clear();
            return len;
        }
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
#ifdef _WIN32
                if (detail::get_last_system_error() != WSAECONNRESET) {
                    detail::set_last_socket_error(detail::get_last_system_error());
                    detail::set_last_error(PN_ESOCKET);
                    return PN_ERROR;
                } else {
                    continue;
                }
#else
                switch (detail::get_last_system_error()) {
                default:
                    detail::set_last_socket_error(detail::get_last_system_error());
                    detail::set_last_error(PN_ESOCKET);
                    return PN_ERROR;

                case EPERM:
                case EPROTO:
                case ECONNABORTED:
                    continue;
                }
#endif
            }

            if (!cb(conn, data)) { // Connections CANNOT be accepted while the callback is blocking
                break;
            }
        }

        return PN_OK;
    }
} // namespace pn
