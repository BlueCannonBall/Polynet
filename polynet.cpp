#include "polynet.hpp"
#include <algorithm>
#include <cassert>
#include <cstring>

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
#if defined(_WIN32)
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
#elif defined(_GNU_SOURCE)
        return strerror_r(error, buf, 1024);
#else
        assert(strerror_r(error, buf, 1024) == PN_OK);
        return buf;
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

    namespace tcp {
        ssize_t Connection::sendall(const void* buf, size_t size) {
            size_t sent = 0;
            while (sent < size) {
                ssize_t result;
                if ((result = ::send(this->fd, ((const char*) buf) + sent, size - sent, 0)) == PN_ERROR) {
                    int system_error = detail::get_last_system_error();
#ifndef _WIN32
                    if (system_error == EINTR) continue;
#endif
                    detail::set_last_socket_error(system_error);
                    detail::set_last_error(PN_ESOCKET);

                    if (sent) {
                        break;
                    } else {
                        return PN_ERROR;
                    }
                }
                sent += result;
            }
            return sent;
        }

        ssize_t Connection::recvall(void* buf, size_t size) {
#if defined(_WIN32) && _WIN32_WINNT >= _WIN32_WINNT_VISTA
            ssize_t result;
            if ((result = ::recv(this->fd, (char*) buf, size, MSG_WAITALL)) == PN_ERROR) {
                detail::set_last_socket_error(detail::get_last_system_error());
                detail::set_last_error(PN_ESOCKET);
            }
            return result;
#else
            size_t received = 0;
            while (received < size) {
                ssize_t result;
                if ((result = ::recv(this->fd, ((char*) buf) + received, size - received, 0)) == PN_ERROR) {
                    int system_error = detail::get_last_system_error();
    #ifndef _WIN32
                    if (system_error == EINTR) continue;
    #endif
                    detail::set_last_socket_error(system_error);
                    detail::set_last_error(PN_ESOCKET);

                    if (received) {
                        break;
                    } else {
                        return PN_ERROR;
                    }
                }
                received += result;
            }
            return received;
#endif
        }

        ssize_t BufReceiver::recv(pn::tcp::Connection& conn, void* buf, size_t size) {
            if (!this->size) {
                return conn.recvall(buf, size);
            }

            if (size > this->buf.size()) {
                if (!this->buf.empty()) {
                    memcpy(buf, this->buf.data(), this->buf.size());
                    this->buf.clear();
                    return this->buf.size();
                } else if (size > this->size) {
                    return conn.recv(buf, size);
                } else {
                    ssize_t result;
                    this->buf.resize(this->size);
                    if ((result = conn.recv(this->buf.data(), this->size)) == PN_ERROR) {
                        return PN_ERROR;
                    }
                    this->buf.resize(result);

                    memcpy(buf, this->buf.data(), std::min<long long>(size, result));
                    this->buf.erase(this->buf.begin(), this->buf.begin() + std::min<long long>(size, result));
                    return std::min<long long>(size, result);
                }
            } else if (size < this->buf.size()) {
                memcpy(buf, this->buf.data(), size);
                this->buf.erase(this->buf.begin(), this->buf.begin() + size);
                return size;
            } else {
                memcpy(buf, this->buf.data(), this->buf.size());
                this->buf.clear();
                return size;
            }
        }

        ssize_t BufReceiver::peek(pn::tcp::Connection& conn, void* buf, size_t size) {
            if (!this->size) {
                return conn.peek(buf, size);
            }

            if (size > this->buf.size()) {
                if (!this->buf.empty()) {
                    memcpy(buf, this->buf.data(), this->buf.size());
                    return this->buf.size();
                } else if (size > this->size) {
                    return conn.peek(buf, size);
                } else {
                    ssize_t result;
                    this->buf.resize(this->size);
                    if ((result = conn.peek(this->buf.data(), this->size)) == PN_ERROR) {
                        return PN_ERROR;
                    }
                    this->buf.resize(result);

                    memcpy(buf, this->buf.data(), std::min<long long>(size, result));
                    return std::min<long long>(size, result);
                }
            } else if (size < this->buf.size()) {
                memcpy(buf, this->buf.data(), size);
                return size;
            } else {
                memcpy(buf, this->buf.data(), this->buf.size());
                return size;
            }
        }

        ssize_t BufReceiver::recvall(pn::tcp::Connection& conn, void* buf, size_t size) {
            if (!this->size) {
                return conn.recvall(buf, size);
            }

            if (size > this->buf.size()) {
                if (!this->buf.empty()) {
                    memcpy(buf, this->buf.data(), this->buf.size());
                } else if (size > 1) {
                    return conn.recvall(buf, size);
                } else {
                    ssize_t result;
                    this->buf.resize(this->size);
                    if ((result = conn.recv(this->buf.data(), this->size)) == PN_ERROR) {
                        return PN_ERROR;
                    }
                    this->buf.resize(result);

                    memcpy(buf, this->buf.data(), std::min<long long>(size, result));
                    this->buf.erase(this->buf.begin(), this->buf.begin() + std::min<long long>(size, result));
                    return std::min<long long>(size, result);
                }

                ssize_t result;
                if ((result = conn.recvall((char*) buf + this->buf.size(), size - this->buf.size())) == PN_ERROR) {
                    return PN_ERROR;
                }

                result += this->buf.size();
                this->buf.clear();
                return result;
            } else if (size < this->buf.size()) {
                memcpy(buf, this->buf.data(), size);
                this->buf.erase(this->buf.begin(), this->buf.begin() + size);
                return size;
            } else {
                memcpy(buf, this->buf.data(), this->buf.size());
                this->buf.clear();
                return size;
            }
        }

        int Server::listen(const std::function<bool(Connection&, void*)>& cb, int backlog, void* data) { // This function BLOCKS
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
    } // namespace tcp
} // namespace pn
