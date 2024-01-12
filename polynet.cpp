#include "polynet.hpp"
#include <algorithm>
#include <cassert>
#include <cstring>
#ifdef POLYNET_SECURE_SOCKETS
    #include "secure_sockets.hpp"
#endif

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
            "OpenSSL error",                                 // PN_ESECURITY
        };

        if (error >= 0 && error <= 5) {
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

#ifdef POLYNET_SECURE_SOCKETS
        case PN_ESECURITY:
            specific_error = security_strerror();
            break;
#endif

        default:
            return base_error;
        }

        return base_error + ": " + specific_error;
    }

    namespace tcp {
        long Connection::sendall(const void* buf, size_t len) {
            size_t sent = 0;
            while (sent < len) {
                long result;
                if ((result = this->send((const char*) buf + sent, len - sent)) == PN_ERROR) {
#ifndef _WIN32
                    if (get_last_error() == PN_ESOCKET && get_last_socket_error() == EINTR) {
                        continue;
                    }
#endif

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

        long Connection::recvall(void* buf, size_t len) {
#if defined(_WIN32) && _WIN32_WINNT >= _WIN32_WINNT_VISTA
            long result;
            if ((result = ::recv(this->fd, (char*) buf, size, MSG_WAITALL)) == PN_ERROR) {
                detail::set_last_socket_error(detail::get_last_system_error());
                detail::set_last_error(PN_ESOCKET);
            }
            return result;
#else
            size_t received = 0;
            while (received < len) {
                long result;
                if ((result = this->recv((char*) buf + received, len - received)) == PN_ERROR) {
    #ifndef _WIN32
                    if (get_last_error() == PN_ESOCKET && get_last_socket_error() == EINTR) {
                        continue;
                    }
    #endif

                    if (received) {
                        break;
                    } else {
                        return PN_ERROR;
                    }
                } else if (result == 0) {
                    break;
                }
                received += result;
            }
            return received;
#endif
        }

        long BufReceiver::recv(Connection& conn, void* buf, size_t len) {
            if (!this->size) {
                return conn.recvall(buf, len);
            }

            if (len > this->buf.size()) {
                if (!this->buf.empty()) {
                    memcpy(buf, this->buf.data(), this->buf.size());
                    this->buf.clear();
                    return this->buf.size();
                } else if (len > this->size) {
                    return conn.recv(buf, len);
                } else {
                    long result;
                    this->buf.resize(this->size);
                    if ((result = conn.recv(this->buf.data(), this->size)) == PN_ERROR) {
                        return PN_ERROR;
                    }
                    this->buf.resize(result);

                    memcpy(buf, this->buf.data(), std::min<long long>(len, result));
                    this->buf.erase(this->buf.begin(), this->buf.begin() + std::min<long long>(len, result));
                    return std::min<long long>(len, result);
                }
            } else if (len < this->buf.size()) {
                memcpy(buf, this->buf.data(), len);
                this->buf.erase(this->buf.begin(), this->buf.begin() + len);
                return len;
            } else {
                memcpy(buf, this->buf.data(), this->buf.size());
                this->buf.clear();
                return len;
            }
        }

        long BufReceiver::peek(Connection& conn, void* buf, size_t len) {
            if (!this->size) {
                return conn.peek(buf, len);
            }

            if (len > this->buf.size()) {
                if (!this->buf.empty()) {
                    memcpy(buf, this->buf.data(), this->buf.size());
                    return this->buf.size();
                } else if (len > this->size) {
                    return conn.peek(buf, len);
                } else {
                    long result;
                    this->buf.resize(this->size);
                    if ((result = conn.peek(this->buf.data(), this->size)) == PN_ERROR) {
                        return PN_ERROR;
                    }
                    this->buf.resize(result);

                    memcpy(buf, this->buf.data(), std::min<long long>(len, result));
                    return std::min<long long>(len, result);
                }
            } else if (len < this->buf.size()) {
                memcpy(buf, this->buf.data(), len);
                return len;
            } else {
                memcpy(buf, this->buf.data(), this->buf.size());
                return len;
            }
        }

        long BufReceiver::recvall(Connection& conn, void* buf, size_t len) {
            if (!this->size) {
                return conn.recvall(buf, len);
            }

            if (len > this->buf.size()) {
                if (!this->buf.empty()) {
                    memcpy(buf, this->buf.data(), this->buf.size());
                } else if (len > 1) {
                    return conn.recvall(buf, len);
                } else {
                    long result;
                    this->buf.resize(this->size);
                    if ((result = conn.recv(this->buf.data(), this->size)) == PN_ERROR) {
                        return PN_ERROR;
                    }
                    this->buf.resize(result);

                    memcpy(buf, this->buf.data(), std::min<long long>(len, result));
                    this->buf.erase(this->buf.begin(), this->buf.begin() + std::min<long long>(len, result));
                    return std::min<long long>(len, result);
                }

                long result;
                if ((result = conn.recvall((char*) buf + this->buf.size(), len - this->buf.size())) == PN_ERROR) {
                    return PN_ERROR;
                }

                result += this->buf.size();
                this->buf.clear();
                return result;
            } else if (len < this->buf.size()) {
                memcpy(buf, this->buf.data(), len);
                this->buf.erase(this->buf.begin(), this->buf.begin() + len);
                return len;
            } else {
                memcpy(buf, this->buf.data(), this->buf.size());
                this->buf.clear();
                return len;
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
