#include "polynet.hpp"
#include "secure_sockets.hpp"
#include <algorithm>
#include <string.h>
#ifndef _GNU_SOURCE
    #include <assert.h>
#endif

namespace pn {
    namespace detail {
        thread_local int last_error = PN_ESUCCESS;
        thread_local int last_gai_error = PN_ESUCCESS;
        thread_local int last_socket_error = PN_ESUCCESS;
    } // namespace detail

#ifdef _WIN32
    WSADATA wsa_data;
#endif

    int quit() {
#ifdef _WIN32
        if (WSACleanup() == PN_ERROR) {
            detail::set_last_socket_error(detail::get_last_system_error());
            detail::set_last_error(PN_ESOCKET);
            return PN_ERROR;
        }
        return PN_OK;
#else
        if (signal(SIGPIPE, SIG_DFL) == SIG_ERR) {
            detail::set_last_socket_error(detail::get_last_system_error());
            detail::set_last_error(PN_ESOCKET);
            return PN_ERROR;
        }
        return PN_OK;
#endif
    }

    std::string strerror(int error) {
        const static std::string error_strings[] = {
            "Success",                                       // PN_ESUCCESS
            "Socket error",                                  // PN_ESOCKET
            "getaddrinfo failed",                            // PN_EAI
            "All addresses returned by getaddrinfo are bad", // PN_EBADADDRS
            "inet_pton failed",                              // PN_EPTON
            "SSL error",                                     // PN_ESSL
            "User callback failed",                          // PN_EUSERCB
        };

        if (error >= 0 && error <= 6) {
            return error_strings[error];
        }
        return "Unknown error";
    }

    std::string socket_strerror(int error) {
        char buf[1024];
#ifdef _WIN32
        DWORD result = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            error,
            0,
            buf,
            1024,
            nullptr);
        assert(result);

        for (DWORD i = 0; i < result - 1; ++i) {
            if (buf[i] == '\n') {
                buf[i] = ' ';
            }
        }
        if (buf[result - 1] == '\n') {
            buf[--result] = '\0';
        }

        return std::string(buf, buf + result);
#elif defined(_GNU_SOURCE)
        return strerror_r(error, buf, 1024);
#else
        assert(strerror_r(error, buf, 1024) == PN_OK);
        return buf;
#endif
    }

    std::string universal_strerror() {
        std::string base_error = strerror(get_last_error());
        std::string specific_error;

        switch (get_last_error()) {
        case PN_ESOCKET:
            specific_error = socket_strerror();
            break;

        case PN_EAI:
            specific_error = gai_strerror();
            break;

        case PN_ESSL:
            specific_error = ssl_strerror();
            break;

        default:
            return base_error;
        }

        return base_error + ": " + specific_error;
    }

    namespace tcp {
        long Connection::sendall(const void* buf, size_t len) {
            size_t sent = 0;
            while (sent < len) {
                if (long result = send((const char*) buf + sent, len - sent); result == PN_ERROR) {
                    if (sent) {
                        break;
                    }
                    return PN_ERROR;
                } else {
                    sent += result;
                }
            }
            return sent;
        }

        long Connection::recvall(void* buf, size_t len) {
            size_t received = 0;
            while (received < len) {
                if (long result = recv((char*) buf + received, len - received); result == PN_ERROR) {
                    if (received) {
                        break;
                    }
                    return PN_ERROR;
                } else if (!result) {
                    break;
                } else {
                    received += result;
                }
            }
            return received;
        }

        long BufReceiver::recv(Connection& conn, void* buf, size_t len) {
            if (!size) {
                return conn.recvall(buf, len);
            }

            if (len > this->buf.size()) {
                if (!this->buf.empty()) {
                    memcpy(buf, this->buf.data(), this->buf.size());
                    this->buf.clear();
                    return this->buf.size();
                } else if (len > size) {
                    return conn.recv(buf, len);
                } else {
                    long result;
                    this->buf.resize(size);
                    if ((result = conn.recv(this->buf.data(), size)) == PN_ERROR) {
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
            if (!size) {
                return conn.peek(buf, len);
            }

            if (len > this->buf.size()) {
                if (!this->buf.empty()) {
                    memcpy(buf, this->buf.data(), this->buf.size());
                    return this->buf.size();
                } else if (len > size) {
                    return conn.peek(buf, len);
                } else {
                    long result;
                    this->buf.resize(size);
                    if ((result = conn.peek(this->buf.data(), size)) == PN_ERROR) {
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
            if (!size) {
                return conn.recvall(buf, len);
            }

            if (len > this->buf.size()) {
                if (!this->buf.empty()) {
                    memcpy(buf, this->buf.data(), this->buf.size());
                } else if (len > 1) {
                    return conn.recvall(buf, len);
                } else {
                    long result;
                    this->buf.resize(size);
                    if ((result = conn.recv(this->buf.data(), size)) == PN_ERROR) {
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

        int Server::listen(const std::function<bool(connection_type&, void*)>& cb, int backlog, void* data) { // This function BLOCKS
            if (this->backlog != backlog || this->backlog == -1) {
                if (::listen(this->fd, backlog) == PN_ERROR) {
                    detail::set_last_socket_error(detail::get_last_system_error());
                    detail::set_last_error(PN_ESOCKET);
                    return PN_ERROR;
                }
                this->backlog = backlog;
            }

            for (;;) {
                connection_type conn;
                if ((conn.fd = accept(fd, &conn.addr, &conn.addrlen)) == PN_INVALID_SOCKFD) {
#ifdef _WIN32
                    if (detail::get_last_system_error() != WSAECONNRESET) {
                        detail::set_last_socket_error(detail::get_last_system_error());
                        detail::set_last_error(PN_ESOCKET);
                        return PN_ERROR;
                    }
                    continue;
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
