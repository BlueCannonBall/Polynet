#include "polynet.hpp"
#include <algorithm>
#include <errno.h>
#include <string.h>
#ifndef _WIN32
    #include <sys/uio.h>
#endif

namespace pn {
#ifdef _WIN32
    WSADATA wsa_data;
#endif

    Status quit() {
#ifdef _WIN32
        if (WSACleanup() == PN_ERROR) {
            return std::unexpected(make_last_socket_error("clean up Winsock"));
        }
        return {};
#else
        if (signal(SIGPIPE, SIG_DFL) == SIG_ERR) {
            return std::unexpected(make_last_socket_error("restore SIGPIPE"));
        }
        return {};
#endif
    }

    namespace tcp {
        Result<size_t> Connection::send(const void* buf, size_t len) {
            for (;;) {
                ssize_t result;
                if ((result = ::send(fd, (const char*) buf, detail::clamp_transfer_len(len), 0)) == PN_ERROR) {
#ifndef _WIN32
                    std::error_code error = last_socket_error_code();
                    if (error.value() == EINTR) {
                        continue;
                    }
                    return std::unexpected(Error {error, "send"});
#else
                    return std::unexpected(make_last_socket_error("send"));
#endif
                }
                return result;
            }
        }

        Result<size_t> Connection::recv(void* buf, size_t len) {
            for (;;) {
                ssize_t result;
                if ((result = ::recv(fd, (char*) buf, detail::clamp_transfer_len(len), 0)) == PN_ERROR) {
#ifndef _WIN32
                    std::error_code error = last_socket_error_code();
                    if (error.value() == EINTR) {
                        continue;
                    }
                    return std::unexpected(Error {error, "receive"});
#else
                    return std::unexpected(make_last_socket_error("receive"));
#endif
                }
                return result;
            }
        }

        Result<size_t> Connection::peek(void* buf, size_t len) {
            for (;;) {
                ssize_t result;
                if ((result = ::recv(fd, (char*) buf, detail::clamp_transfer_len(len), MSG_PEEK)) == PN_ERROR) {
#ifndef _WIN32
                    std::error_code error = last_socket_error_code();
                    if (error.value() == EINTR) {
                        continue;
                    }
                    return std::unexpected(Error {error, "peek"});
#else
                    return std::unexpected(make_last_socket_error("peek"));
#endif
                }
                return result;
            }
        }

        Result<size_t> Connection::sendall(const void* buf, size_t len) {
            size_t sent = 0;
            while (sent < len) {
                if (Result<size_t> result = send((const char*) buf + sent, len - sent); !result) {
                    if (sent) {
                        break;
                    }
                    return std::unexpected(result.error());
                } else {
                    sent += *result;
                }
            }
            return sent;
        }

        Result<size_t> Connection::recvall(void* buf, size_t len) {
            size_t received = 0;
            while (received < len) {
                if (Result<size_t> result = recv((char*) buf + received, len - received); !result) {
                    if (received) {
                        break;
                    }
                    return std::unexpected(result.error());
                } else if (!*result) {
                    break;
                } else {
                    received += *result;
                }
            }
            return received;
        }

        Result<size_t> BufReceiver::recv(Connection& conn, void* buf, size_t len) {
            if (available()) {
                size_t received = std::min(len, available());
                memcpy(buf, data.data() + cursor, received);
                cursor += received;

                if (!available()) {
                    clear();
                }

                return received;
            }

            if (len >= capacity) {
                return conn.recv(buf, len);
            }

            data.resize(capacity);
            if (Result<size_t> result = conn.recv(data.data(), capacity); !result) {
                clear();
                return std::unexpected(result.error());
            } else if (!*result) {
                clear();
                return 0;
            } else {
                data.resize(*result);
                cursor = 0;

                size_t received = std::min<size_t>(len, *result);
                memcpy(buf, data.data(), received);
                cursor += received;

                if (!available()) {
                    clear();
                }

                return received;
            }
        }

        Result<size_t> BufReceiver::peek(Connection& conn, void* buf, size_t len) {
            if (available()) {
                size_t to_copy = std::min(len, available());
                memcpy(buf, data.data() + cursor, to_copy);
                return to_copy;
            }

            if (len >= capacity) {
                return conn.peek(buf, len);
            }

            data.resize(capacity);
            if (Result<size_t> result = conn.recv(data.data(), capacity); !result) {
                clear();
                return std::unexpected(result.error());
            } else if (!*result) {
                clear();
                return 0;
            } else {
                data.resize(*result);
                cursor = 0;

                size_t received = std::min<size_t>(len, *result);
                memcpy(buf, data.data(), received);
                return received;
            }
        }

        Result<size_t> BufReceiver::recvall(Connection& conn, void* buf, size_t len) {
            size_t received = 0;
            while (received < len) {
                if (Result<size_t> result = recv(conn, (char*) buf + received, len - received); !result) {
                    if (received) {
                        break;
                    }
                    return std::unexpected(result.error());
                } else if (!*result) {
                    break;
                } else {
                    received += *result;
                }
            }
            return received;
        }

        void BufReceiver::rewind(const void* buf, size_t size) {
            if (size) {
                if (cursor >= size) {
                    cursor -= size;
                    memcpy(data.data() + cursor, buf, size);
                } else {
                    std::vector<char> new_data;
                    new_data.reserve(size + available() + capacity);
                    new_data.insert(new_data.end(), (const char*) buf, (const char*) buf + size);
                    new_data.insert(new_data.end(), data.begin() + cursor, data.end());

                    data = std::move(new_data);
                    cursor = 0;
                }
            }
        }

        Result<sockfd_t> Server::accept(struct sockaddr* addr, socklen_t* addrlen) {
            for (;;) {
                sockfd_t conn_fd;
                if ((conn_fd = ::accept(fd, addr, addrlen)) != PN_INVALID_SOCKFD) {
                    return conn_fd;
                }

                std::error_code error = last_socket_error_code();
#ifdef _WIN32
                if (error.value() != WSAECONNRESET) {
                    return std::unexpected(Error {error, "accept"});
                }
#else
                switch (error.value()) {
                default:
                    return std::unexpected(Error {error, "accept"});

                case EINTR:
                case EPERM:
                case EPROTO:
                case ECONNABORTED:
                    break;
                }
#endif
            }
        }

        Status Server::listen(const std::function<bool(connection_type)>& cb, int backlog) { // This function BLOCKS
            if (::listen(fd, backlog) == PN_ERROR) {
                return std::unexpected(make_last_socket_error("listen"));
            }

            for (;;) {
                connection_type conn;
                if (Result<sockfd_t> result = accept((struct sockaddr*) &conn.addr, &conn.addrlen); !result) {
                    return std::unexpected(result.error());
                } else {
                    conn.fd = *result;
                }

                if (!cb(std::move(conn))) { // Connections CANNOT be accepted while the callback is blocking
                    break;
                }
            }

            return {};
        }
    } // namespace tcp

    namespace udp {
        Result<size_t> Socket::recvfrom(void* buf, size_t len, struct sockaddr* src_addr, socklen_t* addrlen, int flags, StringView operation) {
            for (;;) {
                ssize_t result;
#ifdef _WIN32
                if ((result = ::recvfrom(fd, (char*) buf, detail::clamp_transfer_len(len), flags, src_addr, addrlen)) == PN_ERROR) {
                    return std::unexpected(make_last_socket_error(operation));
                }
#else
                struct iovec iov;
                iov.iov_base = buf;
                iov.iov_len = detail::clamp_transfer_len(len);

                struct msghdr msg = {};
                msg.msg_name = src_addr;
                msg.msg_namelen = addrlen ? *addrlen : 0;
                msg.msg_iov = &iov;
                msg.msg_iovlen = 1;

                if ((result = ::recvmsg(fd, &msg, flags)) == PN_ERROR) {
                    std::error_code error = last_socket_error_code();
                    if (error.value() == EINTR) {
                        continue;
                    }
                    return std::unexpected(Error {error, operation});
                }
                if (addrlen) {
                    *addrlen = msg.msg_namelen;
                }
                if (msg.msg_flags & MSG_TRUNC) {
                    return std::unexpected(Error {std::make_error_code(std::errc::message_size), operation});
                }
#endif
                return result;
            }
        }

        Result<size_t> Socket::send(const void* buf, size_t len) {
            if (len > detail::max_transfer_len) { // Clamping would silently truncate the datagram
                return std::unexpected(Error {std::make_error_code(std::errc::message_size), "send datagram"});
            }

            for (;;) {
                ssize_t result;
                if ((result = ::send(fd, (const char*) buf, len, 0)) == PN_ERROR) {
#ifndef _WIN32
                    std::error_code error = last_socket_error_code();
                    if (error.value() == EINTR) {
                        continue;
                    }
                    return std::unexpected(Error {error, "send datagram"});
#else
                    return std::unexpected(make_last_socket_error("send datagram"));
#endif
                }
                return result;
            }
        }

        Result<size_t> Socket::sendto(const void* buf, size_t len, const struct sockaddr* dest_addr, socklen_t addrlen) {
            if (len > detail::max_transfer_len) { // Clamping would silently truncate the datagram
                return std::unexpected(Error {std::make_error_code(std::errc::message_size), "send datagram"});
            }

            for (;;) {
                ssize_t result;
                if ((result = ::sendto(fd, (const char*) buf, len, 0, dest_addr, addrlen)) == PN_ERROR) {
#ifndef _WIN32
                    std::error_code error = last_socket_error_code();
                    if (error.value() == EINTR) {
                        continue;
                    }
                    return std::unexpected(Error {error, "send datagram"});
#else
                    return std::unexpected(make_last_socket_error("send datagram"));
#endif
                }
                return result;
            }
        }
    } // namespace udp
} // namespace pn
