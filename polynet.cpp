#include "polynet.hpp"
#include <algorithm>
#include <string.h>

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
        Result<size_t> Connection::sendall(const void* buf, size_t len) {
            size_t sent = 0;
            while (sent < len) {
                Result<size_t> result = send((const char*) buf + sent, len - sent);
                if (!result) {
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
                Result<size_t> result = recv((char*) buf + received, len - received);
                if (!result) {
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
            Result<size_t> result = conn.recv(data.data(), capacity);
            if (!result) {
                clear();
                return std::unexpected(result.error());
            } else if (!*result) {
                clear();
                return 0;
            }
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
            Result<size_t> result = conn.recv(data.data(), capacity);
            if (!result) {
                clear();
                return std::unexpected(result.error());
            } else if (!*result) {
                clear();
                return 0;
            }
            data.resize(*result);
            cursor = 0;

            size_t received = std::min<size_t>(len, *result);
            memcpy(buf, data.data(), received);
            return received;
        }

        Result<size_t> BufReceiver::recvall(Connection& conn, void* buf, size_t len) {
            size_t received = 0;
            while (received < len) {
                Result<size_t> result = recv(conn, (char*) buf + received, len - received);
                if (!result) {
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

        Status Server::listen(const std::function<bool(connection_type)>& cb, int backlog) {
            if (::listen(fd, backlog) == PN_ERROR) {
                return std::unexpected(make_last_socket_error("listen"));
            }

            for (;;) {
                connection_type conn;
                if ((conn.fd = accept(fd, &conn.addr, &conn.addrlen)) == PN_INVALID_SOCKFD) {
                    std::error_code error = last_socket_error_code();
#ifdef _WIN32
                    if (error.value() != WSAECONNRESET) {
                        return std::unexpected(Error {error, "accept"});
                    }
                    continue;
#else
                    switch (error.value()) {
                    default:
                        return std::unexpected(Error {error, "accept"});

                    case EINTR:
                    case EPERM:
                    case EPROTO:
                    case ECONNABORTED:
                        continue;
                    }
#endif
                }

                if (!cb(std::move(conn))) { // Connections CANNOT be accepted while the callback is blocking
                    break;
                }
            }

            return {};
        }
    } // namespace tcp
} // namespace pn
