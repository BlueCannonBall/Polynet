#include "secure_sockets.hpp"

namespace pn {
    namespace detail {
        thread_local unsigned long last_ssl_error;
    }

    namespace tcp {
        long SecureConnection::sendall(const void* buf, size_t len) {
            if (ssl) {
                size_t sent = 0;
                while (sent < len) {
                    long result;
                    if ((result = send((const char*) buf + sent, len - sent)) == PN_ERROR) {
                        if (sent) {
                            break;
                        } else {
                            return PN_ERROR;
                        }
                    }
                    sent += result;
                }
                return sent;
            } else {
                return Connection::sendall(buf, len);
            }
        }

        long SecureConnection::recvall(void* buf, size_t len) {
            if (ssl) {
                size_t received = 0;
                while (received < len) {
                    long result;
                    if ((result = recv((char*) buf + received, len - received)) == PN_ERROR) {
                        if (received) {
                            break;
                        } else {
                            return PN_ERROR;
                        }
                    } else if (!result) {
                        break;
                    }
                    received += result;
                }
                return received;
            } else {
                return Connection::recvall(buf, len);
            }
        }

        int SecureServer::ssl_init(StringView certificate_chain_file, StringView private_key_file, int private_key_file_type) {
            if (!(ssl_ctx = SSL_CTX_new(TLS_server_method()))) {
                detail::set_last_ssl_error(detail::get_last_ssl_error());
                detail::set_last_error(PN_ESSL);
                return PN_ERROR;
            }

            if (SSL_CTX_use_certificate_chain_file(ssl_ctx, certificate_chain_file.c_str()) != 1) {
                detail::set_last_ssl_error(detail::get_last_ssl_error());
                detail::set_last_error(PN_ESSL);
                return PN_ERROR;
            }
            if (SSL_CTX_use_PrivateKey_file(ssl_ctx, private_key_file.c_str(), private_key_file_type) != 1) {
                detail::set_last_ssl_error(detail::get_last_ssl_error());
                detail::set_last_error(PN_ESSL);
                return PN_ERROR;
            }

            return PN_OK;
        }

        int SecureServer::listen(const std::function<bool(connection_type&, void*)>& cb, int backlog, void* data) { // This function BLOCKS
            if (this->backlog != backlog || this->backlog == -1) {
                if (::listen(fd, backlog) == PN_ERROR) {
                    detail::set_last_ssl_error(detail::get_last_system_error());
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

                if (ssl_ctx && conn.ssl_init(ssl_ctx) == PN_ERROR) {
                    return PN_ERROR;
                }

                if (!cb(conn, data)) { // Connections CANNOT be accepted while the callback is blocking
                    break;
                }
            }

            return PN_OK;
        }

        int SecureClient::ssl_init(StringView hostname, int verify_mode, StringView ca_file, StringView ca_path) {
            if (!(ssl_ctx = SSL_CTX_new(TLS_client_method()))) {
                detail::set_last_ssl_error(detail::get_last_ssl_error());
                detail::set_last_error(PN_ESSL);
                return PN_ERROR;
            }

            SSL_CTX_set_verify(ssl_ctx, verify_mode, nullptr);
            if (ca_file.empty() && ca_path.empty()) {
#ifdef _WIN32
                if (!SSL_CTX_load_verify_store(ssl_ctx, "org.openssl.winstore://")) {
#else
                if (!SSL_CTX_set_default_verify_paths(ssl_ctx)) {
#endif
                    detail::set_last_ssl_error(detail::get_last_ssl_error());
                    detail::set_last_error(PN_ESSL);
                    return PN_ERROR;
                }
            } else if (!SSL_CTX_load_verify_locations(ssl_ctx, ca_file.empty() ? nullptr : ca_file.c_str(), ca_path.empty() ? nullptr : ca_path.c_str())) {
                detail::set_last_ssl_error(detail::get_last_ssl_error());
                detail::set_last_error(PN_ESSL);
                return PN_ERROR;
            }

            if (BasicClient<SecureConnection, SOCK_STREAM, IPPROTO_TCP>::ssl_init(ssl_ctx) == PN_ERROR) {
                return PN_ERROR;
            }

            if (!SSL_set_tlsext_host_name(ssl, hostname.c_str())) {
                detail::set_last_ssl_error(detail::get_last_ssl_error());
                detail::set_last_error(PN_ESSL);
                return PN_ERROR;
            }
            if (!SSL_set1_host(ssl, hostname.c_str())) {
                detail::set_last_ssl_error(detail::get_last_ssl_error());
                detail::set_last_error(PN_ESSL);
                return PN_ERROR;
            }

            return PN_OK;
        }
    } // namespace tcp
} // namespace pn
