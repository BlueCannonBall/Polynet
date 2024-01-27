#include "secure_sockets.hpp"
#include "polynet.hpp"
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sys/socket.h>

namespace pn {
    namespace detail {
        thread_local unsigned long last_ssl_error;
    }

    namespace tcp {
        long SecureConnection::sendall(const void* buf, size_t len) {
            if (this->ssl) {
                size_t sent = 0;
                while (sent < len) {
                    long result;
                    if ((result = this->send((const char*) buf + sent, len - sent)) == PN_ERROR) {
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
            if (this->ssl) {
                size_t received = 0;
                while (received < len) {
                    long result;
                    if ((result = this->recv((char*) buf + received, len - received)) == PN_ERROR) {
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
            } else {
                return Connection::recvall(buf, len);
            }
        }

        int SecureServer::ssl_init(const std::string& certificate_chain_file, const std::string& private_key_file, int private_key_file_type) {
            if (!(this->ssl_ctx = SSL_CTX_new(TLS_server_method()))) {
                detail::set_last_ssl_error(detail::get_last_ssl_error());
                detail::set_last_error(PN_ESSL);
                return PN_ERROR;
            }

            if (SSL_CTX_use_certificate_chain_file(this->ssl_ctx, certificate_chain_file.c_str()) != 1) {
                detail::set_last_ssl_error(detail::get_last_ssl_error());
                detail::set_last_error(PN_ESSL);
                return PN_ERROR;
            }
            if (SSL_CTX_use_PrivateKey_file(this->ssl_ctx, private_key_file.c_str(), private_key_file_type) != 1) {
                detail::set_last_ssl_error(detail::get_last_ssl_error());
                detail::set_last_error(PN_ESSL);
                return PN_ERROR;
            }

            return PN_OK;
        }

        int SecureServer::listen(const std::function<bool(connection_type&, void*)>& cb, int backlog, void* data) { // This function BLOCKS
            if (this->backlog != backlog || this->backlog == -1) {
                if (::listen(this->fd, backlog) == PN_ERROR) {
                    detail::set_last_ssl_error(detail::get_last_system_error());
                    detail::set_last_error(PN_ESOCKET);
                    return PN_ERROR;
                }
                this->backlog = backlog;
            }

            for (;;) {
                connection_type conn;
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

                if (conn.ssl_init(this->ssl_ctx) == PN_ERROR) {
                    return PN_ERROR;
                }
                if (conn.ssl_accept() == PN_ERROR) {
                    continue;
                }

                if (!cb(conn, data)) { // Connections CANNOT be accepted while the callback is blocking
                    break;
                }
            }

            return PN_OK;
        }

        int SecureClient::ssl_init(const std::string& hostname, int verify_mode, const std::string& ca_file, const std::string& ca_path) {
            if (!(this->ssl_ctx = SSL_CTX_new(TLS_client_method()))) {
                detail::set_last_ssl_error(detail::get_last_ssl_error());
                detail::set_last_error(PN_ESSL);
                return PN_ERROR;
            }

            SSL_CTX_set_verify(this->ssl_ctx, verify_mode, nullptr);
            if (ca_file.empty() && ca_path.empty()) {
                if (SSL_CTX_set_default_verify_paths(this->ssl_ctx) == 0) {
                    detail::set_last_ssl_error(detail::get_last_ssl_error());
                    detail::set_last_error(PN_ESSL);
                    return PN_ERROR;
                }
            } else if (SSL_CTX_load_verify_locations(this->ssl_ctx, ca_file.empty() ? nullptr : ca_file.c_str(), ca_path.empty() ? nullptr : ca_path.c_str()) == 0) {
                detail::set_last_ssl_error(detail::get_last_ssl_error());
                detail::set_last_error(PN_ESSL);
                return PN_ERROR;
            }

            if (BasicClient<SecureConnection, SOCK_STREAM, IPPROTO_TCP>::ssl_init(this->ssl_ctx) == PN_ERROR) {
                return PN_ERROR;
            }

            if (SSL_set_tlsext_host_name(ssl, hostname.c_str()) == 0) {
                detail::set_last_ssl_error(detail::get_last_ssl_error());
                detail::set_last_error(PN_ESSL);
                return PN_ERROR;
            }
            if (SSL_set1_host(ssl, hostname.c_str()) == 0) {
                detail::set_last_ssl_error(detail::get_last_ssl_error());
                detail::set_last_error(PN_ESSL);
                return PN_ERROR;
            }

            return PN_OK;
        }
    } // namespace tcp
} // namespace pn
