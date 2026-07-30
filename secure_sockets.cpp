#include "secure_sockets.hpp"

namespace pn {
    namespace tcp {
        Error SecureConnection::io_error(int error, StringView operation) {
            switch (SSL_get_error(ssl, error)) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
#ifdef _WIN32
                return make_socket_error(WSAEWOULDBLOCK, operation);
#else
                return make_socket_error(EAGAIN, operation);
#endif

            case SSL_ERROR_SYSCALL:
                if (unsigned long ssl_error = ERR_get_error()) {
                    return make_ssl_error(ssl_error, operation);
                }
                return make_last_socket_error(operation);

            default:
                return make_ssl_error(ERR_get_error(), operation);
            }
        }

        Status SecureServer::ssl_init(StringView certificate_chain_file, StringView private_key_file, int private_key_file_type) {
            if (!(ssl_ctx = SSL_CTX_new(TLS_server_method()))) {
                return std::unexpected(make_ssl_error(ERR_get_error(), "create SSL context"));
            }

            SSL_CTX_set_quiet_shutdown(ssl_ctx, 1);

            if (SSL_CTX_use_certificate_chain_file(ssl_ctx, certificate_chain_file.c_str()) != 1) {
                return std::unexpected(make_ssl_error(ERR_get_error(), "load SSL certificate chain"));
            }
            if (SSL_CTX_use_PrivateKey_file(ssl_ctx, private_key_file.c_str(), private_key_file_type) != 1) {
                return std::unexpected(make_ssl_error(ERR_get_error(), "load SSL private key"));
            }

            return {};
        }

        Status SecureServer::listen(const std::function<bool(connection_type)>& cb, int backlog) { // This function BLOCKS
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

                if (ssl_ctx) {
                    if (Status result = conn.ssl_init(ssl_ctx); !result) {
                        return result;
                    }
                }

                if (!cb(std::move(conn))) { // Connections CANNOT be accepted while the callback is blocking
                    break;
                }
            }

            return {};
        }

        Status SecureClient::ssl_init(StringView hostname, int verify_mode, StringView ca_file, StringView ca_path) {
            if (!(ssl_ctx = SSL_CTX_new(TLS_client_method()))) {
                return std::unexpected(make_ssl_error(ERR_get_error(), "create SSL context"));
            }

            SSL_CTX_set_quiet_shutdown(ssl_ctx, 1);

            SSL_CTX_set_verify(ssl_ctx, verify_mode, nullptr);
            if (verify_mode != SSL_VERIFY_NONE) {
                if (ca_file.empty() && ca_path.empty()) {
#ifdef _WIN32
                    if (!SSL_CTX_load_verify_store(ssl_ctx, "org.openssl.winstore://")) {
#else
                    if (!SSL_CTX_set_default_verify_paths(ssl_ctx)) {
#endif
                        return std::unexpected(make_ssl_error(ERR_get_error(), "load SSL trust store"));
                    }
                } else if (!SSL_CTX_load_verify_locations(ssl_ctx, ca_file.empty() ? nullptr : ca_file.c_str(), ca_path.empty() ? nullptr : ca_path.c_str())) {
                    return std::unexpected(make_ssl_error(ERR_get_error(), "load SSL trust store"));
                }
            }

            if (Status result = BasicClient<SecureConnection, SOCK_STREAM, IPPROTO_TCP>::ssl_init(ssl_ctx); !result) {
                return result;
            }

            if (!SSL_set_tlsext_host_name(ssl, hostname.c_str())) {
                return std::unexpected(make_ssl_error(ERR_get_error(), "set SSL hostname"));
            }
            if (!SSL_set1_host(ssl, hostname.c_str())) {
                return std::unexpected(make_ssl_error(ERR_get_error(), "set SSL hostname"));
            }

            return {};
        }
    } // namespace tcp
} // namespace pn
