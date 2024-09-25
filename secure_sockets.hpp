#ifndef _POLYNET_SECURE_SOCKETS_HPP
#define _POLYNET_SECURE_SOCKETS_HPP

#include "polynet.hpp"
#include <openssl/err.h>
#include <openssl/ssl.h>

// Protocol layers
#define PN_PROTOCOL_LAYER_SSL (1 << 1)

namespace pn {
    namespace detail {
        extern thread_local unsigned long last_ssl_error;

        inline void set_last_ssl_error(unsigned long error) {
            last_ssl_error = error;
        }

        inline unsigned long get_last_ssl_error() {
            return ERR_get_error();
        }
    } // namespace detail

    inline unsigned long get_last_ssl_error() {
        return detail::last_ssl_error;
    }

    inline std::string ssl_strerror(unsigned long error = get_last_ssl_error()) {
        return ERR_error_string(error, nullptr);
    }

    namespace tcp {
        class SecureConnection : public Connection {
        public:
            SSL* ssl = nullptr;

            SecureConnection() = default;
            SecureConnection(sockfd_t fd, SSL* ssl):
                Connection(fd),
                ssl(ssl) {}
            SecureConnection(const struct sockaddr& addr, socklen_t addrlen):
                Connection(addr, addrlen) {}
            SecureConnection(sockfd_t fd, SSL* ssl, const struct sockaddr& addr, socklen_t addrlen):
                Connection(fd, addr, addrlen),
                ssl(ssl) {}

            int ssl_init(SSL_CTX* ssl_ctx) {
                if (!(ssl = SSL_new(ssl_ctx))) {
                    detail::set_last_ssl_error(detail::get_last_ssl_error());
                    detail::set_last_error(PN_ESSL);
                    return PN_ERROR;
                }
                if (SSL_set_fd(ssl, fd) == 0) {
                    detail::set_last_ssl_error(detail::get_last_ssl_error());
                    detail::set_last_error(PN_ESSL);
                    return PN_ERROR;
                }
                return PN_OK;
            }

            void ssl_reset(bool reset_ptr = true, bool validity_check = true) {
                if (!validity_check || ssl) {
                    SSL_free(ssl);
                    if (reset_ptr) ssl = nullptr;
                }
            }

            int ssl_accept() {
                if (SSL_accept(ssl) <= 0) {
                    detail::set_last_ssl_error(detail::get_last_ssl_error());
                    detail::set_last_error(PN_ESSL);
                    return PN_ERROR;
                }
                return PN_OK;
            }

            int close(int protocol_layers = PN_PROTOCOL_LAYER_ALL, bool reset = true) override {
                if (ssl) {
                    if (protocol_layers & PN_PROTOCOL_LAYER_SSL && SSL_shutdown(ssl) < 0) {
                        ERR_clear_error();
                    }
                    SSL_free(ssl);
                    if (reset) ssl = nullptr;
                }
                return Connection::close(protocol_layers, reset);
            }

            long send(const void* buf, size_t len) override {
                if (ssl) {
                    int result;
                    if ((result = SSL_write(ssl, buf, len)) <= 0) {
                        detail::set_last_ssl_error(detail::get_last_ssl_error());
                        detail::set_last_error(PN_ESSL);
                        return PN_ERROR;
                    }
                    return result;
                } else {
                    return Connection::send(buf, len);
                }
            }

            long sendall(const void* buf, size_t len) override;

            long recv(void* buf, size_t len) override {
                if (ssl) {
                    int result;
                    if ((result = SSL_read(ssl, buf, len)) < 0) {
                        detail::set_last_ssl_error(detail::get_last_ssl_error());
                        detail::set_last_error(PN_ESSL);
                    }
                    return result;
                } else {
                    return Connection::recv(buf, len);
                }
            }

            long peek(void* buf, size_t len) override {
                if (ssl) {
                    int result;
                    if ((result = SSL_peek(ssl, buf, len)) < 0) {
                        detail::set_last_ssl_error(detail::get_last_ssl_error());
                        detail::set_last_error(PN_ESSL);
                    }
                    return result;
                } else {
                    return Connection::peek(buf, len);
                }
            }

            long recvall(void* buf, size_t len) override;

            bool is_secure() const override {
                return ssl;
            }
        };

        class SecureServer : public Server {
        public:
            SSL_CTX* ssl_ctx = nullptr;

            typedef SecureConnection connection_type;

            SecureServer() = default;
            SecureServer(sockfd_t fd, SSL_CTX* ssl_ctx):
                Server(fd),
                ssl_ctx(ssl_ctx) {}
            SecureServer(const struct sockaddr& addr, socklen_t addrlen):
                Server(addr, addrlen) {}
            SecureServer(sockfd_t fd, SSL_CTX* ssl_ctx, const struct sockaddr& addr, socklen_t addrlen):
                Server(fd, addr, addrlen),
                ssl_ctx(ssl_ctx) {}

            int ssl_init(StringView certificate_chain_file, StringView private_key_file, int private_key_file_type);

            int close(int protocol_layers = PN_PROTOCOL_LAYER_ALL, bool reset = true) override {
                if (ssl_ctx) {
                    SSL_CTX_free(ssl_ctx);
                    if (reset) ssl_ctx = nullptr;
                }
                return Server::close(protocol_layers, reset);
            }

            int listen(const std::function<bool(connection_type&, void*)>& cb, int backlog = 128, void* data = nullptr);

            bool is_secure() const override {
                return ssl_ctx;
            }
        };

        class SecureClient : public BasicClient<SecureConnection, SOCK_STREAM, IPPROTO_TCP> {
        protected:
            SSL_CTX* ssl_ctx = nullptr;

        private:
            using BasicClient<SecureConnection, SOCK_STREAM, IPPROTO_TCP>::ssl_accept;

        public:
            SecureClient() = default;
            SecureClient(sockfd_t fd, SSL_CTX* ssl_ctx, SSL* ssl):
                BasicClient<SecureConnection, SOCK_STREAM, IPPROTO_TCP>(fd, ssl),
                ssl_ctx(ssl_ctx) {}
            SecureClient(const struct sockaddr& addr, socklen_t addrlen):
                BasicClient<SecureConnection, SOCK_STREAM, IPPROTO_TCP>(addr, addrlen) {}
            SecureClient(sockfd_t fd, SSL_CTX* ssl_ctx, SSL* ssl, const struct sockaddr& addr, socklen_t addrlen):
                BasicClient<SecureConnection, SOCK_STREAM, IPPROTO_TCP>(fd, ssl, addr, addrlen),
                ssl_ctx(ssl_ctx) {}

            int ssl_init(StringView hostname, int verify_mode = SSL_VERIFY_PEER, StringView ca_file = {}, StringView ca_path = {});

            int ssl_connect() {
                if (SSL_connect(ssl) <= 0) {
                    detail::set_last_ssl_error(detail::get_last_ssl_error());
                    detail::set_last_error(PN_ESSL);
                    return PN_ERROR;
                }
                return PN_OK;
            }

            bool is_secure() const override {
                return ssl && ssl_ctx;
            }
        };
    } // namespace tcp
} // namespace pn

#endif
