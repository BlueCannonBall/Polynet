#ifndef POLYNET_SECURE_SOCKETS_HPP_
#define POLYNET_SECURE_SOCKETS_HPP_

#include "polynet.hpp"
#include <openssl/err.h>
#include <openssl/ssl.h>

// Protocol layers
#define PN_PROTOCOL_LAYER_SSL (1 << 1)

namespace pn {
    namespace tcp {
        class SecureConnection : public Connection {
        protected:
            Error io_error(int error, StringView operation);

        public:
            SSL* ssl = nullptr;

            SecureConnection() = default;
            SecureConnection(sockfd_t fd, SSL* ssl):
                Connection(fd),
                ssl(ssl) {}
            SecureConnection(sockfd_t fd, SSL* ssl, const struct sockaddr& addr, socklen_t addrlen):
                Connection(fd, addr, addrlen),
                ssl(ssl) {}
            SecureConnection(SecureConnection&& conn) noexcept {
                *this = std::move(conn);
            }

            ~SecureConnection() {
                (void) close();
            }

            SecureConnection& operator=(SecureConnection&& conn) noexcept {
                if (this != &conn) {
                    Connection::operator=(std::move(conn));
                    ssl = std::exchange(conn.ssl, nullptr);
                }
                return *this;
            }

            Status ssl_init(SSL_CTX* ssl_ctx) {
                if (!(ssl = SSL_new(ssl_ctx))) {
                    return std::unexpected(make_ssl_error(ERR_get_error(), "create SSL connection"));
                }
                if (!SSL_set_fd(ssl, fd)) {
                    return std::unexpected(make_ssl_error(ERR_get_error(), "set SSL socket"));
                }
                return {};
            }

            Status ssl_accept() {
                ERR_clear_error();
                if (int result = SSL_accept(ssl); result <= 0) {
                    return std::unexpected(io_error(result, "accept SSL connection"));
                }
                return {};
            }

            Status close(int protocol_layers = PN_PROTOCOL_LAYER_DEFAULT) override {
                if (ssl) {
                    if (protocol_layers & PN_PROTOCOL_LAYER_SSL) SSL_shutdown(ssl);
                    SSL_free(ssl);
                    ssl = nullptr;
                }
                return Connection::close(protocol_layers);
            }

            bool is_secure() const override {
                return ssl;
            }

            Result<size_t> send(const void* buf, size_t len) override {
                if (ssl) {
                    ERR_clear_error();
                    if (int result = SSL_write(ssl, buf, len); result <= 0) {
                        return std::unexpected(io_error(result, "send SSL data"));
                    } else {
                        return result;
                    }
                }
                return Connection::send(buf, len);
            }

            Result<size_t> recv(void* buf, size_t len) override {
                if (ssl) {
                    ERR_clear_error();
                    if (int result = SSL_read(ssl, buf, len); result < 0) {
                        return std::unexpected(io_error(result, "receive SSL data"));
                    } else {
                        return result;
                    }
                }
                return Connection::recv(buf, len);
            }

            Result<size_t> peek(void* buf, size_t len) override {
                if (ssl) {
                    ERR_clear_error();
                    if (int result = SSL_peek(ssl, buf, len); result < 0) {
                        return std::unexpected(io_error(result, "peek SSL data"));
                    } else {
                        return result;
                    }
                }
                return Connection::peek(buf, len);
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
            SecureServer(sockfd_t fd, SSL_CTX* ssl_ctx, const struct sockaddr& addr, socklen_t addrlen):
                Server(fd, addr, addrlen),
                ssl_ctx(ssl_ctx) {}
            SecureServer(SecureServer&& server) noexcept {
                *this = std::move(server);
            }

            ~SecureServer() {
                (void) close();
            }

            SecureServer& operator=(SecureServer&& server) noexcept {
                if (this != &server) {
                    Server::operator=(std::move(server));
                    ssl_ctx = std::exchange(server.ssl_ctx, nullptr);
                }
                return *this;
            }

            Status ssl_init(StringView certificate_chain_file, StringView private_key_file, int private_key_file_type);

            Status close(int protocol_layers = PN_PROTOCOL_LAYER_DEFAULT) override {
                if (ssl_ctx) {
                    SSL_CTX_free(ssl_ctx);
                    ssl_ctx = nullptr;
                }
                return Server::close(protocol_layers);
            }

            bool is_secure() const override {
                return ssl_ctx;
            }

            Status listen(const std::function<bool(connection_type)>& cb, int backlog = 128);
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
            SecureClient(sockfd_t fd, SSL_CTX* ssl_ctx, SSL* ssl, const struct sockaddr& addr, socklen_t addrlen):
                BasicClient<SecureConnection, SOCK_STREAM, IPPROTO_TCP>(fd, ssl, addr, addrlen),
                ssl_ctx(ssl_ctx) {}
            SecureClient(SecureClient&& client) noexcept {
                *this = std::move(client);
            }

            ~SecureClient() {
                (void) close();
            }

            SecureClient& operator=(SecureClient&& client) noexcept {
                if (this != &client) {
                    BasicClient<SecureConnection, SOCK_STREAM, IPPROTO_TCP>::operator=(std::move(client));
                    ssl_ctx = std::exchange(client.ssl_ctx, nullptr);
                }
                return *this;
            }

            Status ssl_init(StringView hostname, int verify_mode = SSL_VERIFY_PEER, StringView ca_file = {}, StringView ca_path = {});

            Status ssl_connect() {
                ERR_clear_error();
                if (int result = SSL_connect(ssl); result <= 0) {
                    return std::unexpected(io_error(result, "connect SSL connection"));
                }
                return {};
            }

            Status close(int protocol_layers = PN_PROTOCOL_LAYER_DEFAULT) override {
                if (ssl) {
                    if (protocol_layers & PN_PROTOCOL_LAYER_SSL) SSL_shutdown(ssl);
                    SSL_free(ssl);
                    ssl = nullptr;
                }
                if (ssl_ctx) {
                    SSL_CTX_free(ssl_ctx);
                    ssl_ctx = nullptr;
                }
                return Connection::close(protocol_layers);
            }

            bool is_secure() const override {
                return ssl && ssl_ctx;
            }
        };
    } // namespace tcp
} // namespace pn

#endif
