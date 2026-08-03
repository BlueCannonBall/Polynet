#ifndef POLYNET_SECURE_SOCKETS_HPP_
#define POLYNET_SECURE_SOCKETS_HPP_

#include "polynet.hpp"
#include <mutex>
#include <openssl/err.h>
#include <openssl/ssl.h>

// Protocol layers
#define PN_PROTOCOL_LAYER_SSL (1 << 1)

namespace pn {
    const std::error_category& ssl_category() noexcept;

    inline std::error_code ssl_error_code(unsigned long error) noexcept {
        return {(int) error, ssl_category()};
    }

    inline std::error_code last_ssl_error_code() noexcept {
        return ssl_error_code(ERR_get_error());
    }

    inline Error make_ssl_error(unsigned long error, StringView operation = {}) noexcept {
        return error ? Error {ssl_error_code(error), operation} : make_polynet_error(PN_ERROR_SSL, operation);
    }

    inline Error make_last_ssl_error(StringView operation = {}) noexcept {
        if (std::error_code error = last_ssl_error_code(); error) {
            return {error, operation};
        }
        return make_polynet_error(PN_ERROR_SSL, operation);
    }

    namespace tcp {
        class SecureConnection : public Connection {
        protected:
            static constexpr size_t ciphertext_buf_capacity = 16'000;

            std::mutex ssl_mutex;
            std::mutex ssl_retry_mutex;
            std::mutex ssl_write_mutex;
            std::mutex ciphertext_send_mutex;
            std::mutex ciphertext_recv_mutex;
            SSL* ssl = nullptr;
            BIO* ciphertext_send_bio = nullptr;
            BIO* ciphertext_recv_bio = nullptr;
            std::vector<char> pending_ciphertext;
            size_t pending_ciphertext_cursor = 0;
            bool ssl_fatal_error = false;

            Status flush_ciphertext();
            Result<bool> recv_ciphertext();
            Status handshake(StringView operation);
            Result<size_t> read_plaintext(void* plaintext, size_t len, bool peek, StringView operation);

        public:
            SecureConnection() = default;
            SecureConnection(sockfd_t fd) noexcept:
                Connection(fd) {}
            SecureConnection(sockfd_t fd, const struct sockaddr& addr, socklen_t addrlen) noexcept:
                Connection(fd, addr, addrlen) {}
            SecureConnection(SecureConnection&& conn) {
                *this = std::move(conn);
            }

            SecureConnection& operator=(SecureConnection&& conn) {
                if (this != &conn) {
                    Connection::operator=(std::move(conn));
                    ssl = std::exchange(conn.ssl, nullptr);
                    ciphertext_recv_bio = std::exchange(conn.ciphertext_recv_bio, nullptr);
                    ciphertext_send_bio = std::exchange(conn.ciphertext_send_bio, nullptr);
                    pending_ciphertext = std::move(conn.pending_ciphertext);
                    pending_ciphertext_cursor = std::exchange(conn.pending_ciphertext_cursor, 0);
                    ssl_fatal_error = std::exchange(conn.ssl_fatal_error, false);
                }
                return *this;
            }

            ~SecureConnection() {
                (void) close();
            }

            Status ssl_init(SSL_CTX* ssl_ctx);
            Status ssl_accept();

            Status close(int protocol_layers = PN_PROTOCOL_LAYER_DEFAULT) override;

            bool is_secure() const noexcept override {
                return ssl;
            }

            Result<size_t> send(const void* plaintext, size_t len) override;
            Result<size_t> recv(void* plaintext, size_t len) override;
            Result<size_t> peek(void* plaintext, size_t len) override;
        };

        class SecureServer : public Server {
        public:
            SSL_CTX* ssl_ctx = nullptr;

            typedef SecureConnection connection_type;

            SecureServer() = default;
            SecureServer(sockfd_t fd, SSL_CTX* ssl_ctx) noexcept:
                Server(fd),
                ssl_ctx(ssl_ctx) {}
            SecureServer(sockfd_t fd, SSL_CTX* ssl_ctx, const struct sockaddr& addr, socklen_t addrlen) noexcept:
                Server(fd, addr, addrlen),
                ssl_ctx(ssl_ctx) {}
            SecureServer(SecureServer&& server) {
                *this = std::move(server);
            }

            SecureServer& operator=(SecureServer&& server) {
                if (this != &server) {
                    Server::operator=(std::move(server));
                    ssl_ctx = std::exchange(server.ssl_ctx, nullptr);
                }
                return *this;
            }

            ~SecureServer() {
                (void) close();
            }

            Status ssl_init(StringView certificate_chain_file, StringView private_key_file, int private_key_file_type);

            Status close(int protocol_layers = PN_PROTOCOL_LAYER_DEFAULT) override {
                if (ssl_ctx) {
                    SSL_CTX_free(ssl_ctx);
                    ssl_ctx = nullptr;
                }
                return Server::close(protocol_layers);
            }

            bool is_secure() const noexcept override {
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
            SecureClient(SecureClient&& client) {
                *this = std::move(client);
            }

            SecureClient& operator=(SecureClient&& client) {
                if (this != &client) {
                    BasicClient<SecureConnection, SOCK_STREAM, IPPROTO_TCP>::operator=(std::move(client));
                    ssl_ctx = std::exchange(client.ssl_ctx, nullptr);
                }
                return *this;
            }

            ~SecureClient() {
                (void) close();
            }

            Status ssl_init(StringView hostname, int verify_mode = SSL_VERIFY_PEER, StringView ca_file = {}, StringView ca_path = {});
            Status ssl_connect();

            Status close(int protocol_layers = PN_PROTOCOL_LAYER_DEFAULT) override {
                Status result = SecureConnection::close(protocol_layers);
                SSL_CTX_free(std::exchange(ssl_ctx, nullptr));
                return result;
            }

            bool is_secure() const noexcept override {
                return ssl && ssl_ctx;
            }
        };
    } // namespace tcp
} // namespace pn

#endif
