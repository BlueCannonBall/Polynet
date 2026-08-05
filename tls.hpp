#ifndef POLYNET_TLS_HPP_
#define POLYNET_TLS_HPP_

#include "polynet.hpp"
#include <mutex>
#include <vector>
#include <openssl/err.h>
#include <openssl/ssl.h>

// Protocol layers
#define PN_PROTOCOL_LAYER_TLS (1 << 1)

namespace pn {
    const std::error_category& ssl_category() noexcept;

    inline std::error_code ssl_error_code(unsigned long error) noexcept {
        return {(int) error, ssl_category()};
    }

    // Takes the whole error, not just its first entry, so that none of it is left to be
    // reported against whatever fails next
    inline std::error_code take_ssl_error_code() noexcept {
        std::error_code error = ssl_error_code(ERR_get_error());
        ERR_clear_error();
        return error;
    }

    inline Error make_ssl_error(unsigned long error, StringView operation = {}) noexcept {
        return error ? Error {ssl_error_code(error), operation} : make_polynet_error(PN_ERROR_TLS, operation);
    }

    // PN_ERROR_TLS stands for the failures OpenSSL reports without describing
    inline Error take_ssl_error(StringView operation = {}) noexcept {
        if (std::error_code error = take_ssl_error_code(); error) {
            return {error, operation};
        }
        return make_polynet_error(PN_ERROR_TLS, operation);
    }

    // The certificates, trust settings and session cache shared by every connection made
    // from it. Building one is expensive and using one is not, so a program making many
    // connections should build one and hand it to each of them. Connections take their own
    // reference, so a context may be closed while connections made from it are still open
    class TLSContext {
    public:
        SSL_CTX* ssl_ctx = nullptr;

        TLSContext() = default;
        TLSContext(SSL_CTX* ssl_ctx) noexcept:
            ssl_ctx(ssl_ctx) {}
        TLSContext(TLSContext&& context) noexcept {
            *this = std::move(context);
        }

        TLSContext& operator=(TLSContext&& context) noexcept {
            if (this != &context) {
                reset();
                ssl_ctx = std::exchange(context.ssl_ctx, nullptr);
            }
            return *this;
        }

        ~TLSContext() {
            reset();
        }

        Status init_client(int verify_mode = SSL_VERIFY_PEER, StringView ca_file = {}, StringView ca_path = {});
        Status init_server(StringView certificate_chain_file, StringView private_key_file, int private_key_file_type);

        void reset() noexcept {
            if (ssl_ctx) {
                SSL_CTX_free(std::exchange(ssl_ctx, nullptr));
            }
        }

        bool is_valid() const noexcept {
            return ssl_ctx;
        }

        operator bool() const noexcept {
            return is_valid();
        }
    };

    namespace tcp {
        class TLSConnection : public Connection {
        protected:
            static constexpr size_t buf_capacity = 16'000;

            std::mutex ssl_mutex;       // Guards the SSL connection and its BIOs. No blocking
                                        // socket operation may be performed while it is held
            std::mutex ssl_read_mutex;  // Serializes receivers, each of which may need several
            std::mutex ssl_write_mutex; // attempts at one SSL operation, and senders likewise
            std::mutex send_mutex;
            std::mutex recv_mutex;
            BIO* send_bio = nullptr;
            BIO* recv_bio = nullptr;
            std::vector<char> pending;
            size_t pending_cursor = 0;
            bool fatal_ssl_error = false;

            Status flush(bool receiving);
            Result<bool> fill();

            // Carries out one SSL operation, along with whatever transport work its
            // intermediate results call for, until it either finishes or fails. The
            // operation must be repeatable with identical arguments, which is what OpenSSL
            // demands of anything it asks to have retried, and the caller must already hold
            // ssl_read_mutex or ssl_write_mutex so that nothing going the same direction
            // interleaves with those retries. A zero result means the peer shut the
            // connection down cleanly, which only a receive can treat as an ordinary outcome
            template <typename Op>
            Result<size_t> ssl_op(StringView operation, bool receiving, Op op) {
                for (bool eof = false;;) {
                    int result;
                    int ssl_error = SSL_ERROR_NONE;
                    Error error;
                    {
                        std::lock_guard<std::mutex> lock(ssl_mutex);
                        ERR_clear_error();
                        result = op();
                        if (result <= 0) {
                            ssl_error = SSL_get_error(ssl, result);
                            if (ssl_error != SSL_ERROR_ZERO_RETURN && ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE) {
                                error = take_ssl_error(operation);
                            }
                            if (ssl_error == SSL_ERROR_SSL || ssl_error == SSL_ERROR_SYSCALL) {
                                fatal_ssl_error = true;
                            }
                        }
                    }

                    // Plaintext already in the caller's buffer cannot be read again, so a
                    // failed flush is left for the next operation to report rather than
                    // costing the caller data that did arrive
                    Status flushed = flush(receiving);
                    if (receiving && result > 0) {
                        return result;
                    }
                    if (!flushed) {
                        return std::unexpected(flushed.error());
                    }
                    if (result > 0) {
                        return result;
                    }
                    if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                        return 0;
                    }
                    if (ssl_error == SSL_ERROR_WANT_READ) {
                        if (eof) {
                            fatal_ssl_error = true;
                            return std::unexpected(make_polynet_error(PN_ERROR_TLS, "read TLS ciphertext after EOF"));
                        }
                        if (Result<bool> received = fill(); !received) {
                            return std::unexpected(received.error());
                        } else {
                            eof = !*received;
                        }
                        continue;
                    }
                    if (ssl_error == SSL_ERROR_WANT_WRITE) {
                        continue;
                    }
                    return std::unexpected(error);
                }
            }

            Status handshake(StringView operation);

        public:
            SSL* ssl = nullptr; // Guarded by ssl_mutex during sends and receives

            TLSConnection() = default;
            using Connection::Connection;
            TLSConnection(TLSConnection&& conn) {
                *this = std::move(conn);
            }

            TLSConnection& operator=(TLSConnection&& conn) {
                if (this != &conn) {
                    Connection::operator=(std::move(conn));
                    ssl = std::exchange(conn.ssl, nullptr);
                    recv_bio = std::exchange(conn.recv_bio, nullptr);
                    send_bio = std::exchange(conn.send_bio, nullptr);
                    pending = std::move(conn.pending);
                    pending_cursor = std::exchange(conn.pending_cursor, 0);
                    fatal_ssl_error = std::exchange(conn.fatal_ssl_error, false);
                }
                return *this;
            }

            ~TLSConnection() {
                (void) close();
            }

            Status tls_init(const TLSContext& context);
            Status tls_accept();

            Status close(int protocol_layers = PN_PROTOCOL_LAYER_DEFAULT) override;

            bool is_secure() const noexcept override {
                return ssl;
            }

            Result<size_t> send(const void* buf, size_t len) override;
            Result<size_t> recv(void* buf, size_t len) override;
            Result<size_t> peek(void* buf, size_t len) override;
        };

        class TLSServer : public Server {
        public:
            typedef TLSConnection connection_type;

            using Server::listen; // Listening without a context accepts plaintext connections
            using Server::Server;

            Status listen(const TLSContext& context, const std::function<bool(connection_type)>& cb, int backlog = 128);
        };

        class TLSClient : public BasicClient<TLSConnection, SOCK_STREAM, IPPROTO_TCP> {
        private:
            using BasicClient<TLSConnection, SOCK_STREAM, IPPROTO_TCP>::tls_accept;

        public:
            TLSClient() = default;
            using BasicClient<TLSConnection, SOCK_STREAM, IPPROTO_TCP>::BasicClient;

            Status tls_init(const TLSContext& context, StringView hostname);
            Status tls_connect();
        };
    } // namespace tcp
} // namespace pn

#endif
