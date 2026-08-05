#include "tls.hpp"
#include <algorithm>
#include <errno.h>

namespace pn {
    namespace {
        class SSLCategory : public std::error_category {
        public:
            const char* name() const noexcept override {
                return "ssl";
            }

            std::string message(int error) const override {
                char buf[256];
                // OpenSSL error codes do not fit in the int that std::error_code stores, so
                // the round trip goes back through unsigned int rather than sign extending
                // the system error codes, whose top bit is set
                ERR_error_string_n((unsigned int) error, buf, sizeof buf);
                return buf;
            }
        };
    } // namespace

    const std::error_category& ssl_category() noexcept {
        static const SSLCategory category;
        return category;
    }

    Status TLSContext::init_server(StringView certificate_chain_file, StringView private_key_file, int private_key_file_type) {
        if (this->ssl_ctx) {
            return std::unexpected(make_polynet_error(PN_ERROR_ALREADY_INITIALIZED, "create TLS context"));
        }

        ERR_clear_error();
        SSL_CTX* ssl_ctx;
        if (!(ssl_ctx = SSL_CTX_new(TLS_server_method()))) {
            return std::unexpected(take_ssl_error("create TLS context"));
        }

        SSL_CTX_set_quiet_shutdown(ssl_ctx, 1);

        if (SSL_CTX_use_certificate_chain_file(ssl_ctx, certificate_chain_file.c_str()) != 1) {
            Error error = take_ssl_error("load TLS certificate chain");
            SSL_CTX_free(ssl_ctx);
            return std::unexpected(error);
        }
        if (SSL_CTX_use_PrivateKey_file(ssl_ctx, private_key_file.c_str(), private_key_file_type) != 1) {
            Error error = take_ssl_error("load TLS private key");
            SSL_CTX_free(ssl_ctx);
            return std::unexpected(error);
        }
        if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
            Error error = take_ssl_error("check TLS private key");
            SSL_CTX_free(ssl_ctx);
            return std::unexpected(error);
        }

        this->ssl_ctx = ssl_ctx;
        return {};
    }

    Status TLSContext::init_client(int verify_mode, StringView ca_file, StringView ca_path) {
        if (this->ssl_ctx) {
            return std::unexpected(make_polynet_error(PN_ERROR_ALREADY_INITIALIZED, "create TLS context"));
        }

        ERR_clear_error();
        SSL_CTX* ssl_ctx;
        if (!(ssl_ctx = SSL_CTX_new(TLS_client_method()))) {
            return std::unexpected(take_ssl_error("create TLS context"));
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
                    Error error = take_ssl_error("load TLS trust store");
                    SSL_CTX_free(ssl_ctx);
                    return std::unexpected(error);
                }
            } else if (!SSL_CTX_load_verify_locations(ssl_ctx, ca_file.empty() ? nullptr : ca_file.c_str(), ca_path.empty() ? nullptr : ca_path.c_str())) {
                Error error = take_ssl_error("load TLS trust store");
                SSL_CTX_free(ssl_ctx);
                return std::unexpected(error);
            }
        }

        this->ssl_ctx = ssl_ctx;
        return {};
    }

    namespace tcp {
        namespace {
            bool is_ip_literal(StringView hostname) {
                if (in_addr ipv4; pn::inet_pton(AF_INET, hostname, &ipv4)) {
                    return true;
                }
                if (in6_addr ipv6; pn::inet_pton(AF_INET6, hostname, &ipv6)) {
                    return true;
                }
                return false;
            }
        } // namespace

        Status TLSConnection::tls_init(const TLSContext& context) {
            if (this->ssl) {
                return std::unexpected(make_polynet_error(PN_ERROR_ALREADY_INITIALIZED, "create TLS connection"));
            }

            ERR_clear_error();
            SSL* ssl;
            if (!(ssl = SSL_new(context.ssl_ctx))) {
                return std::unexpected(take_ssl_error("create TLS connection"));
            }

            BIO* ssl_rbio = nullptr;
            BIO* ssl_wbio = nullptr;
            BIO* recv_bio = nullptr;
            BIO* send_bio = nullptr;
            if (!BIO_new_bio_pair(&ssl_rbio, buf_capacity, &recv_bio, buf_capacity) ||
                !BIO_new_bio_pair(&send_bio, buf_capacity, &ssl_wbio, buf_capacity)) {
                Error error = take_ssl_error("create TLS BIO pair");
                BIO_free(ssl_rbio);
                BIO_free(ssl_wbio);
                BIO_free(recv_bio);
                BIO_free(send_bio);
                SSL_free(ssl);
                return std::unexpected(error);
            }
            SSL_set0_rbio(ssl, ssl_rbio);
            SSL_set0_wbio(ssl, ssl_wbio);

            this->ssl = ssl;
            this->recv_bio = recv_bio;
            this->send_bio = send_bio;
            pending.clear();
            pending_cursor = 0;
            fatal_ssl_error = false;

            return {};
        }

        // Writing ciphertext to the socket blocks for as long as the peer takes to read it,
        // and the peer may not read until this end drains what it is being sent. A receiver
        // therefore never performs that write while a sender is active: the ciphertext queued
        // by that sender is its to deliver, and a receiver that blocked on it would be unable
        // to drain the connection that the sender is waiting on. Whatever a receive leaves
        // behind goes out with the next flush from either end, as a flush empties the BIO
        Status TLSConnection::flush(bool receiving) {
            std::unique_lock<std::mutex> sender_lock(ssl_write_mutex, std::defer_lock);
            if (receiving && !sender_lock.try_lock()) {
                return {};
            }

            std::lock_guard<std::mutex> lock(send_mutex);
            for (;;) {
                if (pending.empty()) {
                    std::lock_guard<std::mutex> lock(ssl_mutex);
                    int available = BIO_ctrl_pending(send_bio);
                    if (!available) {
                        return {};
                    }

                    pending.resize(available);
                    int read = BIO_read(send_bio, pending.data(), available);
                    if (read <= 0) {
                        pending.clear();
                        return std::unexpected(take_ssl_error("read TLS ciphertext"));
                    }
                    pending.resize(read);
                    pending_cursor = 0;
                }

                while (pending_cursor < pending.size()) {
                    if (Result<size_t> result = Connection::send(pending.data() + pending_cursor, pending.size() - pending_cursor); !result) {
                        return std::unexpected(result.error());
                    } else {
                        pending_cursor += *result;
                    }
                }
                pending.clear();
                pending_cursor = 0;
            }
        }

        Result<bool> TLSConnection::fill() {
            std::lock_guard<std::mutex> lock(recv_mutex);

            size_t capacity;
            {
                std::lock_guard<std::mutex> lock(ssl_mutex);
                capacity = BIO_get_write_guarantee(recv_bio);
            }
            // A sender and a receiver both reach here when each is told to want more
            // ciphertext, and whichever arrives second finds the buffer already refilled.
            // That is ciphertext waiting to be processed, not a failure
            if (!capacity) {
                return true;
            }

            char buf[buf_capacity];
            Result<size_t> result = Connection::recv(buf, std::min(sizeof buf, capacity));
            if (!result) {
                return std::unexpected(result.error());
            }
            if (!*result) {
                std::lock_guard<std::mutex> lock(ssl_mutex);
                BIO_shutdown_wr(recv_bio);
                return false;
            }

            {
                std::lock_guard<std::mutex> lock(ssl_mutex);
                if (BIO_write(recv_bio, buf, (int) *result) != (int) *result) {
                    return std::unexpected(take_ssl_error("buffer TLS ciphertext"));
                }
            }
            return true;
        }

        Status TLSConnection::handshake(StringView operation) {
            Result<size_t> result = ssl_op(operation, false, [this] {
                return SSL_do_handshake(ssl);
            });
            if (!result) {
                return std::unexpected(result.error());
            }
            if (!*result) { // A handshake has no orderly shutdown to report, so a peer
                            // that closes part way through one has failed it
                return std::unexpected(make_polynet_error(PN_ERROR_TLS, operation));
            }
            return {};
        }

        Status TLSConnection::tls_accept() {
            SSL_set_accept_state(ssl);
            return handshake("accept TLS connection");
        }

        Status TLSConnection::close(int protocol_layers) {
            if (ssl && (protocol_layers & PN_PROTOCOL_LAYER_TLS)) {
                if (!fatal_ssl_error) SSL_shutdown(ssl);
                BIO_free(std::exchange(recv_bio, nullptr));
                BIO_free(std::exchange(send_bio, nullptr));
                SSL_free(std::exchange(ssl, nullptr));
                pending.clear();
                pending_cursor = 0;
                fatal_ssl_error = false;
            }
            return Connection::close(protocol_layers);
        }

        Result<size_t> TLSConnection::send(const void* buf, size_t len) {
            if (!ssl) {
                return Connection::send(buf, len);
            }

            std::lock_guard<std::mutex> write_lock(ssl_write_mutex);
            Result<size_t> result = ssl_op("send TLS data", false, [&] {
                return SSL_write(ssl, buf, pn::detail::clamp_transfer_len(len));
            });
            if (result && !*result) { // There is nothing to send to a peer that has shut the
                                      // connection down, and reporting no progress instead of
                                      // an error would leave sendall going round forever
                return std::unexpected(make_polynet_error(PN_ERROR_TLS, "send TLS data"));
            }
            return result;
        }

        Result<size_t> TLSConnection::recv(void* buf, size_t len) {
            if (!ssl) {
                return Connection::recv(buf, len);
            }

            std::lock_guard<std::mutex> read_lock(ssl_read_mutex);
            return ssl_op("receive TLS data", true, [&] {
                return SSL_read(ssl, buf, pn::detail::clamp_transfer_len(len));
            });
        }

        Result<size_t> TLSConnection::peek(void* buf, size_t len) {
            if (!ssl) {
                return Connection::peek(buf, len);
            }

            std::lock_guard<std::mutex> read_lock(ssl_read_mutex);
            return ssl_op("peek TLS data", true, [&] {
                return SSL_peek(ssl, buf, pn::detail::clamp_transfer_len(len));
            });
        }

        Status TLSServer::listen(const TLSContext& context, const std::function<bool(connection_type)>& cb, int backlog) { // This function BLOCKS
            if (::listen(fd, backlog) == PN_ERROR) {
                return std::unexpected(make_last_socket_error("listen"));
            }

            for (;;) {
                connection_type conn;
                if ((conn.fd = accept(fd, (struct sockaddr*) &conn.addr, &conn.addrlen)) == PN_INVALID_SOCKFD) {
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

                if (Status result = conn.tls_init(context); !result) { // One connection failing to
                    continue;                                          // initialize isn't fatal to the server
                }

                if (!cb(std::move(conn))) { // Connections CANNOT be accepted while the callback is blocking
                    break;
                }
            }

            return {};
        }

        Status TLSClient::tls_init(const TLSContext& context, StringView hostname) {
            if (Status result = TLSConnection::tls_init(context); !result) {
                return result;
            }

            ERR_clear_error();
            if (!is_ip_literal(hostname) && !SSL_set_tlsext_host_name(ssl, hostname.c_str())) {
                Error error = take_ssl_error("set TLS hostname");
                (void) TLSConnection::close(PN_PROTOCOL_LAYER_TLS);
                return std::unexpected(error);
            }
            if (!SSL_set1_host(ssl, hostname.c_str())) {
                Error error = take_ssl_error("set TLS hostname");
                (void) TLSConnection::close(PN_PROTOCOL_LAYER_TLS);
                return std::unexpected(error);
            }
            return {};
        }

        Status TLSClient::tls_connect() {
            SSL_set_connect_state(ssl);
            return handshake("connect TLS connection");
        }
    } // namespace tcp
} // namespace pn
