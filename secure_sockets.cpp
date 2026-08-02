#include "secure_sockets.hpp"

namespace pn {
    namespace detail {
        class SSLCategory : public std::error_category {
        public:
            const char* name() const noexcept override {
                return "ssl";
            }

            std::string message(int error) const override {
                char buf[256];
                ERR_error_string_n((unsigned long) error, buf, sizeof buf);
                return buf;
            }
        };
    } // namespace detail

    const std::error_category& ssl_category() {
        static const detail::SSLCategory category;
        return category;
    }

    namespace tcp {
        namespace detail {
            Error make_io_error(int ssl_error, StringView operation) {
                switch (ssl_error) {
                case SSL_ERROR_WANT_READ:
                case SSL_ERROR_WANT_WRITE:
#ifdef _WIN32
                    return make_socket_error(WSAEWOULDBLOCK, operation);
#else
                    return make_socket_error(EAGAIN, operation);
#endif

                default:
                    return make_last_ssl_error(operation);
                }
            }
        } // namespace detail

        Status SecureConnection::ssl_init(SSL_CTX* ssl_ctx) {
            if (ssl) {
                return std::unexpected(make_polynet_error(PN_ERROR_ALREADY_INITIALIZED, "create SSL connection"));
            }

            if (SSL* new_ssl = SSL_new(ssl_ctx); !new_ssl) {
                return std::unexpected(make_last_ssl_error("create SSL connection"));
            } else {
                BIO* ssl_rbio = nullptr;
                BIO* ssl_wbio = nullptr;
                BIO* new_ciphertext_recv_bio = nullptr;
                BIO* new_ciphertext_send_bio = nullptr;
                if (!BIO_new_bio_pair(&ssl_rbio, ciphertext_buf_capacity, &new_ciphertext_recv_bio, ciphertext_buf_capacity) ||
                    !BIO_new_bio_pair(&new_ciphertext_send_bio, ciphertext_buf_capacity, &ssl_wbio, ciphertext_buf_capacity)) {
                    Error error = make_last_ssl_error("create SSL BIO pair");
                    BIO_free(ssl_rbio);
                    BIO_free(ssl_wbio);
                    BIO_free(new_ciphertext_recv_bio);
                    BIO_free(new_ciphertext_send_bio);
                    SSL_free(new_ssl);
                    return std::unexpected(error);
                }
                SSL_set0_rbio(new_ssl, ssl_rbio);
                SSL_set0_wbio(new_ssl, ssl_wbio);

                ssl = new_ssl;
                ciphertext_recv_bio = new_ciphertext_recv_bio;
                ciphertext_send_bio = new_ciphertext_send_bio;
                pending_ciphertext.clear();
                pending_ciphertext_cursor = 0;
                ssl_fatal_error = false;

                return {};
            }
        }

        Status SecureConnection::flush_ciphertext() {
            std::lock_guard<std::mutex> lock(ciphertext_send_mutex);
            for (;;) {
                if (pending_ciphertext.empty()) {
                    std::lock_guard<std::mutex> lock(ssl_mutex);
                    if (int available = BIO_ctrl_pending(ciphertext_send_bio); !available) {
                        return {};
                    } else {
                        pending_ciphertext.resize(available);
                        if (int result = BIO_read(ciphertext_send_bio, pending_ciphertext.data(), available); result <= 0) {
                            pending_ciphertext.clear();
                            return std::unexpected(make_last_ssl_error("read SSL ciphertext"));
                        } else {
                            pending_ciphertext.resize(result);
                            pending_ciphertext_cursor = 0;
                        }
                    }
                }

                while (pending_ciphertext_cursor < pending_ciphertext.size()) {
                    if (Result<size_t> result = Connection::send(pending_ciphertext.data() + pending_ciphertext_cursor, pending_ciphertext.size() - pending_ciphertext_cursor); !result) {
                        return std::unexpected(result.error());
                    } else {
                        pending_ciphertext_cursor += *result;
                    }
                }
                pending_ciphertext.clear();
                pending_ciphertext_cursor = 0;
            }
        }

        Result<bool> SecureConnection::recv_ciphertext() {
            std::lock_guard<std::mutex> lock(ciphertext_recv_mutex);

            size_t capacity;
            {
                std::lock_guard<std::mutex> lock(ssl_mutex);
                capacity = BIO_get_write_guarantee(ciphertext_recv_bio);
            }
            if (!capacity) {
                return std::unexpected(make_ssl_error(0, "buffer SSL ciphertext"));
            }

            char ciphertext[ciphertext_buf_capacity];
            if (Result<size_t> result = Connection::recv(ciphertext, std::min(sizeof ciphertext, capacity)); !result) {
                return std::unexpected(result.error());
            } else {
                std::lock_guard<std::mutex> lock(ssl_mutex);
                if (!*result) {
                    BIO_shutdown_wr(ciphertext_recv_bio);
                    return false;
                }

                if (BIO_write(ciphertext_recv_bio, ciphertext, (int) *result) != (int) *result) {
                    return std::unexpected(make_last_ssl_error("buffer SSL ciphertext"));
                }
                return true;
            }
        }

        Status SecureConnection::handshake(StringView operation) {
            for (bool ciphertext_eof = false;;) {
                int result;
                int ssl_error = SSL_ERROR_NONE;
                Error error;
                ERR_clear_error();
                result = SSL_do_handshake(ssl);
                if (result <= 0) {
                    ssl_error = SSL_get_error(ssl, result);
                    error = detail::make_io_error(ssl_error, operation);
                    if (ssl_error == SSL_ERROR_SSL || ssl_error == SSL_ERROR_SYSCALL) {
                        ssl_fatal_error = true;
                    }
                }

                if (Status result = flush_ciphertext(); !result) {
                    return result;
                }
                if (result > 0) {
                    return {};
                }
                if (ssl_error == SSL_ERROR_WANT_READ) {
                    if (ciphertext_eof) {
                        return std::unexpected(error);
                    }
                    if (Result<bool> result = recv_ciphertext(); !result) {
                        return std::unexpected(result.error());
                    } else {
                        ciphertext_eof = !*result;
                    }
                    continue;
                }
                if (ssl_error == SSL_ERROR_WANT_WRITE) {
                    continue;
                }
                return std::unexpected(error);
            }
        }

        Status SecureConnection::ssl_accept() {
            SSL_set_accept_state(ssl);
            return handshake("accept SSL connection");
        }

        Status SecureConnection::close(int protocol_layers) {
            if (ssl) {
                if ((protocol_layers & PN_PROTOCOL_LAYER_SSL) && !ssl_fatal_error) SSL_shutdown(ssl);
                BIO_free(std::exchange(ciphertext_recv_bio, nullptr));
                BIO_free(std::exchange(ciphertext_send_bio, nullptr));
                SSL_free(std::exchange(ssl, nullptr));
                pending_ciphertext.clear();
                pending_ciphertext_cursor = 0;
                ssl_fatal_error = false;
            }
            return Connection::close(protocol_layers);
        }

        Result<size_t> SecureConnection::send(const void* plaintext, size_t len) {
            if (!ssl) {
                return Connection::send(plaintext, len);
            }

            std::unique_lock<std::mutex> ssl_retry_lock(ssl_retry_mutex, std::defer_lock);
            std::unique_lock<std::mutex> ssl_write_lock(ssl_write_mutex, std::defer_lock);
            for (bool ciphertext_eof = false;;) {
                int result;
                int ssl_error = SSL_ERROR_NONE;
                Error error;
                if (!ssl_write_lock.owns_lock()) {
                    ssl_write_lock.lock();
                }
                if (!ssl_retry_lock.owns_lock()) {
                    ssl_retry_lock.lock();
                }
                {
                    std::lock_guard<std::mutex> lock(ssl_mutex);
                    ERR_clear_error();
                    result = SSL_write(ssl, plaintext, len);
                    if (result <= 0) {
                        ssl_error = SSL_get_error(ssl, result);
                        error = detail::make_io_error(ssl_error, "send SSL data");
                        if (ssl_error == SSL_ERROR_SSL || ssl_error == SSL_ERROR_SYSCALL) {
                            ssl_fatal_error = true;
                        }
                    }
                }

                if (ssl_error != SSL_ERROR_WANT_WRITE) {
                    ssl_retry_lock.unlock();
                }
                if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE) {
                    ssl_write_lock.unlock();
                }

                if (Status result = flush_ciphertext(); !result) {
                    return std::unexpected(result.error());
                }
                if (result > 0) {
                    return result;
                }
                if (ssl_error == SSL_ERROR_WANT_READ) {
                    if (ciphertext_eof) {
                        return std::unexpected(error);
                    }
                    if (Result<bool> result = recv_ciphertext(); !result) {
                        return std::unexpected(result.error());
                    } else {
                        ciphertext_eof = !*result;
                    }
                    continue;
                }
                if (ssl_error == SSL_ERROR_WANT_WRITE) {
                    continue;
                }
                return std::unexpected(error);
            }
        }

        Result<size_t> SecureConnection::read_plaintext(void* plaintext, size_t len, bool peek, StringView operation) {
            if (!ssl) {
                return peek ? Connection::peek(plaintext, len) : Connection::recv(plaintext, len);
            }

            std::unique_lock<std::mutex> lock(ssl_retry_mutex, std::defer_lock);
            for (bool ciphertext_eof = false;;) {
                int result;
                int ssl_error = SSL_ERROR_NONE;
                Error error;
                if (!lock.owns_lock()) {
                    lock.lock();
                }
                {
                    std::lock_guard<std::mutex> lock(ssl_mutex);
                    ERR_clear_error();
                    result = peek ? SSL_peek(ssl, plaintext, len) : SSL_read(ssl, plaintext, len);
                    if (result <= 0) {
                        ssl_error = SSL_get_error(ssl, result);
                        if (ssl_error != SSL_ERROR_ZERO_RETURN) {
                            error = detail::make_io_error(ssl_error, operation);
                        }
                        if (ssl_error == SSL_ERROR_SSL || ssl_error == SSL_ERROR_SYSCALL) {
                            ssl_fatal_error = true;
                        }
                    }
                }

                if (ssl_error != SSL_ERROR_WANT_WRITE) {
                    lock.unlock();
                }

                if (Status result = flush_ciphertext(); !result) {
                    return std::unexpected(result.error());
                }
                if (result > 0) {
                    return result;
                }
                if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                    return 0;
                }
                if (ssl_error == SSL_ERROR_WANT_READ) {
                    if (ciphertext_eof) {
                        return std::unexpected(error);
                    }
                    if (Result<bool> result = recv_ciphertext(); !result) {
                        return std::unexpected(result.error());
                    } else {
                        ciphertext_eof = !*result;
                    }
                    continue;
                }
                if (ssl_error == SSL_ERROR_WANT_WRITE) {
                    continue;
                }
                return std::unexpected(error);
            }
        }

        Result<size_t> SecureConnection::recv(void* plaintext, size_t len) {
            return read_plaintext(plaintext, len, false, "receive SSL data");
        }

        Result<size_t> SecureConnection::peek(void* plaintext, size_t len) {
            return read_plaintext(plaintext, len, true, "peek SSL data");
        }

        Status SecureServer::ssl_init(StringView certificate_chain_file, StringView private_key_file, int private_key_file_type) {
            if (ssl_ctx) {
                return std::unexpected(make_polynet_error(PN_ERROR_ALREADY_INITIALIZED, "create SSL context"));
            }

            if (SSL_CTX* new_ssl_ctx = SSL_CTX_new(TLS_server_method()); !new_ssl_ctx) {
                return std::unexpected(make_last_ssl_error("create SSL context"));
            } else {
                SSL_CTX_set_quiet_shutdown(new_ssl_ctx, 1);

                if (SSL_CTX_use_certificate_chain_file(new_ssl_ctx, certificate_chain_file.c_str()) != 1) {
                    Error error = make_last_ssl_error("load SSL certificate chain");
                    SSL_CTX_free(new_ssl_ctx);
                    return std::unexpected(error);
                }
                if (SSL_CTX_use_PrivateKey_file(new_ssl_ctx, private_key_file.c_str(), private_key_file_type) != 1) {
                    Error error = make_last_ssl_error("load SSL private key");
                    SSL_CTX_free(new_ssl_ctx);
                    return std::unexpected(error);
                }

                ssl_ctx = new_ssl_ctx;
                return {};
            }
        }

        Status SecureServer::listen(const std::function<bool(connection_type)>& cb, int backlog) { // This function BLOCKS
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
            if (ssl_ctx || ssl) {
                return std::unexpected(make_polynet_error(PN_ERROR_ALREADY_INITIALIZED, "create SSL connection"));
            }

            if (SSL_CTX* new_ssl_ctx = SSL_CTX_new(TLS_client_method()); !new_ssl_ctx) {
                return std::unexpected(make_last_ssl_error("create SSL context"));
            } else {
                SSL_CTX_set_quiet_shutdown(new_ssl_ctx, 1);

                SSL_CTX_set_verify(new_ssl_ctx, verify_mode, nullptr);
                if (verify_mode != SSL_VERIFY_NONE) {
                    if (ca_file.empty() && ca_path.empty()) {
#ifdef _WIN32
                        if (!SSL_CTX_load_verify_store(new_ssl_ctx, "org.openssl.winstore://")) {
#else
                        if (!SSL_CTX_set_default_verify_paths(new_ssl_ctx)) {
#endif
                            Error error = make_last_ssl_error("load SSL trust store");
                            SSL_CTX_free(new_ssl_ctx);
                            return std::unexpected(error);
                        }
                    } else if (!SSL_CTX_load_verify_locations(new_ssl_ctx, ca_file.empty() ? nullptr : ca_file.c_str(), ca_path.empty() ? nullptr : ca_path.c_str())) {
                        Error error = make_last_ssl_error("load SSL trust store");
                        SSL_CTX_free(new_ssl_ctx);
                        return std::unexpected(error);
                    }
                }

                if (Status result = BasicClient<SecureConnection, SOCK_STREAM, IPPROTO_TCP>::ssl_init(new_ssl_ctx); !result) {
                    SSL_CTX_free(new_ssl_ctx);
                    return result;
                }

                if (!SSL_set_tlsext_host_name(ssl, hostname.c_str())) {
                    Error error = make_last_ssl_error("set SSL hostname");
                    (void) SecureConnection::close();
                    SSL_CTX_free(new_ssl_ctx);
                    return std::unexpected(error);
                }
                if (!SSL_set1_host(ssl, hostname.c_str())) {
                    Error error = make_last_ssl_error("set SSL hostname");
                    (void) SecureConnection::close();
                    SSL_CTX_free(new_ssl_ctx);
                    return std::unexpected(error);
                }

                ssl_ctx = new_ssl_ctx;
                return {};
            }
        }

        Status SecureClient::ssl_connect() {
            SSL_set_connect_state(ssl);
            return handshake("connect SSL connection");
        }
    } // namespace tcp
} // namespace pn
