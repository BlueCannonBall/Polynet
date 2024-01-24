#ifndef _POLYNET_SECURE_SOCKETS_HPP
#define _POLYNET_SECURE_SOCKETS_HPP

#include "polynet.hpp"
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sys/socket.h>

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
        protected:
            SSL* ssl;

        public:
            SecureConnection() = default;
            SecureConnection(sockfd_t fd, SSL* ssl):
                Connection(fd),
                ssl(ssl) {}
            SecureConnection(const struct sockaddr& addr, socklen_t addrlen):
                Connection(addr, addrlen) {}
            SecureConnection(sockfd_t fd, SSL* ssl, const struct sockaddr& addr, socklen_t addrlen):
                Connection(fd, addr, addrlen),
                ssl(ssl) {}

            inline int ssl_init(SSL_CTX* ssl_ctx) {
                if (!(this->ssl = SSL_new(ssl_ctx))) {
                    detail::set_last_ssl_error(detail::get_last_ssl_error());
                    detail::set_last_error(PN_ESSL);
                    return PN_ERROR;
                }
                if (SSL_set_fd(this->ssl, this->fd) == 0) {
                    detail::set_last_ssl_error(detail::get_last_ssl_error());
                    detail::set_last_error(PN_ESSL);
                    return PN_ERROR;
                }
                return PN_OK;
            }

            inline int ssl_accept() {
                if (SSL_accept(ssl) <= 0) {
                    detail::set_last_ssl_error(detail::get_last_ssl_error());
                    detail::set_last_error(PN_ESSL);
                    return PN_ERROR;
                }
                return PN_OK;
            }

            int close(bool reset = true, bool validity_check = true) override {
                if (!validity_check || this->ssl) {
                    if (SSL_shutdown(this->ssl) < 0) {
                        detail::set_last_ssl_error(detail::get_last_ssl_error());
                        detail::set_last_error(PN_ESSL);
                        return PN_ERROR;
                    }
                    SSL_free(this->ssl);
                    if (reset) this->ssl = nullptr;
                }

                if (Connection::close(reset, validity_check) == PN_ERROR) {
                    return PN_ERROR;
                }

                return PN_OK;
            }

            inline long send(const void* buf, size_t len) override {
                int result;
                if ((result = SSL_write(this->ssl, buf, len)) <= 0) {
                    detail::set_last_ssl_error(detail::get_last_ssl_error());
                    detail::set_last_error(PN_ESSL);
                    return PN_ERROR;
                }
                return result;
            }

            long sendall(const void* buf, size_t len) override;

            inline long recv(void* buf, size_t len) override {
                int result;
                if ((result = SSL_read(this->ssl, buf, len)) < 0) {
                    detail::set_last_ssl_error(detail::get_last_ssl_error());
                    detail::set_last_error(PN_ESSL);
                }
                return result;
            }

            inline long peek(void* buf, size_t len) override {
                int result;
                if ((result = SSL_peek(this->ssl, buf, len)) < 0) {
                    detail::set_last_ssl_error(detail::get_last_ssl_error());
                    detail::set_last_error(PN_ESSL);
                }
                return result;
            }

            long recvall(void* buf, size_t len) override;
        };

        class SecureServer : public Server {
        protected:
            SSL_CTX* ssl_ctx = nullptr;

        public:
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

            int ssl_init(const std::string& certificate_chain_file, const std::string& private_key_file, int private_key_file_type);

            inline int close(bool reset = true, bool validity_check = true) override {
                if (!validity_check || this->ssl_ctx) {
                    SSL_CTX_free(this->ssl_ctx);
                    if (reset) this->ssl_ctx = nullptr;
                }

                if (Server::close(reset, validity_check) == PN_ERROR) {
                    return PN_ERROR;
                }

                return PN_OK;
            }

            int listen(const std::function<bool(connection_type&, void*)>& cb, int backlog = 128, void* data = nullptr);
        };

        class SecureClient : public BasicClient<SecureConnection, SOCK_STREAM, IPPROTO_TCP> {
        protected:
            SSL_CTX* ssl_ctx;

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

            int ssl_init(const std::string& hostname, int verify_mode = SSL_VERIFY_PEER, const std::string& ca_file = {}, const std::string& ca_path = {});

            inline int ssl_connect() {
                if (SSL_connect(ssl) <= 0) {
                    detail::set_last_ssl_error(detail::get_last_ssl_error());
                    detail::set_last_error(PN_ESSL);
                    return PN_ERROR;
                }
                return PN_OK;
            }
        };
    } // namespace tcp
} // namespace pn

#endif
