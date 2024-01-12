#ifndef _POLYNET_SECURE_SOCKS_HPP
#define _POLYNET_SECURE_SOCKS_HPP

#ifndef POLYNET_SECURE_SOCKS
    #error Secure sockets are not enabled
#endif

#include "polynet.hpp"
#include <openssl/err.h>
#include <openssl/ssl.h>

namespace pn {
    namespace detail {
        extern thread_local unsigned long last_security_error;

        inline void set_last_security_error(unsigned long error) {
            last_security_error = error;
        }

        inline unsigned long get_last_openssl_error() {
            return ERR_get_error();
        }
    } // namespace detail

    inline unsigned long get_last_security_error() {
        return detail::last_security_error;
    }

    std::string security_strerror(unsigned long error = get_last_security_error());

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

            int secure_init(SSL_CTX* ssl_ctx, const char* hostname = nullptr);

            inline int secure_connect() {
                if (SSL_connect(ssl) <= 0) {
                    detail::set_last_socket_error(detail::get_last_openssl_error());
                    detail::set_last_error(PN_ESECURITY);
                    return PN_ERROR;
                }
                return PN_OK;
            }

            inline long send(const void* buf, size_t len) override {
                int result;
                if ((result = SSL_write(this->ssl, buf, len)) <= 0) {
                    detail::set_last_socket_error(detail::get_last_openssl_error());
                    detail::set_last_error(PN_ESECURITY);
                    return PN_ERROR;
                }
                return result;
            }

            long sendall(const void* buf, size_t len) override;

            inline long recv(void* buf, size_t len) override {
                int result;
                if ((result = SSL_read(this->ssl, buf, len)) < 0) {
                    detail::set_last_socket_error(detail::get_last_openssl_error());
                    detail::set_last_error(PN_ESECURITY);
                }
                return result;
            }

            inline long peek(void* buf, size_t len) override {
                int result;
                if ((result = SSL_peek(this->ssl, buf, len)) < 0) {
                    detail::set_last_socket_error(detail::get_last_openssl_error());
                    detail::set_last_error(PN_ESECURITY);
                }
                return result;
            }

            long recvall(void* buf, size_t len) override;
        };

        // class SecureServer : public Server {
        // };
    } // namespace tcp
} // namespace pn

#endif
