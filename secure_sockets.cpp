#include "secure_sockets.hpp"
#include <openssl/err.h>

namespace pn {
    namespace detail {
        thread_local unsigned long last_security_error;
    }

    std::string security_strerror(unsigned long error) {
        return ERR_error_string(error, nullptr);
    }

    namespace tcp {
        int SecureConnection::secure_init(SSL_CTX* ssl_ctx, const char* hostname) {
            this->ssl = SSL_new(ssl_ctx);
            if (SSL_set_fd(ssl, this->fd) == 0) {
                detail::set_last_socket_error(detail::get_last_openssl_error());
                detail::set_last_error(PN_ESECURITY);
                return PN_ERROR;
            }

            if (hostname) {
                if (SSL_set_tlsext_host_name(ssl, hostname) == 0) {
                    detail::set_last_socket_error(detail::get_last_openssl_error());
                    detail::set_last_error(PN_ESECURITY);
                    return PN_ERROR;
                }
                if (SSL_set1_host(ssl, hostname) == 0) {
                    detail::set_last_socket_error(detail::get_last_openssl_error());
                    detail::set_last_error(PN_ESECURITY);
                    return PN_ERROR;
                }
            }

            return PN_OK;
        }

        ssize_t SecureConnection::sendall(const void* buf, size_t len) {
            size_t sent = 0;
            while (sent < len) {
                ssize_t result;
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
        }

        ssize_t SecureConnection::recvall(void* buf, size_t len) {
            size_t received = 0;
            while (received < len) {
                ssize_t result;
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
        }
    } // namespace tcp
} // namespace pn
