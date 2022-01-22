#ifndef _POLYNET_HPP
#define _POLYNET_HPP

// Network includes
#ifdef _WIN32
// See http://stackoverflow.com/questions/12765743/getaddrinfo-on-win32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501 // Windows XP
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

// Other includes
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <functional>
#include <iostream>
#include <ostream>
#include <string>

// Bridged constants
#ifndef _WIN32
#define PN_ERROR -1

#define PN_SD_RECEIVE SHUT_RD
#define PN_SD_SEND    SHUT_WR
#define PN_SD_BOTH    SHUT_RDWR
#else
#define PN_ERROR SOCKET_ERROR

#ifndef ssize_t
#define ssize_t SSIZE_T
#endif

#define PN_SD_RECEIVE SD_RECEIVE
#define PN_SD_SEND    SD_SEND
#define PN_SD_BOTH    SD_BOTH
#endif
#define PN_OK 0

// General error categories
#define PN_ESUCCESS  0
#define PN_ESOCKET   1
#define PN_EAI       2
#define PN_EBADADDRS 3

namespace pn {
#ifndef _WIN32
    typedef int sockfd_t;
    typedef ::socklen_t socklen_t;
#else
    typedef SOCKET sockfd_t;
    typedef int socklen_t;
#endif

    namespace detail {
        thread_local int last_error;        // NOLINT
        thread_local int last_gai_error;    // NOLINT
        thread_local int last_socket_error; // NOLINT

        inline void set_last_error(int error) {
            last_error = error;
        }

        inline void set_last_gai_error(int error) {
            last_gai_error = error;
        }

        inline void set_last_socket_error(int error) {
            last_socket_error = error;
        }

        // Returns last WSA error on Windows
        inline int get_last_system_error(void) {
#ifdef _WIN32
            return WSAGetLastError();
#else
            return errno;
#endif
        }

        inline int closesocket(sockfd_t fd) {
#ifdef _WIN32
            return ::closesocket(fd);
#else
            return close(fd);
#endif
        }
    } // namespace detail

#ifdef _WIN32
    WSADATA wsa_data; // NOLINT
#endif

    // This function is special. It DIRECTLY RETURNS the value of WSAStartup, which is either 0 (OK) or an error
    template <typename T = std::ostream>
    inline int init(bool banner = false, T& out = std::cerr) {
        if (banner) {
            out << "█▀▀█ █▀▀█ █   █  █ █▀▀▄ █▀▀ ▀▀█▀▀\n"
                   "█▄▄█ █  █ █   █▄▄█ █  █ █▀▀   █  \n"
                   "█    ▀▀▀▀ ▀▀▀ ▄▄▄█ ▀  ▀ ▀▀▀   ▀  \n";
        }

#ifdef _WIN32
        return WSAStartup(MAKEWORD(2, 2), &wsa_data);
#else
        return PN_OK;
#endif
    }

    // This function does not share the special properties of pn::init
    inline int quit(void) {
#ifdef _WIN32
        int result;
        if ((result = WSACleanup()) == PN_ERROR) {
            detail::set_last_socket_error(detail::get_last_system_error());
            detail::set_last_error(PN_ESOCKET);
        }
        return result;
#else
        return PN_OK;
#endif
    }

    const char* strerror(int error) { // NOLINT
        static const char* error_strings[] = {
            "Success"                                        // PN_ESUCCESS
            "Socket error",                                  // PN_ESOCKET
            "getaddrinfo failed",                            // PN_EAI
            "All addresses returned by getaddrinfo are bad", // PN_EBADADDRS
        };

        return error_strings[error];
    }

    inline int get_last_error(void) {
        return detail::last_error;
    }

    const char* socket_strerror(int error) { // NOLINT
#ifdef _WIN32
        static thread_local char error_string[256];
        memset(error_string, 0, sizeof(error_string));

        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            error,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            error_string,
            sizeof(error_string),
            NULL);

        for (unsigned int i = 0; i < sizeof(error_string); i++) {
            if (error_string[i] == '\n') {
                if (error_string[i + 1] == '\0') {
                    error_string[i] = '\0';
                    break;
                } else {
                    error_string[i] = ' ';
                }
            }
        }

        return error_string;
#else
        return ::strerror(error);
#endif
    }

    inline int get_last_socket_error(void) {
        return detail::last_socket_error;
    }

    inline const char* gai_strerror(int error) {
#ifdef _WIN32
        return socket_strerror(error);
#else
        return ::gai_strerror(error);
#endif
    }

    inline int get_last_gai_error(void) {
        return detail::last_gai_error;
    }

    inline int getaddrinfo(const std::string& host, const std::string& port, const struct addrinfo* hints, struct addrinfo** ret) {
        int result;
        if ((result = ::getaddrinfo(host.c_str(), port.c_str(), hints, ret)) != PN_OK) {
            detail::set_last_error(PN_EAI);
            detail::set_last_gai_error(result);
            return PN_ERROR;
        }
        return result;
    }

    inline int getaddrinfo(const std::string& host, unsigned short port, const struct addrinfo* hints, struct addrinfo** ret) {
        std::string str_port = std::to_string(port);
        return getaddrinfo(host, str_port, hints, ret);
    }

    inline void freeaddrinfo(struct addrinfo* ai) {
        ::freeaddrinfo(ai);
    }

    class Socket {
    public:
        sockfd_t fd;
        struct sockaddr addr; // Corresponds to the address to which
        socklen_t addrlen;    // the server is bound to for servers,
                              // or the server to which the client is
                              // connected to for clients

        Socket(void) = default;
        Socket(sockfd_t fd) :
            fd(fd) { }
        Socket(struct sockaddr addr, socklen_t addrlen) :
            addr(addr),
            addrlen(addrlen) { }
        Socket(sockfd_t fd, struct sockaddr addr, socklen_t addrlen) :
            fd(fd),
            addr(addr),
            addrlen(addrlen) { }

        inline int setsockopt(int level, int optname, const char* optval, socklen_t optlen) {
            int result;
            if ((result = ::setsockopt(this->fd, level, optname, optval, optlen)) == PN_ERROR) {
                detail::set_last_socket_error(detail::get_last_system_error());
                detail::set_last_error(PN_ESOCKET);
            }
            return result;
        }

        inline int getsockopt(int level, int optname, char* optval, socklen_t* optlen) {
            int result;
            if ((result = ::getsockopt(this->fd, level, optname, optval, optlen)) == PN_ERROR) {
                detail::set_last_socket_error(detail::get_last_system_error());
                detail::set_last_error(PN_ESOCKET);
            }
            return result;
        }

        inline int shutdown(int how) {
            int result;
            if ((result = ::shutdown(this->fd, how)) == PN_ERROR) {
                detail::set_last_socket_error(detail::get_last_system_error());
                detail::set_last_error(PN_ESOCKET);
            }
            return result;
        }

        inline int close(void) {
            int result;
            if ((result = detail::closesocket(this->fd)) == PN_ERROR) {
                detail::set_last_socket_error(detail::get_last_system_error());
                detail::set_last_error(PN_ESOCKET);
            }
            return result;
        }
    };

    template <class Base, int Socktype, int Protocol>
    class Server: public Base {
    public:
        Server(void) = default;
        Server(sockfd_t fd) :
            Base(fd) { }
        Server(struct sockaddr addr, socklen_t addrlen) :
            Base(addr, addrlen) { }
        Server(sockfd_t fd, struct sockaddr addr, socklen_t addrlen) :
            Base(fd, addr, addrlen) { }

        int bind(const std::string& host, const std::string& port) {
            struct addrinfo* ai_list;
            struct addrinfo hints = {0};
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = Socktype;
            hints.ai_protocol = Protocol;
            hints.ai_flags = AI_PASSIVE;

            if (getaddrinfo(host, port, &hints, &ai_list) == PN_ERROR) {
                return PN_ERROR;
            }

            struct addrinfo* ai_it;
            for (ai_it = ai_list; ai_it != NULL; ai_it = ai_it->ai_next) {
#ifndef _WIN32
                if ((this->fd = socket(ai_it->ai_family, ai_it->ai_socktype, ai_it->ai_protocol)) == PN_ERROR) {
#else
                if ((this->fd = socket(ai_it->ai_family, ai_it->ai_socktype, ai_it->ai_protocol)) == INVALID_SOCKET) {
#endif
                    continue;
                }

                {
                    int value = 1;
                    if (Base::setsockopt(SOL_SOCKET, SO_REUSEADDR, (char*) &value, sizeof(value)) == PN_ERROR) {
                        pn::freeaddrinfo(ai_list);
                        return PN_ERROR;
                    }
                }

                if (::bind(this->fd, ai_it->ai_addr, ai_it->ai_addrlen) == PN_OK) {
                    break;
                }

                if (detail::closesocket(this->fd) == PN_ERROR) {
                    detail::set_last_socket_error(detail::get_last_system_error());
                    detail::set_last_error(PN_ESOCKET);
                    pn::freeaddrinfo(ai_list);
                    return PN_ERROR;
                }
            }

            if (ai_it == NULL) {
                detail::set_last_error(PN_EBADADDRS);
                pn::freeaddrinfo(ai_list);
                return PN_ERROR;
            }
            this->addr = *ai_it->ai_addr;
            this->addrlen = ai_it->ai_addrlen;

            pn::freeaddrinfo(ai_list);
            return PN_OK;
        }

        inline int bind(const std::string& host, unsigned short port) {
            std::string str_port = std::to_string(port);
            return bind(host, str_port);
        }

        int bind(struct sockaddr* addr, socklen_t addrlen) {
#ifndef _WIN32
            if ((this->fd = socket(addr->sa_family, Socktype, Protocol)) == PN_ERROR) {
#else
            if ((this->fd = socket(addr->sa_family, Socktype, Protocol)) == INVALID_SOCKET) {
#endif
                detail::set_last_socket_error(detail::get_last_system_error());
                detail::set_last_error(PN_ESOCKET);
                return PN_ERROR;
            }

            {
                int value = 1;
                if (Base::setsockopt(SOL_SOCKET, SO_REUSEADDR, (char*) &value, sizeof(value)) == PN_ERROR) {
                    return PN_ERROR;
                }
            }

            if (::bind(this->fd, addr, addrlen) == PN_ERROR) {
                detail::set_last_socket_error(detail::get_last_system_error());
                detail::set_last_error(PN_ESOCKET);
                return PN_ERROR;
            }

            return PN_OK;
        }
    };

    template <class Base, int Socktype, int Protocol>
    class Client: public Base {
    public:
        Client(void) = default;
        Client(sockfd_t fd) :
            Base(fd) { }
        Client(struct sockaddr addr, socklen_t addrlen) :
            Base(addr, addrlen) { }
        Client(sockfd_t fd, struct sockaddr addr, socklen_t addrlen) :
            Base(fd, addr, addrlen) { }

        int connect(const std::string& host, const std::string& port) {
            struct addrinfo* ai_list;
            struct addrinfo hints = {0};
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = Socktype;
            hints.ai_protocol = Protocol;
            hints.ai_flags = AI_PASSIVE;

            if (getaddrinfo(host, port, &hints, &ai_list) == PN_ERROR) {
                return PN_ERROR;
            }

            struct addrinfo* ai_it;
            for (ai_it = ai_list; ai_it != NULL; ai_it = ai_it->ai_next) {
#ifndef _WIN32
                if ((this->fd = socket(ai_it->ai_family, ai_it->ai_socktype, ai_it->ai_protocol)) == PN_ERROR) {
#else
                if ((this->fd = socket(ai_it->ai_family, ai_it->ai_socktype, ai_it->ai_protocol)) == INVALID_SOCKET) {
#endif
                    continue;
                }

                if (::connect(this->fd, ai_it->ai_addr, ai_it->ai_addrlen) == PN_OK) {
                    break;
                }

                if (detail::closesocket(this->fd) == PN_ERROR) {
                    detail::set_last_socket_error(detail::get_last_system_error());
                    detail::set_last_error(PN_ESOCKET);
                    pn::freeaddrinfo(ai_list);
                    return PN_ERROR;
                }
            }

            if (ai_it == NULL) {
                detail::set_last_error(PN_EBADADDRS);
                pn::freeaddrinfo(ai_list);
                return PN_ERROR;
            }
            this->addr = *ai_it->ai_addr;
            this->addrlen = ai_it->ai_addrlen;

            pn::freeaddrinfo(ai_list);
            return PN_OK;
        }

        inline int connect(const std::string& host, unsigned short port) {
            std::string str_port = std::to_string(port);
            return connect(host, str_port);
        }

        int connect(struct sockaddr* addr, socklen_t addrlen) {
#ifndef _WIN32
            if ((this->fd = socket(addr->sa_family, Socktype, Protocol)) == PN_ERROR) {
#else
            if ((this->fd = socket(addr->sa_family, Socktype, Protocol)) == INVALID_SOCKET) {
#endif
                detail::set_last_socket_error(detail::get_last_system_error());
                detail::set_last_error(PN_ESOCKET);
                return PN_ERROR;
            }

            if (::connect(this->fd, addr, addrlen) == PN_ERROR) {
                detail::set_last_socket_error(detail::get_last_system_error());
                detail::set_last_error(PN_ESOCKET);
                return PN_ERROR;
            }

            return PN_OK;
        }
    };

    namespace tcp {
        class Connection: public Socket {
        public:
            Connection(void) = default;
            Connection(sockfd_t fd) :
                Socket(fd) { }
            Connection(struct sockaddr addr, socklen_t addrlen) :
                Socket(addr, addrlen) { }
            Connection(sockfd_t fd, struct sockaddr addr, socklen_t addrlen) :
                Socket(fd, addr, addrlen) { }

            inline ssize_t send(const char* buf, size_t len, int flags = 0) {
                ssize_t result;
                if ((result = ::send(this->fd, buf, len, flags)) == PN_ERROR) {
                    detail::set_last_socket_error(detail::get_last_system_error());
                    detail::set_last_error(PN_ESOCKET);
                }
                return result;
            }

            inline ssize_t recv(char* buf, size_t len, int flags = 0) {
                ssize_t result;
                if ((result = ::recv(this->fd, buf, len, flags)) == PN_ERROR) {
                    detail::set_last_socket_error(detail::get_last_system_error());
                    detail::set_last_error(PN_ESOCKET);
                }
                return result;
            }
        };

        class Server: public pn::Server<pn::Socket, SOCK_STREAM, IPPROTO_TCP> {
        protected:
            int backlog = -1;

        public:
            Server(void) = default;
            Server(sockfd_t fd) :
                pn::Server<pn::Socket, SOCK_STREAM, IPPROTO_TCP>(fd) { }
            Server(struct sockaddr addr, socklen_t addrlen) :
                pn::Server<pn::Socket, SOCK_STREAM, IPPROTO_TCP>(addr, addrlen) { }
            Server(sockfd_t fd, struct sockaddr addr, socklen_t addrlen) :
                pn::Server<pn::Socket, SOCK_STREAM, IPPROTO_TCP>(fd, addr, addrlen) { }

            int listen(const std::function<bool(Connection, void*)>& cb, int backlog, void* data = NULL) { // This function BLOCKS
                if (this->backlog == -1 || this->backlog != backlog) {
                    if (::listen(this->fd, backlog) == PN_ERROR) {
                        detail::set_last_socket_error(detail::get_last_system_error());
                        detail::set_last_error(PN_ESOCKET);
                        return PN_ERROR;
                    }
                    this->backlog = backlog;
                }

                for (;;) {
                    struct sockaddr peer_addr;
                    socklen_t peer_addr_size = sizeof(peer_addr);
                    sockfd_t cfd;
#ifndef _WIN32
                    if ((cfd = accept(this->fd, &peer_addr, &peer_addr_size)) == PN_ERROR) {
#else
                    if ((cfd = accept(this->fd, &peer_addr, &peer_addr_size)) == INVALID_SOCKET) {
#endif
                        detail::set_last_socket_error(detail::get_last_system_error());
                        detail::set_last_error(PN_ESOCKET);
                        return PN_ERROR;
                    }

                    if (!cb(Connection(cfd, peer_addr, peer_addr_size), data)) { // Connections CANNOT be accepted while the callback is blocking
                        break;
                    }
                }

                return PN_OK;
            }
        };

        using Client = pn::Client<Connection, SOCK_STREAM, IPPROTO_TCP>;
    } // namespace tcp

    namespace udp {
        class Socket: public pn::Socket {
        public:
            Socket(void) = default;
            Socket(sockfd_t fd) :
                pn::Socket(fd) { }
            Socket(struct sockaddr addr, socklen_t addrlen) :
                pn::Socket(addr, addrlen) { }
            Socket(sockfd_t fd, struct sockaddr addr, socklen_t addrlen) :
                pn::Socket(fd, addr, addrlen) { }

            inline ssize_t sendto(const char* buf, size_t len, const struct sockaddr* dest_addr, socklen_t addrlen, int flags = 0) {
                ssize_t result;
                if ((result = ::sendto(this->fd, buf, len, flags, dest_addr, addrlen)) == PN_ERROR) {
                    detail::set_last_socket_error(detail::get_last_system_error());
                    detail::set_last_error(PN_ESOCKET);
                }
                return result;
            }

            inline ssize_t recvfrom(char* buf, size_t len, struct sockaddr* src_addr, socklen_t* addrlen, int flags = 0) {
                ssize_t result;
                if ((result = ::recvfrom(this->fd, buf, len, flags, src_addr, addrlen)) == PN_ERROR) {
                    detail::set_last_socket_error(detail::get_last_system_error());
                    detail::set_last_error(PN_ESOCKET);
                }
                return result;
            }
        };

        using Server = pn::Server<pn::udp::Socket, SOCK_DGRAM, IPPROTO_UDP>;
        using Client = pn::Client<pn::udp::Socket, SOCK_DGRAM, IPPROTO_UDP>;
    } // namespace udp
} // namespace pn

#endif