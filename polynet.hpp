#ifndef _POLYNET_HPP
#define _POLYNET_HPP

// Network includes
#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN

    #ifndef _WIN32_WINNT
        #define _WIN32_WINNT 0x0502 // Windows Server 2003
    #endif

    #include <winsock2.h>
    #include <ws2tcpip.h>

    #pragma comment(lib, "ws2_32.lib")
#else
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <netinet/ip.h>
    #include <netinet/ip6.h>
    #include <netinet/tcp.h>
    #include <netinet/udp.h>
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
#include <utility>

// Bridged constants
#ifdef _WIN32
    #define PN_ERROR          SOCKET_ERROR
    #define PN_INVALID_SOCKFD INVALID_SOCKET

    #ifndef ssize_t
        #define ssize_t SSIZE_T
    #endif

    #define PN_SD_RECEIVE SD_RECEIVE
    #define PN_SD_SEND    SD_SEND
    #define PN_SD_BOTH    SD_BOTH
#else
    #define PN_ERROR          -1
    #define PN_INVALID_SOCKFD PN_ERROR

    #define PN_SD_RECEIVE SHUT_RD
    #define PN_SD_SEND    SHUT_WR
    #define PN_SD_BOTH    SHUT_RDWR
#endif
#define PN_OK 0

// General error categories
#define PN_ESUCCESS  0
#define PN_ESOCKET   1
#define PN_EAI       2
#define PN_EBADADDRS 3

namespace pn {
#ifdef _WIN32
    typedef SOCKET sockfd_t;
    typedef int socklen_t;
#else
    typedef int sockfd_t;
    typedef ::socklen_t socklen_t;
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
        if (WSACleanup() == PN_ERROR) {
            detail::set_last_socket_error(detail::get_last_system_error());
            detail::set_last_error(PN_ESOCKET);
        }
        return PN_OK;
#else
        return PN_OK;
#endif
    }

    const char* strerror(int error) { // NOLINT
        static const char* error_strings[] = {
            "Success",                                       // PN_ESUCCESS
            "Socket error",                                  // PN_ESOCKET
            "getaddrinfo failed",                            // PN_EAI
            "All addresses returned by getaddrinfo are bad", // PN_EBADADDRS
        };

        if (error >= 0 && error < 4) {
            return error_strings[error];
        } else {
            return "Unknown error";
        }
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

        for (size_t i = 0; i < sizeof(error_string); i++) {
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

    std::string universal_strerror(int error = get_last_error()) { // NOLINT
        std::string base_error = strerror(error);
        std::string specific_error;

        switch (error) {
            case PN_ESOCKET: {
                specific_error = socket_strerror(get_last_socket_error());
                break;
            }

            case PN_EAI: {
                specific_error = gai_strerror(get_last_gai_error());
                break;
            }

            default: {
                return base_error;
            }
        }

        return base_error + ": " + specific_error;
    }

    inline int getaddrinfo(const std::string& host, const std::string& port, const struct addrinfo* hints, struct addrinfo** ret) {
        int result;
        if ((result = ::getaddrinfo(host.c_str(), port.c_str(), hints, ret)) != PN_OK) {
            detail::set_last_gai_error(result);
            detail::set_last_error(PN_EAI);
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
        sockfd_t fd = PN_INVALID_SOCKFD;
        struct sockaddr addr = {0};       // Corresponds to the address to which
        socklen_t addrlen = sizeof(addr); // the server is bound to for servers,
                                          // or the server to which the client is
                                          // connected to for clients

        Socket(void) = default;
        Socket(const Socket&) = default;
        Socket(Socket&& s) {
            *this = std::move(s);
        }
        Socket(sockfd_t fd) :
            fd(fd) { }
        Socket(struct sockaddr addr, socklen_t addrlen) :
            addr(addr),
            addrlen(addrlen) { }
        Socket(sockfd_t fd, struct sockaddr addr, socklen_t addrlen) :
            fd(fd),
            addr(addr),
            addrlen(addrlen) { }

        Socket& operator=(const Socket&) = default;
        inline Socket& operator=(Socket&& s) {
            if (this != &s) {
                this->close(true, false);

                this->fd = s.fd;
                this->addr = s.addr;
                this->addrlen = s.addrlen;

                s.fd = PN_INVALID_SOCKFD;
                s.addr = {0};
                s.addrlen = sizeof(s.addr);
            }

            return *this;
        }

        ~Socket(void) {
            this->close(true, false);
        }

        inline int setsockopt(int level, int optname, const char* optval, socklen_t optlen) {
            if (::setsockopt(this->fd, level, optname, optval, optlen) == PN_ERROR) {
                detail::set_last_socket_error(detail::get_last_system_error());
                detail::set_last_error(PN_ESOCKET);
            }
            return PN_OK;
        }

        inline int getsockopt(int level, int optname, char* optval, socklen_t* optlen) {
            if (::getsockopt(this->fd, level, optname, optval, optlen) == PN_ERROR) {
                detail::set_last_socket_error(detail::get_last_system_error());
                detail::set_last_error(PN_ESOCKET);
            }
            return PN_OK;
        }

        inline int shutdown(int how) {
            if (::shutdown(this->fd, how) == PN_ERROR) {
                detail::set_last_socket_error(detail::get_last_system_error());
                detail::set_last_error(PN_ESOCKET);
            }
            return PN_OK;
        }

        // By default, the closed socket file descriptor is LOST if this function executes successfully
        inline int close(bool validity_check = true, bool reset_fd = true) {
            if (validity_check) {
                if (!this->is_valid()) {
                    return PN_OK;
                }
            }

            if (detail::closesocket(this->fd) == PN_ERROR) {
                detail::set_last_socket_error(detail::get_last_system_error());
                detail::set_last_error(PN_ESOCKET);
            } else if (reset_fd) {
                this->fd = PN_INVALID_SOCKFD;
            }

            return PN_OK;
        }

        inline sockfd_t release(void) {
            sockfd_t old_fd = this->fd;
            this->fd = PN_INVALID_SOCKFD;
            return old_fd;
        }

        inline bool is_valid(void) const {
            return this->fd != PN_INVALID_SOCKFD;
        }
    };

    template <class Base, int Socktype, int Protocol>
    class Server: public Base {
    public:
        Server(void) = default;
        Server(const Server&) = default;
        Server(Server&& s) {
            *this = std::move(s);
        }
        Server(sockfd_t fd) :
            Base(fd) { }
        Server(struct sockaddr addr, socklen_t addrlen) :
            Base(addr, addrlen) { }
        Server(sockfd_t fd, struct sockaddr addr, socklen_t addrlen) :
            Base(fd, addr, addrlen) { }

        Server& operator=(const Server&) = default;
        inline Server& operator=(Server&& s) {
            Base::operator=(std::move(s));
            return *this;
        }

        int bind(const std::string& host, const std::string& port) {
            struct addrinfo* ai_list;
            struct addrinfo hints = {0};
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = Socktype;
            hints.ai_protocol = Protocol;

            if (getaddrinfo(host, port, &hints, &ai_list) == PN_ERROR) {
                return PN_ERROR;
            }

            struct addrinfo* ai_it;
            for (ai_it = ai_list; ai_it != NULL; ai_it = ai_it->ai_next) {
                if ((this->fd = socket(ai_it->ai_family, ai_it->ai_socktype, ai_it->ai_protocol)) == PN_INVALID_SOCKFD) {
                    continue;
                }

                {
                    const int value = 1;
                    if (Base::setsockopt(SOL_SOCKET, SO_REUSEADDR, (const char*) &value, sizeof(int)) == PN_ERROR) {
                        pn::freeaddrinfo(ai_list);
                        return PN_ERROR;
                    }
                }

                if (::bind(this->fd, ai_it->ai_addr, ai_it->ai_addrlen) == PN_OK) {
                    break;
                }

                if (Base::close() == PN_ERROR) {
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
            if ((this->fd = socket(addr->sa_family, Socktype, Protocol)) == PN_INVALID_SOCKFD) {
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
            this->addr = *addr;
            this->addrlen = addrlen;

            return PN_OK;
        }
    };

    template <class Base, int Socktype, int Protocol>
    class Client: public Base {
    public:
        Client(void) = default;
        Client(const Client&) = default;
        Client(Client&& s) {
            *this = std::move(s);
        }
        Client(sockfd_t fd) :
            Base(fd) { }
        Client(struct sockaddr addr, socklen_t addrlen) :
            Base(addr, addrlen) { }
        Client(sockfd_t fd, struct sockaddr addr, socklen_t addrlen) :
            Base(fd, addr, addrlen) { }

        Client& operator=(const Client&) = default;
        inline Client& operator=(Client&& s) {
            Base::operator=(std::move(s));
            return *this;
        }

        int connect(const std::string& host, const std::string& port) {
            struct addrinfo* ai_list;
            struct addrinfo hints = {0};
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = Socktype;
            hints.ai_protocol = Protocol;

            if (getaddrinfo(host, port, &hints, &ai_list) == PN_ERROR) {
                return PN_ERROR;
            }

            struct addrinfo* ai_it;
            for (ai_it = ai_list; ai_it != NULL; ai_it = ai_it->ai_next) {
                if ((this->fd = socket(ai_it->ai_family, ai_it->ai_socktype, ai_it->ai_protocol)) == PN_INVALID_SOCKFD) {
                    continue;
                }

                if (::connect(this->fd, ai_it->ai_addr, ai_it->ai_addrlen) == PN_OK) {
                    break;
                }

                if (Base::close() == PN_ERROR) {
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
            if ((this->fd = socket(addr->sa_family, Socktype, Protocol)) == PN_INVALID_SOCKFD) {
                detail::set_last_socket_error(detail::get_last_system_error());
                detail::set_last_error(PN_ESOCKET);
                return PN_ERROR;
            }

            if (::connect(this->fd, addr, addrlen) == PN_ERROR) {
                detail::set_last_socket_error(detail::get_last_system_error());
                detail::set_last_error(PN_ESOCKET);
                return PN_ERROR;
            }
            this->addr = *addr;
            this->addrlen = addrlen;

            return PN_OK;
        }
    };

    namespace tcp {
        class Connection: public Socket {
        public:
            Connection(void) = default;
            Connection(const Connection&) = default;
            Connection(Connection&& s) {
                *this = std::move(s);
            }
            Connection(sockfd_t fd) :
                Socket(fd) { }
            Connection(struct sockaddr addr, socklen_t addrlen) :
                Socket(addr, addrlen) { }
            Connection(sockfd_t fd, struct sockaddr addr, socklen_t addrlen) :
                Socket(fd, addr, addrlen) { }

            Connection& operator=(const Connection&) = default;
            inline Connection& operator=(Connection&& s) {
                Socket::operator=(std::move(s));
                return *this;
            }

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
            Server(const Server&) = default;
            Server(Server&& s) {
                *this = std::move(s);
            }
            Server(sockfd_t fd) :
                pn::Server<pn::Socket, SOCK_STREAM, IPPROTO_TCP>(fd) { }
            Server(struct sockaddr addr, socklen_t addrlen) :
                pn::Server<pn::Socket, SOCK_STREAM, IPPROTO_TCP>(addr, addrlen) { }
            Server(sockfd_t fd, struct sockaddr addr, socklen_t addrlen) :
                pn::Server<pn::Socket, SOCK_STREAM, IPPROTO_TCP>(fd, addr, addrlen) { }

            Server& operator=(const Server&) = default;
            inline Server& operator=(Server&& s) {
                pn::Server<pn::Socket, SOCK_STREAM, IPPROTO_TCP>::operator=(std::move(s));
                if (this != &s) {
                    this->backlog = s.backlog;
                    s.backlog = -1;
                }

                return *this;
            }

            // Return false from the callback to stop listening
            int listen(const std::function<bool(Connection&, void*)>& cb, int backlog, void* data = NULL) { // This function BLOCKS
                if (this->backlog != backlog || this->backlog == -1) {
                    if (::listen(this->fd, backlog) == PN_ERROR) {
                        detail::set_last_socket_error(detail::get_last_system_error());
                        detail::set_last_error(PN_ESOCKET);
                        return PN_ERROR;
                    }
                    this->backlog = backlog;
                }

                for (;;) {
                    Connection conn;
                    if ((conn.fd = accept(this->fd, &conn.addr, &conn.addrlen)) == PN_INVALID_SOCKFD) {
                        detail::set_last_socket_error(detail::get_last_system_error());
                        detail::set_last_error(PN_ESOCKET);
                        return PN_ERROR;
                    }

                    if (!cb(conn, data)) { // Connections CANNOT be accepted while the callback is blocking
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
            Socket(const Socket&) = default;
            Socket(Socket&& s) :
                pn::Socket(std::move(s)) { }
            Socket(sockfd_t fd) :
                pn::Socket(fd) { }
            Socket(struct sockaddr addr, socklen_t addrlen) :
                pn::Socket(addr, addrlen) { }
            Socket(sockfd_t fd, struct sockaddr addr, socklen_t addrlen) :
                pn::Socket(fd, addr, addrlen) { }

            Socket& operator=(const Socket&) = default;
            inline Socket& operator=(Socket&& s) {
                pn::Socket::operator=(std::move(s));
                return *this;
            }

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
