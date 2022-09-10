#ifndef _POLYNET_HPP
#define _POLYNET_HPP

// Network includes
#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN

    #ifndef _WIN32_WINNT
        #define _WIN32_WINNT _WIN32_WINNT_VISTA
    #endif

    #include <winsock2.h>
    #include <ws2tcpip.h>

    // Afaik the only Windows compilers that don't support this are GNU compilers
    #if (!defined(__GNUC__)) || defined(__clang__)
        #pragma comment(lib, "ws2_32.lib")
    #endif
#else
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <netinet/ip.h>
    #include <netinet/ip6.h>
    #include <netinet/tcp.h>
    #include <netinet/udp.h>
    #include <signal.h>
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <unistd.h>

    #if __has_include(<endian.h>)
        #include <endian.h>
    #elif __has_include(<machine/endian.h>)
        #include <machine/endian.h>
    #endif
#endif

// Other includes
#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdint>
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

    #if __BYTE_ORDER == __BIG_ENDIAN
        #ifndef htonll
            #define htonll(num) (num)
        #endif
        #ifndef ntohll
            #define ntohll(num) (num)
        #endif
    #else
        #ifndef htonll
            #define htonll(num) ({                                      \
                uint64_t _num = num;                                    \
                ((((uint64_t) htonl(_num)) << 32) | htonl(_num >> 32)); \
            })
        #endif
        #ifndef ntohll
            #define ntohll(num) ({                                      \
                uint64_t _num = num;                                    \
                ((((uint64_t) ntohl(_num)) << 32) | ntohl(_num >> 32)); \
            })
        #endif
    #endif
#endif
#define PN_OK 0

// General error categories
#define PN_ESUCCESS  0
#define PN_ESOCKET   1
#define PN_EAI       2
#define PN_EBADADDRS 3
#define PN_EPTON     4

namespace pn {
#ifdef _WIN32
    typedef SOCKET sockfd_t;
    typedef int socklen_t;
#else
    typedef int sockfd_t;
    typedef unsigned int socklen_t;
#endif
    typedef unsigned long ref_count_t;

    namespace detail {
        extern thread_local int last_error;
        extern thread_local int last_gai_error;
        extern thread_local int last_socket_error;

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
    extern WSADATA wsa_data;
#endif

    template <typename T = std::ostream>
    inline int init(bool banner = false, T& out = std::cerr) {
        if (banner) {
            out << "█▀▀█ █▀▀█ █   █  █ █▀▀▄ █▀▀ ▀▀█▀▀\n"
                   "█▄▄█ █  █ █   █▄▄█ █  █ █▀▀   █  \n"
                   "█    ▀▀▀▀ ▀▀▀ ▄▄▄█ ▀  ▀ ▀▀▀   ▀  \n";
        }

#ifdef _WIN32
        int result;
        if ((result = WSAStartup(MAKEWORD(2, 2), &wsa_data)) != PN_OK) {
            detail::set_last_socket_error(result);
            detail::set_last_error(PN_ESOCKET);
            return PN_ERROR;
        }
        return result;
#else
        if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
            detail::set_last_socket_error(detail::get_last_system_error());
            detail::set_last_error(PN_ESOCKET);
            return PN_ERROR;
        }
        return PN_OK;
#endif
    }

    inline int quit(void) {
#ifdef _WIN32
        if (WSACleanup() == PN_ERROR) {
            detail::set_last_socket_error(detail::get_last_system_error());
            detail::set_last_error(PN_ESOCKET);
            return PN_ERROR;
        }
        return PN_OK;
#else
        if (signal(SIGPIPE, SIG_DFL) == SIG_ERR) {
            detail::set_last_socket_error(detail::get_last_system_error());
            detail::set_last_error(PN_ESOCKET);
            return PN_ERROR;
        }
        return PN_OK;
#endif
    }

    inline int get_last_error(void) {
        return detail::last_error;
    }

    std::string strerror(int error = get_last_error());

    inline int get_last_socket_error(void) {
        return detail::last_socket_error;
    }

    std::string socket_strerror(int error = get_last_socket_error());

    inline int get_last_gai_error(void) {
        return detail::last_gai_error;
    }

    inline std::string gai_strerror(int error = get_last_gai_error()) {
#ifdef _WIN32
        return socket_strerror(error);
#else
        return ::gai_strerror(error);
#endif
    }

    std::string universal_strerror(int error = get_last_error());

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

    inline int inet_ntop(int af, const void* src, std::string& ret) {
        char result[128];
        if (::inet_ntop(af, src, result, sizeof(result)) == NULL) {
            detail::set_last_socket_error(detail::get_last_system_error());
            detail::set_last_error(PN_ESOCKET);
            return PN_ERROR;
        }
        ret = result;
        return PN_OK;
    }

    inline int inet_pton(int af, const std::string& src, void* ret) {
        int result;
        if ((result = ::inet_pton(af, src.c_str(), ret)) == 0) {
            detail::set_last_error(PN_EPTON);
            return PN_ERROR;
        } else if (result == -1) {
            detail::set_last_socket_error(detail::get_last_system_error());
            detail::set_last_error(PN_ESOCKET);
            return PN_ERROR;
        }
        return PN_OK;
    }

    class Socket {
    public:
        sockfd_t fd = PN_INVALID_SOCKFD;
        struct sockaddr addr = {0};       // Corresponds to the address to which
        socklen_t addrlen = sizeof(addr); // the server is bound to for servers,
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
            if (::setsockopt(this->fd, level, optname, optval, optlen) == PN_ERROR) {
                detail::set_last_socket_error(detail::get_last_system_error());
                detail::set_last_error(PN_ESOCKET);
                return PN_ERROR;
            }
            return PN_OK;
        }

        inline int getsockopt(int level, int optname, char* optval, socklen_t* optlen) {
            if (::getsockopt(this->fd, level, optname, optval, optlen) == PN_ERROR) {
                detail::set_last_socket_error(detail::get_last_system_error());
                detail::set_last_error(PN_ESOCKET);
                return PN_ERROR;
            }
            return PN_OK;
        }

        inline int shutdown(int how) {
            if (::shutdown(this->fd, how) == PN_ERROR) {
                detail::set_last_socket_error(detail::get_last_system_error());
                detail::set_last_error(PN_ESOCKET);
                return PN_ERROR;
            }
            return PN_OK;
        }

        // By default, the closed socket file descriptor is LOST if this function executes successfully
        inline int close(bool reset_fd = true, bool validity_check = true) {
            if (validity_check && !this->is_valid()) {
                return PN_OK;
            }

            if (detail::closesocket(this->fd) == PN_ERROR) {
                detail::set_last_socket_error(detail::get_last_system_error());
                detail::set_last_error(PN_ESOCKET);
                return PN_ERROR;
            } else if (reset_fd) {
                this->fd = PN_INVALID_SOCKFD;
            }

            return PN_OK;
        }

        inline bool is_valid(void) const {
            return this->fd != PN_INVALID_SOCKFD;
        }

        inline operator bool(void) const {
            return is_valid();
        }
    };

    // THIS IS JUST A BASE CLASS
    template <typename T>
    class BasicSock {
    protected:
        T sock;

    public:
        typedef T sock_type;

        inline const T& get(void) const {
            return sock;
        }

        inline T& get(void) {
            return sock;
        }

        inline const T& operator*(void) const {
            return sock;
        }

        inline T& operator*(void) {
            return sock;
        }

        inline const T* operator->(void) const {
            return &sock;
        }

        inline T* operator->(void) {
            return &sock;
        }

        inline bool is_valid(void) const {
            return sock.is_valid();
        }

        inline operator bool(void) const {
            return is_valid();
        }
    };

    template <typename T>
    class UniqueSock: public BasicSock<T> {
    public:
        UniqueSock(void) = default;
        UniqueSock(const T& sock) {
            *this = sock;
        }
        UniqueSock(UniqueSock<T>&& unique_sock) {
            *this = std::move(unique_sock);
        }

        inline UniqueSock<T>& operator=(const T& sock) {
            if (&this->sock != &sock) {
                this->sock.close(/* Reset fd */ false);
                this->sock = sock;
            }
            return *this;
        }

        inline UniqueSock<T>& operator=(UniqueSock<T>&& unique_sock) {
            if (this != &unique_sock) {
                this->sock.close(/* Reset fd */ false);
                this->sock = std::exchange(unique_sock.sock, T());
            }
            return *this;
        }

        inline ~UniqueSock(void) {
            this->sock.close(/* Reset fd */ false);
        }

        inline void reset(void) {
            this->sock.close(/* Reset fd */ false);
            this->sock = T();
        }
    };

    template <typename T>
    class SharedSock: public BasicSock<T> {
    protected:
        std::atomic<ref_count_t>* ref_count = NULL;

    public:
        SharedSock(void) = default;
        SharedSock(const T& sock) {
            *this = sock;
        }
        SharedSock(UniqueSock<T>&& unique_sock) {
            *this = unique_sock;
        }
        SharedSock(const SharedSock<T>& shared_sock) {
            *this = shared_sock;
        }
        SharedSock(SharedSock<T>&& shared_sock) {
            *this = std::move(shared_sock);
        }

        inline SharedSock<T>& operator=(const T& sock) {
            if (&this->sock != &sock) {
                if (this->ref_count && !(--(*this->ref_count))) {
                    this->sock.close(/* Reset fd */ false);
                    delete this->ref_count;
                }
                this->sock = sock;
                this->ref_count = new std::atomic<ref_count_t>(1);
            }
            return *this;
        }

        inline SharedSock<T>& operator=(UniqueSock<T>&& unique_sock) {
            if (&this->sock != &unique_sock.sock) {
                if (this->ref_count && !(--(*this->ref_count))) {
                    this->sock.close(/* Reset fd */ false);
                    delete this->ref_count;
                }
                this->sock = std::exchange(unique_sock.sock, T());
                this->ref_count = new std::atomic<ref_count_t>(1);
            }
            return *this;
        }

        inline SharedSock<T>& operator=(const SharedSock<T>& shared_sock) {
            if (this != &shared_sock) {
                if (this->ref_count && !(--(*this->ref_count))) {
                    this->sock.close(/* Reset fd */ false);
                    delete this->ref_count;
                }
                this->sock = shared_sock.sock;
                this->ref_count = shared_sock.ref_count;
                if (ref_count) {
                    (*ref_count)++;
                }
            }
            return *this;
        }

        inline SharedSock<T>& operator=(SharedSock<T>&& shared_sock) {
            if (this != &shared_sock) {
                if (this->ref_count && !(--(*this->ref_count))) {
                    this->sock.close(/* Reset fd */ false);
                    delete this->ref_count;
                }
                this->sock = std::exchange(shared_sock.sock, T());
                this->ref_count = std::exchange(shared_sock.ref_count, NULL);
            }
            return *this;
        }

        inline ~SharedSock(void) {
            if (ref_count && !(--(*ref_count))) {
                this->sock.close(/* Reset fd */ false);
                delete ref_count;
            }
        }

        inline void reset(void) {
            if (ref_count && !(--(*ref_count))) {
                this->sock.close(/* Reset fd */ false);
                delete ref_count;
            }
            this->sock = T();
            ref_count = NULL;
        }

        inline ref_count_t use_count(void) const {
            return *ref_count;
        }
    };

    template <typename T, typename... Ts>
    inline UniqueSock<T> make_unique(Ts... args) {
        return UniqueSock<T>(T(args...));
    }

    template <typename T, typename... Ts>
    inline SharedSock<T> make_shared(Ts... args) {
        return SharedSock<T>(T(args...));
    }

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

                if (Base::close(true, false) == PN_ERROR) {
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

                if (Base::close(true, false) == PN_ERROR) {
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

            // Return false from the callback to stop listening
            int listen(const std::function<bool(Connection&, void*)>& cb, int backlog = 128, void* data = NULL);
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
