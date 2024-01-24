#ifndef _POLYNET_HPP
#define _POLYNET_HPP

// Network includes
#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN

    #ifndef _WIN32_WINNT
        #define _WIN32_WINNT _WIN32_WINNT_WIN8 // This is a reasonable default
    #endif

    #include <basetsd.h>
    #include <windef.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>

    #if defined(_MSC_VER) || defined(__clang__) || defined(__INTEL_COMPILER)
        #pragma comment(lib, "ws2_32.lib")
    #endif
#else
    #include <arpa/inet.h>
    #include <errno.h>
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
#endif

// Other includes
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <ostream>
#include <string>
#include <vector>
#if __has_include(<endian.h>)
    #include <endian.h>
#elif __has_include(<machine/endian.h>)
    #include <machine/endian.h>
#else
    #define LITTLE_ENDIAN 1234
    #define BIG_ENDIAN    4321
    #define PDP_ENDIAN    3412
    #define BYTE_ORDER    LITTLE_ENDIAN
#endif

#define PN_OK 0

// Bridged
#ifdef _WIN32
    #define PN_ERROR          SOCKET_ERROR
    #define PN_INVALID_SOCKFD INVALID_SOCKET

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
        #ifndef ntohll
            #define ntohll(num) (num)
        #endif
        #ifndef htonll
            #define htonll(num) (num)
        #endif
    #else
        #ifndef ntohll
            #define ntohll(num) ({                                    \
                uint64_t _num = num;                                  \
                (((uint64_t) ntohl(_num)) << 32) | ntohl(_num >> 32); \
            })
        #endif
        #ifndef htonll
            #define htonll(num) ({                                    \
                uint64_t _num = num;                                  \
                (((uint64_t) htonl(_num)) << 32) | htonl(_num >> 32); \
            })
        #endif
    #endif
#endif

// Errors
#define PN_ESUCCESS  0
#define PN_ESOCKET   1
#define PN_EAI       2
#define PN_EBADADDRS 3
#define PN_EPTON     4
#define PN_ESSL      5

namespace pn {
#ifdef _WIN32
    typedef SOCKET sockfd_t;
#else
    typedef int sockfd_t;
#endif

    namespace detail {
        extern thread_local int last_error;
        extern thread_local int last_socket_error;
        extern thread_local int last_gai_error;

        inline void set_last_error(int error) {
            last_error = error;
        }

        inline void set_last_socket_error(int error) {
            last_socket_error = error;
        }

        inline void set_last_gai_error(int error) {
            last_gai_error = error;
        }

        // Returns last Winsock error on Windows
        inline int get_last_system_error() {
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

    inline int quit() {
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

    inline int get_last_error() {
        return detail::last_error;
    }

    std::string strerror(int error = get_last_error());

    inline int get_last_socket_error() {
        return detail::last_socket_error;
    }

    // Invalid error numbers are not tolerated
    std::string socket_strerror(int error = get_last_socket_error());

    inline int get_last_gai_error() {
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

    inline int getaddrinfo(const std::string& hostname, const std::string& port, const struct addrinfo* hints, struct addrinfo** ret) {
        int result;
        if ((result = ::getaddrinfo(hostname.c_str(), port.c_str(), hints, ret)) != PN_OK) {
            detail::set_last_gai_error(result);
            detail::set_last_error(PN_EAI);
            return PN_ERROR;
        }
        return result;
    }

    inline int getaddrinfo(const std::string& hostname, unsigned short port, const struct addrinfo* hints, struct addrinfo** ret) {
        std::string str_port = std::to_string(port);
        return getaddrinfo(hostname, str_port, hints, ret);
    }

    inline void freeaddrinfo(struct addrinfo* ai) {
        ::freeaddrinfo(ai);
    }

    inline int getnameinfo(const struct sockaddr* sockaddr, socklen_t addrlen, std::string& hostname, std::string& port, int flags) {
        int result;
        hostname.resize(NI_MAXHOST);
        port.resize(NI_MAXSERV);
        if ((result = ::getnameinfo(sockaddr, addrlen, &hostname[0], NI_MAXHOST, &port[0], NI_MAXSERV, flags)) != PN_OK) {
            detail::set_last_gai_error(result);
            detail::set_last_error(PN_EAI);
            return PN_ERROR;
        }
        hostname.resize(strlen(hostname.c_str()));
        port.resize(strlen(port.c_str()));
        return result;
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

    inline int inet_ntop(int af, const void* src, std::string& ret) {
        ret.resize(INET6_ADDRSTRLEN);
        if (::inet_ntop(af, src, &ret[0], INET6_ADDRSTRLEN) == nullptr) {
            detail::set_last_socket_error(detail::get_last_system_error());
            detail::set_last_error(PN_ESOCKET);
            return PN_ERROR;
        }
        ret.resize(strlen(ret.c_str()));
        return PN_OK;
    }

    class Socket {
    public:
        sockfd_t fd = PN_INVALID_SOCKFD;
        struct sockaddr addr = {0};      // Corresponds to the address to which
        socklen_t addrlen = sizeof addr; // the server is bound to for servers,
                                         // or the server to which the client is
                                         // connected to for clients

        Socket() = default;
        Socket(sockfd_t fd):
            fd(fd) {}
        Socket(const struct sockaddr& addr, socklen_t addrlen):
            addr(addr),
            addrlen(addrlen) {}
        Socket(sockfd_t fd, const struct sockaddr& addr, socklen_t addrlen):
            fd(fd),
            addr(addr),
            addrlen(addrlen) {}

        // Don't use this if you are using bind or connect on pn::Server or pn::Client, respectively
        inline int init(int domain, int type, int protocol) {
            if ((this->fd = socket(domain, type, protocol)) == PN_INVALID_SOCKFD) {
                detail::set_last_socket_error(detail::get_last_system_error());
                detail::set_last_error(PN_ESOCKET);
                return PN_ERROR;
            }
            return PN_OK;
        }

        inline int setsockopt(int level, int optname, const void* optval, socklen_t optlen) {
            if (::setsockopt(this->fd, level, optname, (const char*) optval, optlen) == PN_ERROR) {
                detail::set_last_socket_error(detail::get_last_system_error());
                detail::set_last_error(PN_ESOCKET);
                return PN_ERROR;
            }
            return PN_OK;
        }

        inline int getsockopt(int level, int optname, void* optval, socklen_t* optlen) {
            if (::getsockopt(this->fd, level, optname, (char*) optval, optlen) == PN_ERROR) {
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
        inline virtual int close(bool reset_fd = true, bool validity_check = true) {
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

        inline bool is_valid() const {
            return this->fd != PN_INVALID_SOCKFD;
        }

        inline operator bool() const {
            return is_valid();
        }

        inline bool operator==(const Socket& socket) const {
            return this->fd == socket.fd;
        }

        inline bool operator!=(const Socket& socket) const {
            return this->fd != socket.fd;
        }
    };

    template <class Base, int Socktype, int Protocol>
    class BasicServer : public Base {
    public:
        template <typename... Ts>
        BasicServer(Ts... args):
            Base(args...) {}

        int bind(const std::string& hostname, const std::string& port) {
            struct addrinfo* ai_list;
            struct addrinfo hints = {0};
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = Socktype;
            hints.ai_protocol = Protocol;

            if (getaddrinfo(hostname, port, &hints, &ai_list) == PN_ERROR) {
                return PN_ERROR;
            }

            struct addrinfo* ai_it;
            for (ai_it = ai_list; ai_it != nullptr; ai_it = ai_it->ai_next) {
                if (this->init(ai_it->ai_family, ai_it->ai_socktype, ai_it->ai_protocol) == PN_ERROR) {
                    continue;
                }

                {
                    const int value = 1;
                    if (Base::setsockopt(SOL_SOCKET, SO_REUSEADDR, &value, sizeof(int)) == PN_ERROR) {
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
            if (ai_it == nullptr) {
                detail::set_last_error(PN_EBADADDRS);
                pn::freeaddrinfo(ai_list);
                return PN_ERROR;
            }

            this->addr = *ai_it->ai_addr;
            this->addrlen = ai_it->ai_addrlen;

            pn::freeaddrinfo(ai_list);
            return PN_OK;
        }

        inline int bind(const std::string& hostname, unsigned short port) {
            std::string str_port = std::to_string(port);
            return bind(hostname, str_port);
        }

        int bind(struct sockaddr* addr, socklen_t addrlen) {
            if (this->init(addr->sa_family, Socktype, Protocol) == PN_ERROR) {
                return PN_ERROR;
            }

            {
                const int value = 1;
                if (Base::setsockopt(SOL_SOCKET, SO_REUSEADDR, &value, sizeof(int)) == PN_ERROR) {
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
    class BasicClient : public Base {
    public:
        template <typename... Ts>
        BasicClient(Ts... args):
            Base(args...) {}

        int connect(const std::string& hostname, const std::string& port) {
            struct addrinfo* ai_list;
            struct addrinfo hints = {0};
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = Socktype;
            hints.ai_protocol = Protocol;

            if (getaddrinfo(hostname, port, &hints, &ai_list) == PN_ERROR) {
                return PN_ERROR;
            }

            struct addrinfo* ai_it;
            for (ai_it = ai_list; ai_it != nullptr; ai_it = ai_it->ai_next) {
                if (this->init(ai_it->ai_family, ai_it->ai_socktype, ai_it->ai_protocol) == PN_ERROR) {
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
            if (ai_it == nullptr) {
                detail::set_last_error(PN_EBADADDRS);
                pn::freeaddrinfo(ai_list);
                return PN_ERROR;
            }

            this->addr = *ai_it->ai_addr;
            this->addrlen = ai_it->ai_addrlen;

            pn::freeaddrinfo(ai_list);
            return PN_OK;
        }

        inline int connect(const std::string& hostname, unsigned short port) {
            std::string str_port = std::to_string(port);
            return connect(hostname, str_port);
        }

        int connect(const struct sockaddr* addr, socklen_t addrlen) {
            if (this->init(addr->sa_family, Socktype, Protocol) == PN_ERROR) {
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
        class Connection : public Socket {
        public:
            Connection() = default;
            Connection(sockfd_t fd):
                Socket(fd) {}
            Connection(const struct sockaddr& addr, socklen_t addrlen):
                Socket(addr, addrlen) {}
            Connection(sockfd_t fd, const struct sockaddr& addr, socklen_t addrlen):
                Socket(fd, addr, addrlen) {}

            virtual inline long send(const void* buf, size_t len) {
                long result;
                if ((result = ::send(this->fd, (const char*) buf, len, 0)) == PN_ERROR) {
                    detail::set_last_socket_error(detail::get_last_system_error());
                    detail::set_last_error(PN_ESOCKET);
                }
                return result;
            }

            virtual long sendall(const void* buf, size_t len);

            virtual inline long recv(void* buf, size_t len) {
                long result;
                if ((result = ::recv(this->fd, (char*) buf, len, 0)) == PN_ERROR) {
                    detail::set_last_socket_error(detail::get_last_system_error());
                    detail::set_last_error(PN_ESOCKET);
                }
                return result;
            }

            virtual inline long peek(void* buf, size_t len) {
                long result;
                if ((result = ::recv(this->fd, (char*) buf, len, MSG_PEEK)) == PN_ERROR) {
                    detail::set_last_socket_error(detail::get_last_system_error());
                    detail::set_last_error(PN_ESOCKET);
                }
                return result;
            }

            virtual long recvall(void* buf, size_t len);
        };

        class BufReceiver {
        protected:
            std::vector<char> buf;

        public:
            size_t size;

            BufReceiver(size_t size = 4'000):
                size(size) {}

            long recv(Connection& conn, void* buf, size_t len);
            long peek(Connection& conn, void* buf, size_t len);
            long recvall(Connection& conn, void* buf, size_t len);

            inline void rewind(const void* buf, size_t len) {
                this->buf.insert(this->buf.begin(), (const char*) buf, (const char*) buf + len);
            }
        };

        class Server : public BasicServer<Socket, SOCK_STREAM, IPPROTO_TCP> {
        protected:
            int backlog = -1;

        public:
            typedef Connection connection_type;

            Server() = default;
            Server(sockfd_t fd):
                BasicServer<Socket, SOCK_STREAM, IPPROTO_TCP>(fd) {}
            Server(const struct sockaddr& addr, socklen_t addrlen):
                BasicServer<Socket, SOCK_STREAM, IPPROTO_TCP>(addr, addrlen) {}
            Server(sockfd_t fd, const struct sockaddr& addr, socklen_t addrlen):
                BasicServer<Socket, SOCK_STREAM, IPPROTO_TCP>(fd, addr, addrlen) {}

            // Return false from the callback to stop listening
            int listen(const std::function<bool(connection_type&, void*)>& cb, int backlog = 128, void* data = nullptr);
        };

        using Client = BasicClient<Connection, SOCK_STREAM, IPPROTO_TCP>;
    } // namespace tcp

    namespace udp {
        class Socket : public pn::Socket {
        public:
            Socket() = default;
            Socket(sockfd_t fd):
                pn::Socket(fd) {}
            Socket(const struct sockaddr& addr, socklen_t addrlen):
                pn::Socket(addr, addrlen) {}
            Socket(sockfd_t fd, const struct sockaddr& addr, socklen_t addrlen):
                pn::Socket(fd, addr, addrlen) {}

            inline long sendto(const void* buf, size_t len, const struct sockaddr* dest_addr, socklen_t addrlen, int flags = 0) {
                long result;
                if ((result = ::sendto(this->fd, (const char*) buf, len, flags, dest_addr, addrlen)) == PN_ERROR) {
                    detail::set_last_socket_error(detail::get_last_system_error());
                    detail::set_last_error(PN_ESOCKET);
                }
                return result;
            }

            inline long recvfrom(void* buf, size_t len, struct sockaddr* src_addr, socklen_t* addrlen, int flags = 0) {
                long result;
                if ((result = ::recvfrom(this->fd, (char*) buf, len, flags, src_addr, addrlen)) == PN_ERROR) {
                    detail::set_last_socket_error(detail::get_last_system_error());
                    detail::set_last_error(PN_ESOCKET);
                }
                return result;
            }
        };

        using Server = BasicServer<pn::udp::Socket, SOCK_DGRAM, IPPROTO_UDP>;
        using Client = BasicClient<pn::udp::Socket, SOCK_DGRAM, IPPROTO_UDP>;
    } // namespace udp
} // namespace pn

#endif
