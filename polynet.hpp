#ifndef POLYNET_HPP_
#define POLYNET_HPP_

// System includes
#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #define NOMINMAX

    #ifndef WINVER
        #define WINVER 0x0A00
    #endif
    #ifndef _WIN32_WINNT
        #define _WIN32_WINNT 0x0A00
    #endif

    #include <windows.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>

    #pragma comment(lib, "ws2_32.lib")
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
    #include <stdint.h>
    #include <sys/socket.h>
    #include <unistd.h>
#endif

// Other includes
#include "string.hpp"
#include <functional>
#include <iostream>
#include <stddef.h>
#include <string.h>
#include <string>
#include <utility>
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

    #if BYTE_ORDER == BIG_ENDIAN
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

// Protocol layers
#define PN_PROTOCOL_LAYER_DEFAULT 0x0000FFFF // The lower half of the protocol layers bitmask is reserved
#define PN_PROTOCOL_LAYER_SYSTEM  1          // for protocol layers that are closed by default, while the upper
                                             // half is for those that aren't

// Errors
#define PN_ESUCCESS  0
#define PN_ESOCKET   1
#define PN_EAI       2
#define PN_EBADADDRS 3
#define PN_EPTON     4
#define PN_ESSL      5
#define PN_EUSERCB   6

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
#ifdef _WIN32
            out << "\x1b[1m+--+ +--+ |   |  | +--. +-- -----\x1b[0m\n"
                   "\x1b[1m|__| |  | |   +--| |  | |--   |  \x1b[0m\n"
                   "\x1b[1m|    +--+ +-- ___| |  | +--   |  \x1b[0m\n";
#else
            out << "█▀▀█ █▀▀█ █   █  █ █▀▀▄ █▀▀ ▀▀█▀▀\n"
                   "█▄▄█ █  █ █   █▄▄█ █  █ █▀▀   █  \n"
                   "█    ▀▀▀▀ ▀▀▀ ▄▄▄█ ▀  ▀ ▀▀▀   ▀  \n";
#endif
        }

#ifdef _WIN32
        if (int result = WSAStartup(MAKEWORD(2, 2), &wsa_data); result != PN_OK) {
            detail::set_last_socket_error(result);
            detail::set_last_error(PN_ESOCKET);
            return PN_ERROR;
        }
#else
        if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
            detail::set_last_socket_error(detail::get_last_system_error());
            detail::set_last_error(PN_ESOCKET);
            return PN_ERROR;
        }
#endif
        return PN_OK;
    }

    int quit();

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

    std::string universal_strerror();

    inline int getaddrinfo(StringView hostname, StringView port, const struct addrinfo* hints, struct addrinfo** ret) {
        if (int result = ::getaddrinfo(hostname.c_str(), port.c_str(), hints, ret); result != PN_OK) {
            detail::set_last_gai_error(result);
            detail::set_last_error(PN_EAI);
            return PN_ERROR;
        }
        return PN_OK;
    }

    inline int getaddrinfo(StringView hostname, unsigned short port, const struct addrinfo* hints, struct addrinfo** ret) {
        std::string str_port = std::to_string(port);
        return getaddrinfo(hostname, str_port, hints, ret);
    }

    inline void freeaddrinfo(struct addrinfo* ai) {
        ::freeaddrinfo(ai);
    }

    inline int getnameinfo(const struct sockaddr* sockaddr, socklen_t addrlen, std::string& hostname, std::string& port, int flags) {
        hostname.resize(NI_MAXHOST);
        port.resize(NI_MAXSERV);
        if (int result = ::getnameinfo(sockaddr, addrlen, &hostname[0], NI_MAXHOST, &port[0], NI_MAXSERV, flags); result != PN_OK) {
            detail::set_last_gai_error(result);
            detail::set_last_error(PN_EAI);
            return PN_ERROR;
        }
        hostname.resize(strlen(hostname.data()));
        port.resize(strlen(port.data()));
        return PN_OK;
    }

    inline int inet_pton(int af, StringView src, void* ret) {
        if (int result = ::inet_pton(af, src.c_str(), ret); !result) {
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
        Socket(const Socket&) = default;
        Socket(Socket&& socket) {
            *this = std::move(socket);
        }

        Socket& operator=(const Socket&) = default;

        Socket& operator=(Socket&& socket) {
            if (this != &socket) {
                fd = socket.fd;
                addr = socket.addr;
                addrlen = socket.addrlen;

                socket.fd = PN_INVALID_SOCKFD;
                socket.addr = {0};
                socket.addrlen = sizeof socket.addr;
            }
            return *this;
        }

        // Don't use this if you are using bind or connect on pn::Server or pn::Client, respectively
        int init(int domain, int type, int protocol) {
            if ((fd = socket(domain, type, protocol)) == PN_INVALID_SOCKFD) {
                detail::set_last_socket_error(detail::get_last_system_error());
                detail::set_last_error(PN_ESOCKET);
                return PN_ERROR;
            }
            return PN_OK;
        }

        int setsockopt(int level, int optname, const void* optval, socklen_t optlen) {
            if (::setsockopt(fd, level, optname, (const char*) optval, optlen) == PN_ERROR) {
                detail::set_last_socket_error(detail::get_last_system_error());
                detail::set_last_error(PN_ESOCKET);
                return PN_ERROR;
            }
            return PN_OK;
        }

        int getsockopt(int level, int optname, void* optval, socklen_t* optlen) {
            if (::getsockopt(fd, level, optname, (char*) optval, optlen) == PN_ERROR) {
                detail::set_last_socket_error(detail::get_last_system_error());
                detail::set_last_error(PN_ESOCKET);
                return PN_ERROR;
            }
            return PN_OK;
        }

        int shutdown(int how) {
            if (::shutdown(fd, how) == PN_ERROR) {
                detail::set_last_socket_error(detail::get_last_system_error());
                detail::set_last_error(PN_ESOCKET);
                return PN_ERROR;
            }
            return PN_OK;
        }

        // By default, the closed socket file descriptor is LOST if this function executes successfully
        virtual int close(bool reset = true, int protocol_layers = PN_PROTOCOL_LAYER_DEFAULT) {
            if (!is_valid()) {
                return PN_OK;
            }

            if ((protocol_layers & PN_PROTOCOL_LAYER_SYSTEM) && detail::closesocket(fd) == PN_ERROR) {
                detail::set_last_socket_error(detail::get_last_system_error());
                detail::set_last_error(PN_ESOCKET);
                return PN_ERROR;
            }
            if (reset) fd = PN_INVALID_SOCKFD;
            return PN_OK;
        }

        virtual bool is_secure() const {
            return false;
        }

        bool is_valid() const {
            return fd != PN_INVALID_SOCKFD;
        }

        operator bool() const {
            return is_valid();
        }

        bool operator==(const Socket& socket) const {
            return fd == socket.fd;
        }

        bool operator!=(const Socket& socket) const {
            return fd != socket.fd;
        }
    };

    template <class Base, int Socktype, int Protocol>
    class BasicServer : public Base {
    public:
        template <typename... Args>
        BasicServer(Args&&... args):
            Base(std::forward<Args>(args)...) {}

        int bind(StringView hostname, StringView port) {
            struct addrinfo* ai_list;
            struct addrinfo hints = {0};
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = Socktype;
            hints.ai_protocol = Protocol;
#ifdef AI_IDN
            hints.ai_flags = AI_IDN;
#endif

            if (getaddrinfo(hostname, port, &hints, &ai_list) == PN_ERROR) {
                return PN_ERROR;
            }

            struct addrinfo* ai_it;
            for (ai_it = ai_list; ai_it != nullptr; ai_it = ai_it->ai_next) {
                if (this->init(ai_it->ai_family, ai_it->ai_socktype, ai_it->ai_protocol) == PN_ERROR) {
                    continue;
                }

                {
                    static constexpr int value = 1;
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

        int bind(StringView hostname, unsigned short port) {
            return bind(hostname, std::to_string(port));
        }

        int bind(const struct sockaddr* addr, socklen_t addrlen) {
            if (this->init(addr->sa_family, Socktype, Protocol) == PN_ERROR) {
                return PN_ERROR;
            }

            {
                static constexpr int value = 1;
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
        template <typename... Args>
        BasicClient(Args&&... args):
            Base(std::forward<Args>(args)...) {}

        int connect(StringView hostname, StringView port, const std::function<bool(pn::BasicClient<Base, Socktype, Protocol>&)>& config_cb = {}) {
            struct addrinfo* ai_list;
            struct addrinfo hints = {0};
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = Socktype;
            hints.ai_protocol = Protocol;
#ifdef AI_IDN
            hints.ai_flags = AI_IDN;
#endif

            if (getaddrinfo(hostname, port, &hints, &ai_list) == PN_ERROR) {
                return PN_ERROR;
            }

            struct addrinfo* ai_it;
            for (ai_it = ai_list; ai_it != nullptr; ai_it = ai_it->ai_next) {
                if (this->init(ai_it->ai_family, ai_it->ai_socktype, ai_it->ai_protocol) == PN_ERROR) {
                    continue;
                }

                if (config_cb && !config_cb(*this)) {
                    detail::set_last_error(PN_EUSERCB);
                    pn::freeaddrinfo(ai_list);
                    return PN_ERROR;
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

        int connect(StringView hostname, unsigned short port, const std::function<bool(pn::BasicClient<Base, Socktype, Protocol>&)>& config_cb = {}) {
            return connect(hostname, std::to_string(port), config_cb);
        }

        int connect(const struct sockaddr* addr, socklen_t addrlen, const std::function<bool(pn::BasicClient<Base, Socktype, Protocol>&)>& config_cb = {}) {
            if (this->init(addr->sa_family, Socktype, Protocol) == PN_ERROR) {
                return PN_ERROR;
            }

            if (config_cb && !config_cb(*this)) {
                detail::set_last_error(PN_EUSERCB);
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

            virtual long send(const void* buf, size_t len) {
                for (;;) {
                    long result;
                    if ((result = ::send(fd, (const char*) buf, len, 0)) == PN_ERROR) {
#ifndef _WIN32
                        if (detail::get_last_system_error() == EINTR) {
                            continue;
                        }
#endif

                        detail::set_last_socket_error(detail::get_last_system_error());
                        detail::set_last_error(PN_ESOCKET);
                    }
                    return result;
                }
            }

            virtual long sendall(const void* buf, size_t len);

            virtual long recv(void* buf, size_t len) {
                for (;;) {
                    long result;
                    if ((result = ::recv(fd, (char*) buf, len, 0)) == PN_ERROR) {
#ifndef _WIN32
                        if (detail::get_last_system_error() == EINTR) {
                            continue;
                        }
#endif

                        detail::set_last_socket_error(detail::get_last_system_error());
                        detail::set_last_error(PN_ESOCKET);
                    }
                    return result;
                }
            }

            virtual long peek(void* buf, size_t len) {
                for (;;) {
                    long result;
                    if ((result = ::recv(fd, (char*) buf, len, MSG_PEEK)) == PN_ERROR) {
#ifndef _WIN32
                        if (detail::get_last_system_error() == EINTR) {
                            continue;
                        }
#endif

                        detail::set_last_socket_error(detail::get_last_system_error());
                        detail::set_last_error(PN_ESOCKET);
                    }
                    return result;
                }
            }

            virtual long recvall(void* buf, size_t len);
        };

        class BufReceiver {
        protected:
            size_t cursor = 0;
            std::vector<char> buf;

            void clear() {
                buf.clear();
                cursor = 0;
            }

        public:
            size_t capacity;

            BufReceiver(size_t capacity = 4'000):
                capacity(capacity) {}
            BufReceiver(BufReceiver&& buf_receiver) {
                *this = std::move(buf_receiver);
            }

            BufReceiver& operator=(BufReceiver&& buf_receiver) {
                if (this != &buf_receiver) {
                    cursor = buf_receiver.cursor;
                    buf = std::move(buf_receiver.buf);
                    capacity = buf_receiver.capacity;

                    buf_receiver.cursor = 0;
                    buf_receiver.capacity = 4'000;
                }
                return *this;
            }

            size_t available() const {
                return buf.size() - cursor;
            }

            long recv(Connection& conn, void* ret, size_t len);
            long peek(Connection& conn, void* ret, size_t len);
            long recvall(Connection& conn, void* ret, size_t len);

            void rewind(const void* data, size_t len);
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
            Server(const Server&) = default;
            Server(Server&& server) {
                *this = std::move(server);
            }

            Server& operator=(const Server&) = default;

            Server& operator=(Server&& server) {
                if (this != &server) {
                    BasicServer<Socket, SOCK_STREAM, IPPROTO_TCP>::operator=(std::move(server));
                    backlog = server.backlog;

                    server.backlog = -1;
                }
                return *this;
            }

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

            virtual long sendto(const void* buf, size_t len, const struct sockaddr* dest_addr, socklen_t addrlen, int flags = 0) {
                for (;;) {
                    long result;
                    if ((result = ::sendto(fd, (const char*) buf, len, flags, dest_addr, addrlen)) == PN_ERROR) {
#ifndef _WIN32
                        if (detail::get_last_system_error() == EINTR) {
                            continue;
                        }
#endif

                        detail::set_last_socket_error(detail::get_last_system_error());
                        detail::set_last_error(PN_ESOCKET);
                    }
                    return result;
                }
            }

            virtual long recvfrom(void* buf, size_t len, struct sockaddr* src_addr, socklen_t* addrlen, int flags = 0) {
                for (;;) {
                    long result;
                    if ((result = ::recvfrom(fd, (char*) buf, len, flags, src_addr, addrlen)) == PN_ERROR) {
#ifndef _WIN32
                        if (detail::get_last_system_error() == EINTR) {
                            continue;
                        }
#endif

                        detail::set_last_socket_error(detail::get_last_system_error());
                        detail::set_last_error(PN_ESOCKET);
                    }
                    return result;
                }
            }
        };

        using Server = BasicServer<pn::udp::Socket, SOCK_DGRAM, IPPROTO_UDP>;
        using Client = BasicClient<pn::udp::Socket, SOCK_DGRAM, IPPROTO_UDP>;
    } // namespace udp
} // namespace pn

#endif
