#ifndef POLYNET_HPP_
#define POLYNET_HPP_

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
    #include <stddef.h>
    #include <stdint.h>
    #include <sys/socket.h>
    #include <unistd.h>
#endif
#include "error.hpp"
#include "string.hpp"
#include <functional>
#include <iostream>
#include <string.h>
#include <string>
#include <type_traits>
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
#define PN_PROTOCOL_LAYER_DEFAULT 0x0000FFFF // The lower half of the bitmask is reserved for protocol
#define PN_PROTOCOL_LAYER_SYSTEM  1          // layers that are closed by default, while the upper half
                                             // is for those that aren't

namespace pn {
#ifdef _WIN32
    typedef SOCKET sockfd_t;
#else
    typedef int sockfd_t;
#endif
    typedef std::make_signed_t<size_t> ssize_t;

#ifdef _WIN32
    extern WSADATA wsa_data;
#endif

    namespace detail {
        inline int closesocket(sockfd_t fd) {
#ifdef _WIN32
            return ::closesocket(fd);
#else
            return close(fd);
#endif
        }
    } // namespace detail

    template <typename T = std::ostream>
    inline Status init(bool banner = false, T& out = std::cerr) {
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
            return std::unexpected(make_socket_error(result, "initialize Winsock"));
        }
#else
        if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
            return std::unexpected(make_last_socket_error("ignore SIGPIPE"));
        }
#endif
        return {};
    }

    Status quit();

    inline Status getaddrinfo(StringView hostname, StringView port, const struct addrinfo* hints, struct addrinfo** ret) {
        if (int result = ::getaddrinfo(hostname.c_str(), port.c_str(), hints, ret); result != PN_OK) {
            return std::unexpected(make_address_info_error(result, "resolve address"));
        }
        return {};
    }

    inline Status getaddrinfo(StringView hostname, unsigned short port, const struct addrinfo* hints, struct addrinfo** ret) {
        std::string str_port = std::to_string(port);
        return getaddrinfo(hostname, str_port, hints, ret);
    }

    inline void freeaddrinfo(struct addrinfo* ai) {
        ::freeaddrinfo(ai);
    }

    inline Status getnameinfo(const struct sockaddr* sockaddr, socklen_t addrlen, std::string& hostname, std::string& port, int flags) {
        hostname.resize(NI_MAXHOST);
        port.resize(NI_MAXSERV);
        if (int result = ::getnameinfo(sockaddr, addrlen, &hostname[0], NI_MAXHOST, &port[0], NI_MAXSERV, flags); result != PN_OK) {
            return std::unexpected(make_address_info_error(result, "resolve address"));
        }
        hostname.resize(strlen(hostname.data()));
        port.resize(strlen(port.data()));
        return {};
    }

    inline Status inet_pton(int af, StringView src, void* ret) {
        if (int result = ::inet_pton(af, src.c_str(), ret); result == 0) {
            return std::unexpected(make_polynet_error(PN_ERROR_INVALID_ADDRESS, "parse address"));
        } else if (result == -1) {
            return std::unexpected(make_last_socket_error("parse address"));
        }
        return {};
    }

    inline Status inet_ntop(int af, const void* src, std::string& ret) {
        ret.resize(INET6_ADDRSTRLEN);
        if (::inet_ntop(af, src, &ret[0], INET6_ADDRSTRLEN) == nullptr) {
            return std::unexpected(make_last_socket_error("format address"));
        }
        ret.resize(strlen(ret.c_str()));
        return {};
    }

    class Socket {
    public:
        sockfd_t fd = PN_INVALID_SOCKFD;
        struct sockaddr_storage addr = {}; // The address corresponds to the address to which
        socklen_t addrlen = sizeof addr;   // the server is bound to for servers, or the address
                                           // to which the client is connected to for clients

        Socket() = default;
        Socket(sockfd_t fd):
            fd(fd) {}
        Socket(sockfd_t fd, const struct sockaddr& addr, socklen_t addrlen):
            fd(fd),
            addrlen(addrlen) {
            memcpy(&this->addr, &addr, addrlen);
        }
        Socket(Socket&& socket) noexcept {
            *this = std::move(socket);
        }

        Socket& operator=(Socket&& socket) noexcept {
            if (this != &socket) {
                (void) close();
                fd = std::exchange(socket.fd, PN_INVALID_SOCKFD);
                addr = socket.addr;
                addrlen = socket.addrlen;
            }
            return *this;
        }

        virtual ~Socket() {
            (void) close();
        }

        // This socket must not already be initialized. Don't use this if you are using
        // bind or connect on pn::Server or pn::Client, respectively
        Status init(int domain, int type, int protocol) {
            if (is_valid()) {
                return std::unexpected(make_polynet_error(PN_ERROR_ALREADY_INITIALIZED, "create socket"));
            }

            if (sockfd_t fd = socket(domain, type, protocol); fd == PN_INVALID_SOCKFD) {
                return std::unexpected(make_last_socket_error("create socket"));
            } else {
                this->fd = fd;
                return {};
            }
        }

        Status setsockopt(int level, int optname, const void* optval, socklen_t optlen) {
            if (::setsockopt(fd, level, optname, (const char*) optval, optlen) == PN_ERROR) {
                return std::unexpected(make_last_socket_error("set socket option"));
            }
            return {};
        }

        Status getsockopt(int level, int optname, void* optval, socklen_t* optlen) const {
            if (::getsockopt(fd, level, optname, (char*) optval, optlen) == PN_ERROR) {
                return std::unexpected(make_last_socket_error("get socket option"));
            }
            return {};
        }

        Status shutdown(int how) {
            if (::shutdown(fd, how) == PN_ERROR) {
                return std::unexpected(make_last_socket_error("shut down socket"));
            }
            return {};
        }

        // By default, this function gives up ownership of the socket file descriptor
        virtual Status close(int protocol_layers = PN_PROTOCOL_LAYER_DEFAULT) {
            if (!is_valid()) {
                return {};
            }

            if ((protocol_layers & PN_PROTOCOL_LAYER_SYSTEM) && detail::closesocket(std::exchange(this->fd, PN_INVALID_SOCKFD)) == PN_ERROR) {
                return std::unexpected(make_last_socket_error("close socket"));
            }
            return {};
        }

        bool is_valid() const {
            return fd != PN_INVALID_SOCKFD;
        }

        operator bool() const {
            return is_valid();
        }

        virtual bool is_secure() const {
            return false;
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

        Status bind(StringView hostname, StringView port) {
            if (this->is_valid()) {
                return std::unexpected(make_polynet_error(PN_ERROR_ALREADY_INITIALIZED, "bind"));
            }

            struct addrinfo* ai_list;
            struct addrinfo hints = {};
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = Socktype;
            hints.ai_protocol = Protocol;
#ifdef AI_IDN
            hints.ai_flags = AI_IDN;
#endif
            if (Status result = getaddrinfo(hostname, port, &hints, &ai_list); !result) {
                return result;
            }

            std::error_code last_error;
            struct addrinfo* ai_it;
            for (ai_it = ai_list; ai_it != nullptr; ai_it = ai_it->ai_next) {
                if (Status result = this->init(ai_it->ai_family, ai_it->ai_socktype, ai_it->ai_protocol); !result) {
                    last_error = result.error().code;
                    continue;
                }

                {
                    static constexpr int value = 1;
                    if (Status result = this->setsockopt(SOL_SOCKET, SO_REUSEADDR, &value, sizeof(int)); !result) {
                        (void) Socket::close(PN_PROTOCOL_LAYER_SYSTEM);
                        pn::freeaddrinfo(ai_list);
                        return result;
                    }
                }

                if (::bind(this->fd, ai_it->ai_addr, ai_it->ai_addrlen) == PN_OK) {
                    break;
                }
                last_error = last_socket_error_code();
                (void) Socket::close(PN_PROTOCOL_LAYER_SYSTEM);
            }
            if (ai_it == nullptr) {
                pn::freeaddrinfo(ai_list);
                if (last_error) {
                    return std::unexpected(Error {last_error, "bind"});
                }
                return std::unexpected(make_polynet_error(PN_ERROR_INVALID_ADDRESS, "bind"));
            }

            memcpy(&this->addr, ai_it->ai_addr, ai_it->ai_addrlen);
            this->addrlen = ai_it->ai_addrlen;

            pn::freeaddrinfo(ai_list);
            return {};
        }

        Status bind(StringView hostname, unsigned short port) {
            return bind(hostname, std::to_string(port));
        }

        Status bind(const struct sockaddr* addr, socklen_t addrlen) {
            if (this->is_valid()) {
                return std::unexpected(make_polynet_error(PN_ERROR_ALREADY_INITIALIZED, "bind"));
            }

            if (Status result = this->init(addr->sa_family, Socktype, Protocol); !result) {
                return result;
            }

            {
                static constexpr int value = 1;
                if (Status result = this->setsockopt(SOL_SOCKET, SO_REUSEADDR, &value, sizeof(int)); !result) {
                    (void) Socket::close(PN_PROTOCOL_LAYER_SYSTEM);
                    return result;
                }
            }

            if (::bind(this->fd, addr, addrlen) == PN_ERROR) {
                Error error = make_last_socket_error("bind");
                (void) Socket::close(PN_PROTOCOL_LAYER_SYSTEM);
                return std::unexpected(error);
            }

            memcpy(&this->addr, addr, addrlen);
            this->addrlen = addrlen;

            return {};
        }
    };

    template <class Base, int Socktype, int Protocol>
    class BasicClient : public Base {
    public:
        template <typename... Args>
        BasicClient(Args&&... args):
            Base(std::forward<Args>(args)...) {}

        Status connect(StringView hostname, StringView port, const std::function<bool(pn::BasicClient<Base, Socktype, Protocol>&)>& config_cb = {}) {
            if (this->is_valid()) {
                return std::unexpected(make_polynet_error(PN_ERROR_ALREADY_INITIALIZED, "connect"));
            }

            struct addrinfo* ai_list;
            struct addrinfo hints = {};
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = Socktype;
            hints.ai_protocol = Protocol;
#ifdef AI_IDN
            hints.ai_flags = AI_IDN;
#endif
            if (Status result = getaddrinfo(hostname, port, &hints, &ai_list); !result) {
                return result;
            }

            std::error_code last_error;
            struct addrinfo* ai_it;
            for (ai_it = ai_list; ai_it != nullptr; ai_it = ai_it->ai_next) {
                if (Status result = this->init(ai_it->ai_family, ai_it->ai_socktype, ai_it->ai_protocol); !result) {
                    last_error = result.error().code;
                    continue;
                }

                if (config_cb && !config_cb(*this)) {
                    (void) Socket::close(PN_PROTOCOL_LAYER_SYSTEM);
                    pn::freeaddrinfo(ai_list);
                    return std::unexpected(make_polynet_error(PN_ERROR_USER_CALLBACK, "configure client"));
                }

                if (::connect(this->fd, ai_it->ai_addr, ai_it->ai_addrlen) == PN_OK) {
                    break;
                }
                last_error = last_socket_error_code();
                (void) Socket::close(PN_PROTOCOL_LAYER_SYSTEM);
            }
            if (ai_it == nullptr) {
                pn::freeaddrinfo(ai_list);
                if (last_error) {
                    return std::unexpected(Error {last_error, "connect"});
                }
                return std::unexpected(make_polynet_error(PN_ERROR_INVALID_ADDRESS, "connect"));
            }

            memcpy(&this->addr, ai_it->ai_addr, ai_it->ai_addrlen);
            this->addrlen = ai_it->ai_addrlen;

            pn::freeaddrinfo(ai_list);
            return {};
        }

        Status connect(StringView hostname, unsigned short port, const std::function<bool(pn::BasicClient<Base, Socktype, Protocol>&)>& config_cb = {}) {
            return connect(hostname, std::to_string(port), config_cb);
        }

        Status connect(const struct sockaddr* addr, socklen_t addrlen, const std::function<bool(pn::BasicClient<Base, Socktype, Protocol>&)>& config_cb = {}) {
            if (this->is_valid()) {
                return std::unexpected(make_polynet_error(PN_ERROR_ALREADY_INITIALIZED, "connect"));
            }

            if (Status result = this->init(addr->sa_family, Socktype, Protocol); !result) {
                return result;
            }

            if (config_cb && !config_cb(*this)) {
                (void) Socket::close(PN_PROTOCOL_LAYER_SYSTEM);
                return std::unexpected(make_polynet_error(PN_ERROR_USER_CALLBACK, "configure client"));
            }

            if (::connect(this->fd, addr, addrlen) == PN_ERROR) {
                Error error = make_last_socket_error("connect");
                (void) Socket::close(PN_PROTOCOL_LAYER_SYSTEM);
                return std::unexpected(error);
            }

            memcpy(&this->addr, addr, addrlen);
            this->addrlen = addrlen;

            return {};
        }
    };

    namespace tcp {
        class Connection : public Socket {
        public:
            Connection() = default;
            Connection(sockfd_t fd):
                Socket(fd) {}
            Connection(sockfd_t fd, const struct sockaddr& addr, socklen_t addrlen):
                Socket(fd, addr, addrlen) {}

            virtual Result<size_t> send(const void* buf, size_t len) {
                for (;;) {
                    ssize_t result;
                    if ((result = ::send(fd, (const char*) buf, len, 0)) == PN_ERROR) {
#ifndef _WIN32
                        std::error_code error = last_socket_error_code();
                        if (error.value() == EINTR) {
                            continue;
                        }
                        return std::unexpected(Error {error, "send"});
#else
                        return std::unexpected(make_last_socket_error("send"));
#endif
                    }
                    return result;
                }
            }

            virtual Result<size_t> recv(void* buf, size_t len) {
                for (;;) {
                    ssize_t result;
                    if ((result = ::recv(fd, (char*) buf, len, 0)) == PN_ERROR) {
#ifndef _WIN32
                        std::error_code error = last_socket_error_code();
                        if (error.value() == EINTR) {
                            continue;
                        }
                        return std::unexpected(Error {error, "receive"});
#else
                        return std::unexpected(make_last_socket_error("receive"));
#endif
                    }
                    return result;
                }
            }

            virtual Result<size_t> peek(void* buf, size_t len) {
                for (;;) {
                    ssize_t result;
                    if ((result = ::recv(fd, (char*) buf, len, MSG_PEEK)) == PN_ERROR) {
#ifndef _WIN32
                        std::error_code error = last_socket_error_code();
                        if (error.value() == EINTR) {
                            continue;
                        }
                        return std::unexpected(Error {error, "peek"});
#else
                        return std::unexpected(make_last_socket_error("peek"));
#endif
                    }
                    return result;
                }
            }

            Result<size_t> sendall(const void* buf, size_t len);
            Result<size_t> recvall(void* buf, size_t len);
        };

        class BufReceiver {
        protected:
            std::vector<char> data;
            size_t cursor = 0;

            void clear() {
                data.clear();
                cursor = 0;
            }

        public:
            size_t capacity;

            BufReceiver(size_t capacity = 4'000):
                capacity(capacity) {}
            BufReceiver(BufReceiver&& buf_receiver) noexcept {
                *this = std::move(buf_receiver);
            }

            BufReceiver& operator=(BufReceiver&& buf_receiver) noexcept {
                if (this != &buf_receiver) {
                    data = std::move(buf_receiver.data);
                    cursor = std::exchange(buf_receiver.cursor, 0);
                    capacity = std::exchange(buf_receiver.capacity, 4'000);
                }
                return *this;
            }

            size_t available() const {
                return data.size() - cursor;
            }

            Result<size_t> recv(Connection& conn, void* buf, size_t len);
            Result<size_t> peek(Connection& conn, void* buf, size_t len);
            Result<size_t> recvall(Connection& conn, void* buf, size_t len);
            void rewind(const void* buf, size_t len);
        };

        class Server : public BasicServer<Socket, SOCK_STREAM, IPPROTO_TCP> {
        public:
            typedef Connection connection_type;

            Server() = default;
            Server(sockfd_t fd):
                BasicServer<Socket, SOCK_STREAM, IPPROTO_TCP>(fd) {}
            Server(sockfd_t fd, const struct sockaddr& addr, socklen_t addrlen):
                BasicServer<Socket, SOCK_STREAM, IPPROTO_TCP>(fd, addr, addrlen) {}

            // Return false from the callback to stop listening
            Status listen(const std::function<bool(connection_type)>& cb, int backlog = 128);
        };

        using Client = BasicClient<Connection, SOCK_STREAM, IPPROTO_TCP>;
    } // namespace tcp

    namespace udp {
        class Socket : public pn::Socket {
        public:
            Socket() = default;
            Socket(sockfd_t fd):
                pn::Socket(fd) {}
            Socket(sockfd_t fd, const struct sockaddr& addr, socklen_t addrlen):
                pn::Socket(fd, addr, addrlen) {}

            virtual Result<size_t> sendto(const void* buf, size_t len, const struct sockaddr* dest_addr, socklen_t addrlen, int flags = 0) {
                for (;;) {
                    ssize_t result;
                    if ((result = ::sendto(fd, (const char*) buf, len, flags, dest_addr, addrlen)) == PN_ERROR) {
#ifndef _WIN32
                        std::error_code error = last_socket_error_code();
                        if (error.value() == EINTR) {
                            continue;
                        }
                        return std::unexpected(Error {error, "send datagram"});
#else
                        return std::unexpected(make_last_socket_error("send datagram"));
#endif
                    }
                    return result;
                }
            }

            virtual Result<size_t> recvfrom(void* buf, size_t len, struct sockaddr* src_addr, socklen_t* addrlen, int flags = 0) {
                for (;;) {
                    ssize_t result;
                    if ((result = ::recvfrom(fd, (char*) buf, len, flags, src_addr, addrlen)) == PN_ERROR) {
#ifndef _WIN32
                        std::error_code error = last_socket_error_code();
                        if (error.value() == EINTR) {
                            continue;
                        }
                        return std::unexpected(Error {error, "receive datagram"});
#else
                        return std::unexpected(make_last_socket_error("receive datagram"));
#endif
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
