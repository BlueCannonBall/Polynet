#ifndef _POLYNET_HPP
#define _POLYNET_HPP

// Network includes
#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN

    #ifndef _WIN32_WINNT
        #define _WIN32_WINNT _WIN32_WINNT_VISTA
    #endif

    #include <basetsd.h>
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

    #if __has_include(<endian.h>)
        #include <endian.h>
    #elif __has_include(<machine/endian.h>)
        #include <machine/endian.h>
    #endif
#endif

// Other includes
#include <atomic>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

#define _POLYNET_COPY_CTOR_TEMPLATE(class_name, type1, type2, arg_name)   \
    class_name(const class_name& arg_name): class_name(arg_name, true) {} \
    template <typename type2>                                             \
    class_name(const class_name<type2>& arg_name, bool _same_type = false)
#define _POLYNET_MOVE_CTOR_TEMPLATE(class_name, type1, type2, arg_name)         \
    class_name(class_name&& arg_name): class_name(std::move(arg_name), true) {} \
    template <typename type2>                                                   \
    class_name(class_name<type2>&& arg_name, bool _same_type = false)
#define _POLYNET_COPY_ASSIGN_TEMPLATE(class_name, type1, type2, arg_name) \
    inline class_name& operator=(const class_name& arg_name) {            \
        return class_name::operator=<type1>(arg_name);                    \
    }                                                                     \
    template <typename type2>                                             \
    class_name& operator=(const class_name<type2>& arg_name)
#define _POLYNET_MOVE_ASSIGN_TEMPLATE(class_name, type1, type2, arg_name) \
    inline class_name& operator=(class_name&& arg_name) {                 \
        return class_name::operator=<type1>(std::move(arg_name));         \
    }                                                                     \
    template <typename type2>                                             \
    class_name& operator=(class_name<type2>&& arg_name)

// Bridged
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
#define PN_OK 0

// Errors
#define PN_ESUCCESS  0
#define PN_ESOCKET   1
#define PN_EAI       2
#define PN_EBADADDRS 3
#define PN_EPTON     4

namespace pn {
#ifdef _WIN32
    typedef SOCKET sockfd_t;
#else
    typedef int sockfd_t;
#endif
    typedef unsigned long use_count_t;

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

        class ControlBlock {
        public:
            std::atomic<use_count_t> use_count;
            std::atomic<use_count_t> weak_use_count;

            ControlBlock(use_count_t use_count = 1, use_count_t weak_use_count = 0):
                use_count(use_count),
                weak_use_count(weak_use_count) {}
        };
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
        char result[INET6_ADDRSTRLEN];
        if (::inet_ntop(af, src, result, sizeof result) == nullptr) {
            detail::set_last_socket_error(detail::get_last_system_error());
            detail::set_last_error(PN_ESOCKET);
            return PN_ERROR;
        }
        ret = result;
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

        inline bool is_valid() const {
            return this->fd != PN_INVALID_SOCKFD;
        }

        inline operator bool() const {
            return is_valid();
        }

        inline bool operator==(const Socket& sock) const {
            return this->fd == sock.fd;
        }

        inline bool operator!=(const Socket& sock) const {
            return this->fd != sock.fd;
        }
    };

    class BufReceiver {
    protected:
        std::vector<char> buf;

    public:
        size_t size;

        BufReceiver(size_t size = 4'000):
            size(size) {}

        template <typename T>
        ssize_t recv(T& conn, void* buf, size_t len, int flags = 0) {
            if (len > this->buf.size()) {
                if (!this->buf.empty()) {
                    memcpy(buf, this->buf.data(), this->buf.size());
                } else if (len > this->size || (flags & MSG_WAITALL)) {
                    return conn.recv(buf, len, flags);
                } else {
                    ssize_t result;
                    this->buf.resize(this->size);
                    if ((result = conn.recv(this->buf.data(), this->size, flags)) == PN_ERROR) {
                        return PN_ERROR;
                    }
                    this->buf.resize(result);

                    memcpy(buf, this->buf.data(), std::min<long long>(len, result));
                    if (!(flags & MSG_PEEK)) this->buf.erase(this->buf.begin(), this->buf.begin() + std::min<long long>(len, result));
                    return std::min<long long>(len, result);
                }

                if (flags & MSG_WAITALL) {
                    ssize_t result;
                    if ((result = conn.recv((char*) buf + this->buf.size(), len - this->buf.size(), flags)) == PN_ERROR) {
                        return PN_ERROR;
                    }

                    result += this->buf.size();
                    if (!(flags & MSG_PEEK)) this->buf.clear();
                    return result;
                }

                ssize_t ret = this->buf.size();
                if (!(flags & MSG_PEEK)) this->buf.clear();
                return ret;
            } else if (len < this->buf.size()) {
                memcpy(buf, this->buf.data(), len);
                if (!(flags & MSG_PEEK)) this->buf.erase(this->buf.begin(), this->buf.begin() + len);
                return len;
            } else {
                memcpy(buf, this->buf.data(), this->buf.size());
                if (!(flags & MSG_PEEK)) this->buf.clear();
                return len;
            }
        }
    };

    template <typename T>
    class UniqueSock {
    protected:
        template <typename U>
        friend class UniqueSock;

        template <typename U>
        friend class SharedSock;

        template <typename U>
        friend class WeakSock;

        T sock;

    public:
        typedef T sock_type;

        UniqueSock() = default;
        UniqueSock(const T& sock):
            sock(sock) {}
        _POLYNET_MOVE_CTOR_TEMPLATE(UniqueSock, T, U, unique_sock) {
            *this = std::move(unique_sock);
        }

        _POLYNET_MOVE_ASSIGN_TEMPLATE(UniqueSock, T, U, unique_sock) {
            if (this->sock != unique_sock.sock) {
                this->sock.close(/* Reset fd */ false);
                this->sock = unique_sock.sock;
            }
            unique_sock.sock = U();
            return *this;
        }

        ~UniqueSock() {
            this->sock.close(/* Reset fd */ false);
        }

        inline T get() const {
            return this->sock;
        }

        inline const T& operator*() const {
            return this->sock;
        }

        inline T& operator*() {
            return this->sock;
        }

        inline const T* operator->() const {
            return &this->sock;
        }

        inline T* operator->() {
            return &this->sock;
        }

        inline void reset() {
            this->sock.close(/* Reset fd */ false);
            this->sock = T();
        }

        inline void reset(const T& sock) {
            if (this->sock != sock) {
                this->sock.close(/* Reset fd */ false);
                this->sock = sock;
            }
        }

        inline bool is_valid() const {
            return this->sock.is_valid();
        }

        inline operator bool() const {
            return is_valid();
        }

        template <typename U>
        inline bool operator==(const U& other_sock) const {
            return this->sock == other_sock.sock;
        }

        template <typename U>
        inline bool operator!=(const U& other_sock) const {
            return this->sock != other_sock.sock;
        }

        inline T release() const {
            return std::exchange(this->sock, T());
        }
    };

    template <typename T>
    class SharedSock {
    protected:
        template <typename U>
        friend class SharedSock;

        template <typename U>
        friend class WeakSock;

        template <typename U>
        friend class UniqueSock;

        T sock;
        detail::ControlBlock* control_block = new detail::ControlBlock;

        void increment() {
            control_block->use_count++;
        }

        void decrement() {
            if (!--control_block->use_count) {
                this->sock.close(/* Reset fd */ false);
                if (!control_block->weak_use_count) {
                    delete control_block;
                }
            }
        }

        SharedSock(const T& sock, detail::ControlBlock* control_block):
            sock(sock),
            control_block(control_block) {}

    public:
        typedef T sock_type;

        SharedSock() = default;
        SharedSock(const T& sock):
            sock(sock) {}
        _POLYNET_COPY_CTOR_TEMPLATE(SharedSock, T, U, shared_sock) {
            *this = shared_sock;
        }
        _POLYNET_MOVE_CTOR_TEMPLATE(SharedSock, T, U, shared_sock) {
            *this = std::move(shared_sock);
        }
        template <typename U>
        SharedSock(UniqueSock<U>&& unique_sock) {
            *this = std::move(unique_sock);
        }

        _POLYNET_COPY_ASSIGN_TEMPLATE(SharedSock, T, U, shared_sock) {
            if (this->sock != shared_sock.sock) {
                decrement();
                this->sock = shared_sock.sock;
                control_block = shared_sock.control_block;
                increment();
            }
            return *this;
        }

        _POLYNET_MOVE_ASSIGN_TEMPLATE(SharedSock, T, U, shared_sock) {
            if (this->sock != shared_sock.sock) {
                decrement();
                this->sock = shared_sock.sock;
                control_block = shared_sock.control_block;
            }
            shared_sock.sock = U();
            shared_sock.control_block = new detail::ControlBlock;
            return *this;
        }

        template <typename U>
        SharedSock& operator=(UniqueSock<U>&& unique_sock) {
            if (this->sock != unique_sock.sock) {
                decrement();
                this->sock = unique_sock.sock;
                control_block = new detail::ControlBlock;
            }
            unique_sock.sock = U();
            return *this;
        }

        ~SharedSock() {
            decrement();
        }

        inline T get() const {
            return this->sock;
        }

        inline const T& operator*() const {
            return this->sock;
        }

        inline T& operator*() {
            return this->sock;
        }

        inline const T* operator->() const {
            return &this->sock;
        }

        inline T* operator->() {
            return &this->sock;
        }

        inline void reset() {
            decrement();
            this->sock = T();
            control_block = new detail::ControlBlock;
        }

        inline void reset(const T& sock) {
            if (this->sock != sock) {
                decrement();
                this->sock = sock;
                control_block = new detail::ControlBlock;
            }
        }

        inline bool is_valid() const {
            return this->sock.is_valid();
        }

        inline operator bool() const {
            return is_valid();
        }

        template <typename U>
        inline bool operator==(const U& other_sock) const {
            return this->sock == other_sock.sock;
        }

        template <typename U>
        inline bool operator!=(const U& other_sock) const {
            return this->sock != other_sock.sock;
        }

        inline use_count_t use_count() const {
            return control_block->use_count;
        }
    };

    template <typename T>
    class WeakSock {
    protected:
        template <typename U>
        friend class WeakSock;

        template <typename U>
        friend class UniqueSock;

        template <typename U>
        friend class SharedSock;

        T sock;
        detail::ControlBlock* control_block = nullptr;

        void increment() {
            if (control_block) {
                control_block->weak_use_count++;
            }
        }

        void decrement() {
            if (control_block && (!--control_block->weak_use_count) && !control_block->use_count) {
                delete control_block;
            }
        }

    public:
        typedef T sock_type;

        WeakSock() = default;
        _POLYNET_COPY_CTOR_TEMPLATE(WeakSock, T, U, weak_sock) {
            *this = weak_sock;
        }
        _POLYNET_MOVE_CTOR_TEMPLATE(WeakSock, T, U, weak_sock) {
            *this = std::move(weak_sock);
        }
        template <typename U>
        WeakSock(const SharedSock<U>& shared_sock) {
            *this = shared_sock;
        }
        template <typename U>
        WeakSock(SharedSock<U>&& shared_sock) {
            *this = std::move(shared_sock);
        }

        template <typename U>
        WeakSock& operator=(const SharedSock<U>& shared_sock) {
            if (this->sock != shared_sock.sock) {
                decrement();
                this->sock = shared_sock.sock;
                control_block = shared_sock.control_block;
                increment();
            }
            return *this;
        }

        template <typename U>
        WeakSock& operator=(SharedSock<U>&& shared_sock) {
            if (this->sock != shared_sock.sock) {
                decrement();
                this->sock = shared_sock.sock;
                control_block = shared_sock.control_block;
                increment();
            }
            shared_sock.decrement();
            shared_sock.sock = U();
            shared_sock.control_block = new detail::ControlBlock;
            return *this;
        }

        _POLYNET_COPY_ASSIGN_TEMPLATE(WeakSock, T, U, weak_sock) {
            if (this->sock != weak_sock.sock) {
                decrement();
                this->sock = weak_sock.sock;
                control_block = weak_sock.control_block;
                increment();
            }
            return *this;
        }

        _POLYNET_MOVE_ASSIGN_TEMPLATE(WeakSock, T, U, weak_sock) {
            if (this->sock != weak_sock.sock) {
                decrement();
                this->sock = weak_sock.sock;
                control_block = weak_sock.control_block;
            }
            weak_sock.sock = U();
            weak_sock.control_block = nullptr;
            return *this;
        }

        ~WeakSock() {
            decrement();
        }

        inline void reset() {
            decrement();
            this->sock = T();
            control_block = nullptr;
        }

        inline bool is_valid() const {
            return this->sock.is_valid();
        }

        inline operator bool() const {
            return is_valid();
        }

        template <typename U>
        inline bool operator==(const U& other_sock) const {
            return this->sock == other_sock.sock;
        }

        template <typename U>
        inline bool operator!=(const U& other_sock) const {
            return this->sock != other_sock.sock;
        }

        inline use_count_t use_count() const {
            if (control_block) {
                return control_block->use_count;
            } else {
                return 0; // Invalid state
            }
        }

        inline bool expired() const {
            return !use_count();
        }

        inline SharedSock<T> lock() const {
            if (control_block && control_block->use_count) {
                SharedSock<T> ret(this->sock, control_block);
                control_block->use_count++;
                return ret;
            } else {
                return SharedSock<T>();
            }
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
    class Server : public Base {
    public:
        Server() = default;
        Server(sockfd_t fd):
            Base(fd) {}
        Server(const struct sockaddr& addr, socklen_t addrlen):
            Base(addr, addrlen) {}
        Server(sockfd_t fd, const struct sockaddr& addr, socklen_t addrlen):
            Base(fd, addr, addrlen) {}

        int bind(const std::string& hostname, const std::string& port) {
            std::unique_ptr<struct addrinfo, decltype(&freeaddrinfo)> ai_list(nullptr, freeaddrinfo);
            struct addrinfo hints = {0};
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = Socktype;
            hints.ai_protocol = Protocol;

            {
                struct addrinfo* tmp = nullptr;
                if (getaddrinfo(hostname, port, &hints, &tmp) == PN_ERROR) {
                    return PN_ERROR;
                }
                ai_list.reset(tmp);
            }

            struct addrinfo* ai_it;
            for (ai_it = ai_list.get(); ai_it != nullptr; ai_it = ai_it->ai_next) {
                if (this->init(ai_it->ai_family, ai_it->ai_socktype, ai_it->ai_protocol) == PN_ERROR) {
                    continue;
                }

                {
                    const int value = 1;
                    if (Base::setsockopt(SOL_SOCKET, SO_REUSEADDR, &value, sizeof(int)) == PN_ERROR) {
                        return PN_ERROR;
                    }
                }

                if (::bind(this->fd, ai_it->ai_addr, ai_it->ai_addrlen) == PN_OK) {
                    break;
                }

                if (Base::close(true, false) == PN_ERROR) {
                    return PN_ERROR;
                }
            }
            if (ai_it == nullptr) {
                detail::set_last_error(PN_EBADADDRS);
                return PN_ERROR;
            }

            this->addr = *ai_it->ai_addr;
            this->addrlen = ai_it->ai_addrlen;

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
    class Client : public Base {
    public:
        Client() = default;
        Client(sockfd_t fd):
            Base(fd) {}
        Client(const struct sockaddr& addr, socklen_t addrlen):
            Base(addr, addrlen) {}
        Client(sockfd_t fd, const struct sockaddr& addr, socklen_t addrlen):
            Base(fd, addr, addrlen) {}

        int connect(const std::string& hostname, const std::string& port) {
            std::unique_ptr<struct addrinfo, decltype(&freeaddrinfo)> ai_list(nullptr, freeaddrinfo);
            struct addrinfo hints = {0};
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = Socktype;
            hints.ai_protocol = Protocol;

            {
                struct addrinfo* tmp = nullptr;
                if (getaddrinfo(hostname, port, &hints, &tmp) == PN_ERROR) {
                    return PN_ERROR;
                }
                ai_list.reset(tmp);
            }

            struct addrinfo* ai_it;
            for (ai_it = ai_list.get(); ai_it != nullptr; ai_it = ai_it->ai_next) {
                if (this->init(ai_it->ai_family, ai_it->ai_socktype, ai_it->ai_protocol) == PN_ERROR) {
                    continue;
                }

                if (::connect(this->fd, ai_it->ai_addr, ai_it->ai_addrlen) == PN_OK) {
                    break;
                }

                if (Base::close(true, false) == PN_ERROR) {
                    return PN_ERROR;
                }
            }
            if (ai_it == nullptr) {
                detail::set_last_error(PN_EBADADDRS);
                return PN_ERROR;
            }

            this->addr = *ai_it->ai_addr;
            this->addrlen = ai_it->ai_addrlen;

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

            inline ssize_t send(const void* buf, size_t len, int flags = 0) {
                ssize_t result;
                if ((result = ::send(this->fd, (const char*) buf, len, flags)) == PN_ERROR) {
                    detail::set_last_socket_error(detail::get_last_system_error());
                    detail::set_last_error(PN_ESOCKET);
                }
                return result;
            }

            inline ssize_t recv(void* buf, size_t len, int flags = 0) {
                ssize_t result;
                if ((result = ::recv(this->fd, (char*) buf, len, flags)) == PN_ERROR) {
                    detail::set_last_socket_error(detail::get_last_system_error());
                    detail::set_last_error(PN_ESOCKET);
                }
                return result;
            }
        };

        class Server : public pn::Server<pn::Socket, SOCK_STREAM, IPPROTO_TCP> {
        protected:
            int backlog = -1;

        public:
            Server() = default;
            Server(sockfd_t fd):
                pn::Server<pn::Socket, SOCK_STREAM, IPPROTO_TCP>(fd) {}
            Server(const struct sockaddr& addr, socklen_t addrlen):
                pn::Server<pn::Socket, SOCK_STREAM, IPPROTO_TCP>(addr, addrlen) {}
            Server(sockfd_t fd, const struct sockaddr& addr, socklen_t addrlen):
                pn::Server<pn::Socket, SOCK_STREAM, IPPROTO_TCP>(fd, addr, addrlen) {}

            // Return false from the callback to stop listening
            int listen(const std::function<bool(Connection&, void*)>& cb, int backlog = 128, void* data = nullptr);
        };

        using Client = pn::Client<Connection, SOCK_STREAM, IPPROTO_TCP>;
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

            inline ssize_t sendto(const void* buf, size_t len, const struct sockaddr* dest_addr, socklen_t addrlen, int flags = 0) {
                ssize_t result;
                if ((result = ::sendto(this->fd, (const char*) buf, len, flags, dest_addr, addrlen)) == PN_ERROR) {
                    detail::set_last_socket_error(detail::get_last_system_error());
                    detail::set_last_error(PN_ESOCKET);
                }
                return result;
            }

            inline ssize_t recvfrom(void* buf, size_t len, struct sockaddr* src_addr, socklen_t* addrlen, int flags = 0) {
                ssize_t result;
                if ((result = ::recvfrom(this->fd, (char*) buf, len, flags, src_addr, addrlen)) == PN_ERROR) {
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
