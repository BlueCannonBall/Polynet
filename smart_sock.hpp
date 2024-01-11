#include "polynet.hpp"
#include <mutex>
#include <utility>

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
        return class_name::operator= <type1>(arg_name);                   \
    }                                                                     \
    template <typename type2>                                             \
    class_name& operator=(const class_name<type2>& arg_name)
#define _POLYNET_MOVE_ASSIGN_TEMPLATE(class_name, type1, type2, arg_name) \
    inline class_name& operator=(class_name&& arg_name) {                 \
        return class_name::operator= <type1>(std::move(arg_name));        \
    }                                                                     \
    template <typename type2>                                             \
    class_name& operator=(class_name<type2>&& arg_name)

namespace pn {
    typedef unsigned long use_count_t;

    namespace detail {
        class ControlBlock {
        public:
            std::mutex mutex;
            use_count_t use_count;
            use_count_t weak_use_count;

            ControlBlock(use_count_t use_count = 1, use_count_t weak_use_count = 0):
                use_count(use_count),
                weak_use_count(weak_use_count) {}
        };
    } // namespace detail

    template <typename T>
    class BasicSock {
    protected:
        T sock;

    public:
        typedef T sock_type;

        BasicSock(const T& sock):
            sock(sock) {}

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

        inline operator bool() const {
            return this->sock.is_valid();
        }

        template <typename U>
        inline bool operator==(const U& other_sock) const {
            return this->sock == other_sock.sock;
        }

        template <typename U>
        inline bool operator!=(const U& other_sock) const {
            return this->sock != other_sock.sock;
        }
    };

    template <typename T>
    class UniqueSock : public BasicSock<T> {
    protected:
        template <typename U>
        friend class UniqueSock;

        template <typename U>
        friend class SharedSock;

        template <typename U>
        friend class WeakSock;

    public:
        UniqueSock() = default;
        UniqueSock(const T& sock):
            BasicSock<T>(sock) {}
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

        inline T release() const {
            return std::exchange(this->sock, T());
        }
    };

    template <typename T>
    class SharedSock : public BasicSock<T> {
    protected:
        template <typename U>
        friend class SharedSock;

        template <typename U>
        friend class WeakSock;

        template <typename U>
        friend class UniqueSock;

        detail::ControlBlock* control_block = new detail::ControlBlock;

        void increment() {
            std::lock_guard<std::mutex> lock(control_block->mutex);
            control_block->use_count++;
        }

        void decrement() {
            std::unique_lock<std::mutex> lock(control_block->mutex);
            if (!--control_block->use_count) {
                this->sock.close(/* Reset fd */ false);
                if (!control_block->weak_use_count) {
                    lock.unlock();
                    delete control_block;
                }
            }
        }

        SharedSock(const T& sock, detail::ControlBlock* control_block):
            BasicSock<T>(sock),
            control_block(control_block) {}

    public:
        SharedSock() = default;
        SharedSock(const T& sock):
            BasicSock<T>(sock) {}
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

        inline use_count_t use_count() const {
            std::lock_guard<std::mutex> lock(control_block->mutex);
            return control_block->use_count;
        }
    };

    template <typename T>
    class WeakSock : public SharedSock<T> {
    protected:
        template <typename U>
        friend class WeakSock;

        template <typename U>
        friend class UniqueSock;

        template <typename U>
        friend class SharedSock;

        detail::ControlBlock* control_block = nullptr;

        void increment() {
            if (control_block) {
                std::lock_guard<std::mutex> lock(control_block->mutex);
                control_block->weak_use_count++;
            }
        }

        void decrement() {
            if (control_block) {
                std::unique_lock<std::mutex> lock(control_block->mutex);
                if ((!--control_block->weak_use_count) && !control_block->use_count) {
                    lock.unlock();
                    delete control_block;
                }
            }
        }

    private:
        using BasicSock<T>::get;
        using BasicSock<T>::operator*;
        using BasicSock<T>::operator->;

    public:
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

        inline use_count_t use_count() const {
            if (control_block) {
                std::lock_guard<std::mutex> lock(control_block->mutex);
                return control_block->use_count;
            } else {
                return 0; // Invalid state
            }
        }

        inline bool expired() const {
            return !use_count();
        }

        inline SharedSock<T> lock() const {
            if (control_block) {
                std::lock_guard<std::mutex> lock(control_block->mutex);
                if (control_block->use_count) {
                    SharedSock<T> ret(this->sock, control_block);
                    control_block->use_count++;
                    return ret;
                }
            }

            return SharedSock<T>();
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
} // namespace pn
