#ifndef _POLYNET_SMART_SOCKETS_HPP
#define _POLYNET_SMART_SOCKETS_HPP

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
    class BasicSocket {
    protected:
        T socket;

    public:
        typedef T sock_type;

        BasicSocket() = default;
        BasicSocket(const T& socket):
            socket(socket) {}

        inline T get() const {
            return this->socket;
        }

        inline const T& operator*() const {
            return this->socket;
        }

        inline T& operator*() {
            return this->socket;
        }

        inline const T* operator->() const {
            return &this->socket;
        }

        inline T* operator->() {
            return &this->socket;
        }

        inline operator bool() const {
            return this->socket.is_valid();
        }

        template <typename U>
        inline bool operator==(const U& other_sock) const {
            return this->socket == other_sock.socket;
        }

        template <typename U>
        inline bool operator!=(const U& other_sock) const {
            return this->socket != other_sock.socket;
        }
    };

    template <typename T>
    class UniqueSocket : public BasicSocket<T> {
    protected:
        template <typename U>
        friend class UniqueSocket;

        template <typename U>
        friend class SharedSocket;

        template <typename U>
        friend class WeakSocket;

    public:
        UniqueSocket() = default;
        UniqueSocket(const T& socket):
            BasicSocket<T>(socket) {}
        _POLYNET_MOVE_CTOR_TEMPLATE(UniqueSocket, T, U, unique_sock) {
            *this = std::move(unique_sock);
        }

        _POLYNET_MOVE_ASSIGN_TEMPLATE(UniqueSocket, T, U, unique_sock) {
            if (this->socket != unique_sock.socket) {
                this->socket.close(/* Reset fd */ false);
                this->socket = unique_sock.socket;
            }
            unique_sock.socket = U();
            return *this;
        }

        ~UniqueSocket() {
            this->socket.close(/* Reset fd */ false);
        }

        inline void reset() {
            this->socket.close(/* Reset fd */ false);
            this->socket = T();
        }

        inline void reset(const T& socket) {
            if (this->socket != socket) {
                this->socket.close(/* Reset fd */ false);
                this->socket = socket;
            }
        }

        inline T release() const {
            return std::exchange(this->socket, T());
        }
    };

    template <typename T>
    class SharedSocket : public BasicSocket<T> {
    protected:
        template <typename U>
        friend class SharedSocket;

        template <typename U>
        friend class WeakSocket;

        template <typename U>
        friend class UniqueSocket;

        detail::ControlBlock* control_block = new detail::ControlBlock;

        void increment() {
            std::lock_guard<std::mutex> lock(control_block->mutex);
            control_block->use_count++;
        }

        void decrement() {
            std::unique_lock<std::mutex> lock(control_block->mutex);
            if (!--control_block->use_count) {
                this->socket.close(/* Reset fd */ false);
                if (!control_block->weak_use_count) {
                    lock.unlock();
                    delete control_block;
                }
            }
        }

        SharedSocket(const T& socket, detail::ControlBlock* control_block):
            BasicSocket<T>(socket),
            control_block(control_block) {}

    public:
        SharedSocket() = default;
        SharedSocket(const T& socket):
            BasicSocket<T>(socket) {}
        _POLYNET_COPY_CTOR_TEMPLATE(SharedSocket, T, U, shared_sock) {
            *this = shared_sock;
        }
        _POLYNET_MOVE_CTOR_TEMPLATE(SharedSocket, T, U, shared_sock) {
            *this = std::move(shared_sock);
        }
        template <typename U>
        SharedSocket(UniqueSocket<U>&& unique_sock) {
            *this = std::move(unique_sock);
        }

        _POLYNET_COPY_ASSIGN_TEMPLATE(SharedSocket, T, U, shared_sock) {
            if (this->socket != shared_sock.socket) {
                decrement();
                this->socket = shared_sock.socket;
                control_block = shared_sock.control_block;
                increment();
            }
            return *this;
        }

        _POLYNET_MOVE_ASSIGN_TEMPLATE(SharedSocket, T, U, shared_sock) {
            if (this->socket != shared_sock.socket) {
                decrement();
                this->socket = shared_sock.socket;
                control_block = shared_sock.control_block;
            }
            shared_sock.socket = U();
            shared_sock.control_block = new detail::ControlBlock;
            return *this;
        }

        template <typename U>
        SharedSocket& operator=(UniqueSocket<U>&& unique_sock) {
            if (this->socket != unique_sock.socket) {
                decrement();
                this->socket = unique_sock.socket;
                control_block = new detail::ControlBlock;
            }
            unique_sock.socket = U();
            return *this;
        }

        ~SharedSocket() {
            decrement();
        }

        inline void reset() {
            decrement();
            this->socket = T();
            control_block = new detail::ControlBlock;
        }

        inline void reset(const T& socket) {
            if (this->socket != socket) {
                decrement();
                this->socket = socket;
                control_block = new detail::ControlBlock;
            }
        }

        inline use_count_t use_count() const {
            std::lock_guard<std::mutex> lock(control_block->mutex);
            return control_block->use_count;
        }
    };

    template <typename T>
    class WeakSocket : public SharedSocket<T> {
    protected:
        template <typename U>
        friend class WeakSocket;

        template <typename U>
        friend class UniqueSocket;

        template <typename U>
        friend class SharedSocket;

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
        using BasicSocket<T>::get;
        using BasicSocket<T>::operator*;
        using BasicSocket<T>::operator->;

    public:
        WeakSocket() = default;
        _POLYNET_COPY_CTOR_TEMPLATE(WeakSocket, T, U, weak_sock) {
            *this = weak_sock;
        }
        _POLYNET_MOVE_CTOR_TEMPLATE(WeakSocket, T, U, weak_sock) {
            *this = std::move(weak_sock);
        }
        template <typename U>
        WeakSocket(const SharedSocket<U>& shared_sock) {
            *this = shared_sock;
        }
        template <typename U>
        WeakSocket(SharedSocket<U>&& shared_sock) {
            *this = std::move(shared_sock);
        }

        template <typename U>
        WeakSocket& operator=(const SharedSocket<U>& shared_sock) {
            if (this->socket != shared_sock.socket) {
                decrement();
                this->socket = shared_sock.socket;
                control_block = shared_sock.control_block;
                increment();
            }
            return *this;
        }

        template <typename U>
        WeakSocket& operator=(SharedSocket<U>&& shared_sock) {
            if (this->socket != shared_sock.socket) {
                decrement();
                this->socket = shared_sock.socket;
                control_block = shared_sock.control_block;
                increment();
            }
            shared_sock.decrement();
            shared_sock.socket = U();
            shared_sock.control_block = new detail::ControlBlock;
            return *this;
        }

        _POLYNET_COPY_ASSIGN_TEMPLATE(WeakSocket, T, U, weak_sock) {
            if (this->socket != weak_sock.socket) {
                decrement();
                this->socket = weak_sock.socket;
                control_block = weak_sock.control_block;
                increment();
            }
            return *this;
        }

        _POLYNET_MOVE_ASSIGN_TEMPLATE(WeakSocket, T, U, weak_sock) {
            if (this->socket != weak_sock.socket) {
                decrement();
                this->socket = weak_sock.socket;
                control_block = weak_sock.control_block;
            }
            weak_sock.socket = U();
            weak_sock.control_block = nullptr;
            return *this;
        }

        ~WeakSocket() {
            decrement();
        }

        inline void reset() {
            decrement();
            this->socket = T();
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

        inline SharedSocket<T> lock() const {
            if (control_block) {
                std::lock_guard<std::mutex> lock(control_block->mutex);
                if (control_block->use_count) {
                    SharedSocket<T> ret(this->socket, control_block);
                    control_block->use_count++;
                    return ret;
                }
            }

            return SharedSocket<T>();
        }
    };

    template <typename T, typename... Ts>
    inline UniqueSocket<T> make_unique(Ts... args) {
        return UniqueSocket<T>(T(args...));
    }

    template <typename T, typename... Ts>
    inline SharedSocket<T> make_shared(Ts... args) {
        return SharedSocket<T>(T(args...));
    }
} // namespace pn

#endif
