# Polynet
Polynet is a simple, cross-platform networking abstraction for C++.

## Usage
Polynet is designed to be similar to Berkeley sockets while using C++ features such as objects, methods, inheritance, and templates. Polynet supports TCP and UDP.
```cpp
// Creating a TCP server
pn::tcp::Server server;
if (server.bind("0.0.0.0", 8000) == PN_ERROR) {
    std::cerr << "Error: " << pn::universal_strerror() << std::endl;
    exit(EXIT_FAILURE);
}

// Accepting connections
if (server.listen(/* Accept callback */) == PN_ERROR) {
    std::cerr << "Error: " << pn::universal_strerror() << std::endl;
    exit(EXIT_FAILURE);
}

// Creating a TCP client
pn::tcp::Client client;
if (client.connect("localhost", 8000) == PN_ERROR) {
    std::cerr << "Error: " << pn::universal_strerror() << std::endl;
    exit(EXIT_FAILURE);
}
```
See `polynet.h` to check out more ways to use Polynet.

### `pn::UniqueSock`, `pn::SharedSock`, and `pn::WeakSock`
These 3 class templates are not unlike `std::unique_ptr`, `std::shared_ptr`, and `std::weak_ptr`, except they deal with sockets rather than pointers. They ensure that sockets they own are automatically closed once they are no longer needed.
