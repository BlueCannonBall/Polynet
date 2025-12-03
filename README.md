# Polynet
Polynet is a simple, cross-platform networking abstraction for C++.

## Usage
Polynet is designed to be similar to Berkeley sockets while using C++ features such as objects, methods, inheritance, and templates. Polynet supports TCP and UDP.

### Quick Examples
```cpp
pn::init();

// Creating a TCP server
pn::tcp::Server server;
if (server.bind("0.0.0.0", 8000) == PN_ERROR) {
    std::cerr << "Error: " << pn::universal_strerror() << std::endl;
    exit(EXIT_FAILURE);
}

// Accepting connections (this blocks until an error occurs or the callback returns false)
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

pn::quit();
```
See `polynet.hpp` and `smart_sockets.hpp` to check out more ways to use Polynet. Since the secure examples are a bit longer, they can be found in the examples directory.
