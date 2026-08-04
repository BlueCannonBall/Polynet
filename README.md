# Polynet
Polynet is a cross-platform networking abstraction for C++ with TLS support.

## Usage
Polynet is designed to be similar to Berkeley sockets while using C++ features such as objects, methods, inheritance, and templates. Polynet supports TCP and UDP.

### Quick Examples
```cpp
(void) pn::init();

// Creating a TCP server
pn::tcp::Server server;
if (pn::Status result = server.bind("0.0.0.0", 8000); !result) {
    std::cerr << "Error: " << result.error().message() << std::endl;
    exit(EXIT_FAILURE);
}

// Accepting connections (this blocks until an error occurs or the callback returns false)
if (pn::Status result = server.listen(/* Accept callback */); !result) {
    std::cerr << "Error: " << result.error().message() << std::endl;
    exit(EXIT_FAILURE);
}

// Creating a TCP client
pn::tcp::Client client;
if (pn::Status result = client.connect("localhost", 8000); !result) {
    std::cerr << "Error: " << result.error().message() << std::endl;
    exit(EXIT_FAILURE);
}

(void) pn::quit();
```
See `polynet.hpp` and `tls.hpp` to check out more ways to use Polynet. Since the secure examples are a bit longer, they can be found in the examples directory.
