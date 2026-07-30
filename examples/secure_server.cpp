#include "../polynet.hpp"
#include "../secure_sockets.hpp"
#include <iostream>
#include <openssl/ssl.h>

int main() {
    (void) pn::init();

    pn::tcp::SecureServer server;
    if (pn::Status result = server.bind("0.0.0.0", 443); !result) {
        std::cerr << "Error: " << result.error().message() << std::endl;
        return 1;
    }
    if (pn::Status result = server.ssl_init("cert.pem", "key.pem", SSL_FILETYPE_PEM); !result) {
        std::cerr << "Error: " << result.error().message() << std::endl;
        return 1;
    }

    if (pn::Status result = server.listen([](pn::tcp::SecureConnection conn) {
            // This is only necessary for secure servers
            if (pn::Status result = conn.ssl_accept(); !result) {
                std::cerr << "Error: " << result.error().message() << std::endl;
                return true;
            }

            char req[32000];
            if (pn::Result<size_t> result = conn.recv(req, sizeof req - 1); !result) {
                std::cerr << "Error: " << result.error().message() << std::endl;
                return true;
            } else {
                req[*result] = '\0';
            }
            std::cout << req << std::endl;

            const char resp[] = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\nContent-Type: text/plain\r\n\r\nHello, World!";
            if (pn::Result<size_t> result = conn.sendall(resp, sizeof resp - 1); !result) {
                std::cerr << "Error: " << result.error().message() << std::endl;
                return true;
            }

            return true; // If you return false, listen stops successfully
        });
        !result) {
        std::cerr << "Error: " << result.error().message() << std::endl;
        return 1;
    }

    if (pn::Status result = server.close(); !result) {
        std::cerr << "Error: " << result.error().message() << std::endl;
        return 1;
    }
    (void) pn::quit();
}
