#include "../polynet.hpp"
#include "../tls.hpp"
#include <iostream>
#include <openssl/ssl.h>

int main() {
    (void) pn::init();

    pn::tcp::TLSServer server;
    if (pn::Status result = server.bind("0.0.0.0", 443); !result) {
        std::cerr << "Error: " << result.error().message() << std::endl;
        return 1;
    }
    pn::TLSContext context;
    if (pn::Status result = context.init_server("cert.pem", "key.pem", SSL_FILETYPE_PEM); !result) {
        std::cerr << "Error: " << result.error().message() << std::endl;
        return 1;
    }

    if (pn::Status result = server.listen(context, [](pn::tcp::TLSConnection conn) {
            // This is only necessary for secure servers
            if (pn::Status result = conn.tls_accept(); !result) {
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
