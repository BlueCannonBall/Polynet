#include "../polynet.hpp"
#include "../secure_sockets.hpp"
#include <iostream>
#include <openssl/ssl.h>

int main() {
    pn::init();

    pn::tcp::SecureServer server;
    if (server.bind("0.0.0.0", 443) == PN_ERROR) {
        std::cerr << "Error: " << pn::universal_strerror() << std::endl;
        return 1;
    }
    if (server.ssl_init("cert.pem", "key.pem", SSL_FILETYPE_PEM) == PN_ERROR) {
        std::cerr << "Error: " << pn::universal_strerror() << std::endl;
        return 1;
    }

    if (server.listen([](pn::tcp::SecureConnection& conn, void*) {
            // This is only necessary for secure servers
            if (conn.ssl_accept() == PN_ERROR) {
                std::cerr << "Error: " << pn::universal_strerror() << std::endl;
                return true;
            }

            char req[32000];
            long result;
            if ((result = conn.recv(req, 32000)) == PN_ERROR) {
                std::cerr << "Error: " << pn::universal_strerror() << std::endl;
                conn.close();
                return true;
            }
            req[result] = '\0';
            std::cout << req << std::endl;

            const char resp[] = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\nContent-Type: text/plain\r\n\r\nHello, World!";
            if (conn.sendall(resp, sizeof resp - 1) == PN_ERROR) {
                std::cerr << "Error: " << pn::universal_strerror() << std::endl;
                conn.close();
                return true;
            }

            return true; // If you return false, the listen function stops and returns PN_OK
        }) == PN_ERROR) {
        std::cerr << "Error: " << pn::universal_strerror() << std::endl;
        return 1;
    }

    server.close();
    pn::quit();
}
