#include "../polynet.hpp"
#include "../secure_sockets.hpp"
#include <iostream>

int main() {
    (void) pn::init();

    pn::tcp::SecureClient client;
    if (pn::Status result = client.connect("localhost", 443); !result) {
        std::cerr << "Error: " << result.error().message() << std::endl;
        return 1;
    }
    if (pn::Status result = client.ssl_init("localhost", SSL_VERIFY_PEER, "cert.pem"); !result) {
        std::cerr << "Error: " << result.error().message() << std::endl;
        return 1;
    }
    if (pn::Status result = client.ssl_connect(); !result) {
        std::cerr << "Error: " << result.error().message() << std::endl;
        return 1;
    }

    const char req[] = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    if (pn::Result<size_t> result = client.sendall(req, sizeof req - 1); !result) {
        std::cerr << "Error: " << result.error().message() << std::endl;
        return 1;
    }

    char resp[32000];
    if (pn::Result<size_t> result = client.recv(resp, sizeof resp - 1); !result) {
        std::cerr << "Error: " << result.error().message() << std::endl;
        return 1;
    } else {
        resp[*result] = '\0';
    }
    std::cout << resp << std::endl;

    if (pn::Status result = client.close(); !result) {
        std::cerr << "Error: " << result.error().message() << std::endl;
        return 1;
    }
    (void) pn::quit();
}
