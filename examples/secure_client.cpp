#include "../polynet.hpp"
#include "../secure_sockets.hpp"
#include <iostream>

int main() {
    pn::init();

    pn::tcp::SecureClient client;
    if (client.connect("localhost", 443) == PN_ERROR) {
        std::cerr << "Error: " << pn::universal_strerror() << std::endl;
        return 1;
    }
    if (client.ssl_init("localhost", SSL_VERIFY_PEER, "cert.pem") == PN_ERROR) {
        std::cerr << "Error: " << pn::universal_strerror() << std::endl;
        return 1;
    }
    if (client.ssl_connect() == PN_ERROR) {
        std::cerr << "Error: " << pn::universal_strerror() << std::endl;
        return 1;
    }

    const char req[] = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    if (client.sendall(req, sizeof req - 1) == PN_ERROR) {
        std::cerr << "Error: " << pn::universal_strerror() << std::endl;
        return 1;
    }

    char resp[32000];
    pn::ssize_t result;
    if ((result = client.recv(resp, 32000)) == PN_ERROR) {
        std::cerr << "Error: " << pn::universal_strerror() << std::endl;
        return 1;
    }
    resp[result] = '\0';
    std::cout << resp << std::endl;

    client.close();
    pn::quit();
}
