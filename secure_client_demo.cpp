#include "polynet.hpp"
#include "secure_sockets.hpp"

int main() {
    pn::init();

    pn::tcp::SecureClient client;
    if (client.connect("example.com", 443) == PN_ERROR) {
        std::cerr << "Error: " << pn::universal_strerror() << std::endl;
        return 1;
    }
    if (client.ssl_init("example.com") == PN_ERROR) {
        std::cerr << "Error: " << pn::universal_strerror() << std::endl;
        return 1;
    }
    if (client.ssl_connect() == PN_ERROR) {
        std::cerr << "Error: " << pn::universal_strerror() << std::endl;
        return 1;
    }

    const char buf[] = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    if (client.sendall(buf, sizeof buf - 1) == PN_ERROR) {
        std::cerr << "Error: " << pn::universal_strerror() << std::endl;
        return 1;
    }

    char resp[32000];
    long result;
    if ((result = client.recv(resp, 32000)) == PN_ERROR) {
        std::cerr << "Error: " << pn::universal_strerror() << std::endl;
        return 1;
    }
    resp[result] = '\0';
    std::cout << resp << std::endl;

    pn::quit();
}
