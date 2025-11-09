#include "client.hpp"
#include <iostream>
int main() {
    std::string server_ip;
    std::cout << "Enter server IP (e.g., 127.0.0.1): ";
    std::cin >> server_ip;
    std::cin.ignore();
    client_mode(server_ip);
    return 0;
}
