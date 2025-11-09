#include "server.hpp"
#include "utils.hpp"
#include "crypto.hpp"
#include <iostream>
#include <thread>
#include <filesystem>
#include <fstream>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/rand.h>
#include <sstream>
#include <vector>

#define PORT 8080
#define BUFFER_SIZE 4096
namespace fs = std::filesystem;

static bool read_until_header_fd(int fd, std::string& header_out, std::string& leftover_out) {
    std::string acc;
    std::vector<char> buf(BUFFER_SIZE);
    while (true) {
        ssize_t n = ::read(fd, buf.data(), buf.size());
        if (n <= 0) return false;
        acc.append(buf.data(), buf.data() + n);
        size_t pos = acc.find("\n\n");
        size_t pos_crlf = acc.find("\r\n\r\n");
        if (pos != std::string::npos) {
            header_out = acc.substr(0, pos);
            leftover_out = acc.substr(pos + 2);
            return true;
        }
        if (pos_crlf != std::string::npos) {
            header_out = acc.substr(0, pos_crlf);
            leftover_out = acc.substr(pos_crlf + 4);
            return true;
        }
        if (acc.size() > 64 * 1024) return false;
    }
}

static void send_error(int fd, const std::string& msg) {
    std::string h = "ERROR\nMSG " + msg + "\n\n";
    ::send(fd, h.c_str(), h.size(), 0);
}
static void send_ok(const std::string& msg, int fd) {
    std::string h = "OK\nMSG " + msg + "\n\n";
    ::send(fd, h.c_str(), h.size(), 0);
}

void handle_client(int client_socket) {
    char buffer[BUFFER_SIZE];
    int bytes_read = read(client_socket, buffer, sizeof(buffer) - 1);
    if (bytes_read <= 0) { close(client_socket); return; }
    buffer[bytes_read] = '\0';
    std::string command(buffer);

    log_event("Client command: " + command);

    if (command == "LIST") {
        std::string files;
        for (const auto &entry : fs::directory_iterator("data/server_files"))
            files += entry.path().filename().string() + "\n";
        send(client_socket, files.c_str(), files.size(), 0);
    }

    else if (command.rfind("GET ", 0) == 0) {
        std::string filename = command.substr(4);
        auto ltrim = [](std::string& s){ s.erase(0, s.find_first_not_of(" \t\r\n")); };
        auto rtrim = [](std::string& s){ s.erase(s.find_last_not_of(" \t\r\n")+1); };
        ltrim(filename); rtrim(filename);

        std::string path = "data/server_files/" + filename;
        if (!fs::exists(path) || !fs::is_regular_file(path)) {
            send_error(client_socket, "File not found");
        } else {
            try {
                auto fsize = fs::file_size(path);
                std::string hash = sha256_file(path);
                std::string header = "OK\nSIZE " + std::to_string(fsize) + "\nSHA256 " + hash + "\n\n";
                send(client_socket, header.c_str(), header.size(), 0);

                std::ifstream file(path, std::ios::binary);
                char chunk[BUFFER_SIZE];
                while (file.read(chunk, sizeof(chunk)) || file.gcount()) {
                    send(client_socket, chunk, file.gcount(), 0);
                }
            } catch (const std::exception& e) {
                send_error(client_socket, e.what());
            }
        }
    }

    else if (command.rfind("GETENC ", 0) == 0) {
        std::istringstream iss(command);
        std::string cmd, filename, password;
        iss >> cmd >> filename;
        std::getline(iss, password);
        auto trim = [](std::string& s){ s.erase(0, s.find_first_not_of(" \t\r\n")); s.erase(s.find_last_not_of(" \t\r\n")+1); };
        trim(password);

        if (filename.empty() || password.empty()) { send_error(client_socket, "Missing filename or password"); close(client_socket); return; }

        std::string path = "data/server_files/" + filename;
        if (!fs::exists(path) || !fs::is_regular_file(path)) { send_error(client_socket, "File not found"); close(client_socket); return; }

        try {
            auto fsize = fs::file_size(path);
            std::string hash = sha256_file(path);
            unsigned char key[32]; kdf_sha256_key32(password, key);
            unsigned char iv[16];
            if (RAND_bytes(iv, sizeof(iv)) != 1) { send_error(client_socket, "RAND_bytes failed"); close(client_socket); return; }

            size_t pad = 16 - (fsize % 16); if (pad == 0) pad = 16;
            size_t cipher_bytes = fsize + pad;

            std::string header = "OK\nSIZE " + std::to_string(cipher_bytes) +
                                 "\nSHA256 " + hash +
                                 "\nIV " + to_hex(iv, sizeof(iv)) + "\n\n";
            send(client_socket, header.c_str(), header.size(), 0);
            log_event("Sent encrypted header for " + filename);

            aes256_cbc_encrypt_file_to_socket(path, client_socket, key, iv);
        } catch (const std::exception& e) {
            send_error(client_socket, e.what());
        }
    }

else if (command.rfind("PUT", 0) == 0) {
    log_event("Entering PUT handler");

    std::string header = command;
    std::string leftover;

    size_t header_end = header.find("\n\n");
    if (header_end != std::string::npos) {
        leftover = header.substr(header_end + 2);
        header = header.substr(0, header_end);
    }

    log_event("PUT header received:\n" + header);

    std::istringstream ih(header);
    std::string line, name, size_str, sha_hex;
    while (std::getline(ih, line)) {
        if (line.rfind("NAME ", 0) == 0)
            name = line.substr(5);
        else if (line.rfind("SIZE ", 0) == 0)
            size_str = line.substr(5);
        else if (line.rfind("SHA256 ", 0) == 0)
            sha_hex = line.substr(7);
    }

    auto trim = [](std::string &s) {
        s.erase(0, s.find_first_not_of(" \t\r\n"));
        s.erase(s.find_last_not_of(" \t\r\n") + 1);
    };
    trim(name);
    trim(size_str);
    trim(sha_hex);

    if (name.empty() || size_str.empty() || sha_hex.empty()) {
        send_error(client_socket, "Missing NAME/SIZE/SHA256");
        close(client_socket);
        return;
    }

    long long total = -1;
    try {
        total = std::stoll(size_str);
    } catch (...) {
        total = -1;
    }

    if (total <= 0) {
        send_error(client_socket, "Invalid SIZE");
        close(client_socket);
        return;
    }

    fs::create_directories("data/server_files");
    std::string outpath = "data/server_files/" + name;
    std::ofstream out(outpath, std::ios::binary);
    if (!out.is_open()) {
        send_error(client_socket, "Failed to open file for writing");
        close(client_socket);
        return;
    }

    log_event("Receiving upload: " + name + " (" + std::to_string(total) + " bytes)");

    long long written = 0;

    if (!leftover.empty()) {
        out.write(leftover.data(), leftover.size());
        written += leftover.size();
    }

    char buffer[BUFFER_SIZE];
    while (written < total) {
        ssize_t n = read(client_socket, buffer, sizeof(buffer));
        if (n <= 0) {
            send_error(client_socket, "Connection closed during upload");
            out.close();
            std::remove(outpath.c_str());
            close(client_socket);
            return;
        }
        out.write(buffer, n);
        written += n;
    }

    out.close();
    log_event("Upload complete for " + name + ", verifying SHA-256...");

    try {
        std::string local_hash = sha256_file(outpath);
        if (local_hash == sha_hex) {
            send_ok("Upload complete and verified", client_socket);
            log_event("File " + name + " uploaded and verified OK.");
        } else {
            std::remove(outpath.c_str());
            send_error(client_socket, "SHA-256 mismatch");
            log_event("SHA mismatch for uploaded file " + name);
        }
    } catch (const std::exception &e) {
        send_error(client_socket, e.what());
        std::remove(outpath.c_str());
        log_event(std::string("Upload verification error: ") + e.what());
    }

    close(client_socket);
    return;
}


    else if (command == "PUTENC") {
        std::string header, leftover;
        if (!read_until_header_fd(client_socket, header, leftover)) { send_error(client_socket, "Failed to read PUTENC header"); close(client_socket); return; }

        std::istringstream ih(header);
        std::string line, name, size_str, sha_hex, iv_hex;
        while (std::getline(ih, line)) {
            if (line.rfind("NAME ", 0) == 0) name = line.substr(5);
            else if (line.rfind("SIZE ", 0) == 0) size_str = line.substr(5);
            else if (line.rfind("SHA256 ", 0) == 0) sha_hex = line.substr(7);
            else if (line.rfind("IV ", 0) == 0) iv_hex = line.substr(3);
        }
        auto trim = [](std::string& s){ s.erase(0, s.find_first_not_of(" \t\r\n")); s.erase(s.find_last_not_of(" \t\r\n")+1); };
        trim(name); trim(size_str); trim(sha_hex); trim(iv_hex);
        if (name.empty() || size_str.empty() || sha_hex.empty() || iv_hex.empty()) { send_error(client_socket, "Missing NAME/SIZE/SHA256/IV"); close(client_socket); return; }

        long long cipher_total = -1; try { cipher_total = std::stoll(size_str); } catch (...) {}
        if (cipher_total <= 0) { send_error(client_socket, "Bad SIZE"); close(client_socket); return; }

        std::string password = "mysecret";
        {
            std::istringstream ih2(header);
            while (std::getline(ih2, line)) {
                if (line.rfind("PASS ", 0) == 0) { password = line.substr(5); trim(password); break; }
            }
        }

        unsigned char key[32]; kdf_sha256_key32(password, key);
        std::vector<unsigned char> ivb = hex_to_bytes(iv_hex);
        if (ivb.size() != 16) { send_error(client_socket, "Bad IV length"); close(client_socket); return; }
        unsigned char iv[16]; std::copy(ivb.begin(), ivb.end(), iv);

        fs::create_directories("data/server_files");
        std::string outpath = "data/server_files/" + name;

        try {
            std::ofstream out(outpath, std::ios::binary);
            if (!out) { send_error(client_socket, "Cannot open output file"); close(client_socket); return; }

            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (!ctx) { out.close(); send_error(client_socket, "EVP ctx new failed"); close(client_socket); return; }
            if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
                EVP_CIPHER_CTX_free(ctx); out.close(); send_error(client_socket, "EVP decrypt init failed"); close(client_socket); return;
            }

            std::vector<unsigned char> outbuf(BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
            long long remaining = cipher_total;

            if (!leftover.empty()) {
                size_t take = std::min<long long>(remaining, leftover.size());
                int outlen = 0;
                if (EVP_DecryptUpdate(ctx, outbuf.data(), &outlen,
                                      reinterpret_cast<const unsigned char*>(leftover.data()), (int)take) != 1) {
                    EVP_CIPHER_CTX_free(ctx); out.close(); std::remove(outpath.c_str()); send_error(client_socket, "Decrypt update failed (leftover)"); close(client_socket); return;
                }
                if (outlen > 0) out.write(reinterpret_cast<char*>(outbuf.data()), outlen);
                leftover.erase(0, take);
                remaining -= take;
            }

            std::vector<unsigned char> inbuf(BUFFER_SIZE);
            while (remaining > 0) {
                size_t want = std::min<long long>(remaining, inbuf.size());
                ssize_t r = ::read(client_socket, inbuf.data(), want);
                if (r <= 0) { EVP_CIPHER_CTX_free(ctx); out.close(); std::remove(outpath.c_str()); send_error(client_socket, "Socket closed during upload"); close(client_socket); return; }
                remaining -= (long long)r;

                int outlen = 0;
                if (EVP_DecryptUpdate(ctx, outbuf.data(), &outlen, inbuf.data(), (int)r) != 1) {
                    EVP_CIPHER_CTX_free(ctx); out.close(); std::remove(outpath.c_str()); send_error(client_socket, "Decrypt update failed"); close(client_socket); return;
                }
                if (outlen > 0) out.write(reinterpret_cast<char*>(outbuf.data()), outlen);
            }

            int finallen = 0;
            if (EVP_DecryptFinal_ex(ctx, outbuf.data(), &finallen) != 1) {
                EVP_CIPHER_CTX_free(ctx); out.close(); std::remove(outpath.c_str()); send_error(client_socket, "Decrypt final failed (wrong password?)"); close(client_socket); return;
            }
            if (finallen > 0) out.write(reinterpret_cast<char*>(outbuf.data()), finallen);

            EVP_CIPHER_CTX_free(ctx);
            out.close();

            std::string got = sha256_file(outpath);
            if (got == sha_hex) send_ok("Encrypted upload complete", client_socket);
            else { std::remove(outpath.c_str()); send_error(client_socket, "SHA-256 mismatch after decrypt"); }
        } catch (const std::exception& e) {
            std::remove(outpath.c_str()); send_error(client_socket, e.what());
        }
    }

    else {
        send_error(client_socket, "Unknown command");
    }

    close(client_socket);
}

void start_server() {
    fs::create_directories("data/server_files");
    fs::create_directories("data/client_files");

    int server_fd, client_socket;
    struct sockaddr_in address{};
    int opt = 1;
    socklen_t addrlen = sizeof(address);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 5);

    log_event("Server listening on port " + std::to_string(PORT));

    while (true) {
        client_socket = accept(server_fd, (struct sockaddr *)&address, &addrlen);
        std::thread(handle_client, client_socket).detach();
    }
}
