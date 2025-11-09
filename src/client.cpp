#include "client.hpp"
#include "utils.hpp"
#include "crypto.hpp"
#include <iostream>
#include <arpa/inet.h>
#include <unistd.h>
#include <fstream>
#include <algorithm>
#include <string>
#include <sstream>
#include <filesystem>
#include <vector>
#include <openssl/rand.h> 

#define PORT 8080
#define BUFFER_SIZE 4096
namespace fs = std::filesystem;

static bool read_until_header(int sock, std::string &header_out, std::string &leftover_out) {
    std::string acc;
    char buf[BUFFER_SIZE];
    while (true) {
        ssize_t n = read(sock, buf, sizeof(buf));
        if (n <= 0) return false;
        acc.append(buf, buf + n);

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

void client_mode(const std::string &server_ip) {
    while (true) {
        std::cout << "\nCommands: LIST | GET <filename> | GETENC <filename> | PUT <localpath> | PUTENC <localpath> | EXIT\n> ";
        std::string cmd;
        std::getline(std::cin, cmd);

        cmd.erase(0, cmd.find_first_not_of(" \t\n\r"));
        if (cmd.empty()) continue;
        cmd.erase(cmd.find_last_not_of(" \t\n\r") + 1);

        if (cmd == "EXIT") break;

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in serv_addr {};
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(PORT);
        inet_pton(AF_INET, server_ip.c_str(), &serv_addr.sin_addr);

        if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
            log_event("Connection failed");
            close(sock);
            continue;
        }

        if (cmd == "LIST") {
            send(sock, cmd.c_str(), cmd.size(), 0);

            char buffer[BUFFER_SIZE];
            int bytes;
            bool any = false;
            while ((bytes = read(sock, buffer, sizeof(buffer))) > 0) {
                any = true;
                std::cout.write(buffer, bytes);
            }
            if (!any) std::cout << "(no files)\n";
            close(sock);
            continue;
        }

        else if (cmd.rfind("GET ", 0) == 0) {
            send(sock, cmd.c_str(), cmd.size(), 0);

            std::string filename = cmd.substr(4);
            filename.erase(0, filename.find_first_not_of(" \t\n\r"));
            filename.erase(filename.find_last_not_of(" \t\n\r") + 1);
            if (filename.empty()) { log_event("No filename provided."); close(sock); continue; }

            std::string header, leftover;
            if (!read_until_header(sock, header, leftover)) {
                log_event("Failed to read response header."); close(sock); continue;
            }

            bool is_ok = false;
            std::istringstream iss(header);
            std::string first;
            if (!(iss >> first)) { log_event("Malformed header."); close(sock); continue; }
            if (first == "OK") is_ok = true;
            else if (first == "ERROR") { std::string rest; std::getline(iss, rest); std::cerr << "ERROR from server: " << rest << "\n"; close(sock); continue; }
            else { log_event("Unexpected header: " + first); close(sock); continue; }

            std::string size_str, sha_hex, line;
            while (std::getline(iss, line)) {
                if (line.rfind("SIZE ", 0) == 0) size_str = line.substr(5);
                else if (line.rfind("SHA256 ", 0) == 0) sha_hex = line.substr(7);
            }
            auto trim = [](std::string &s){ s.erase(0, s.find_first_not_of(" \t\r\n")); s.erase(s.find_last_not_of(" \t\r\n")+1); };
            trim(size_str); trim(sha_hex);
            if (!is_ok || size_str.empty() || sha_hex.empty()) { log_event("Invalid OK header (missing SIZE/SHA256)."); close(sock); continue; }

            long long total = -1; try { total = std::stoll(size_str); } catch (...) {}
            if (total < 0) { log_event("Invalid SIZE value."); close(sock); continue; }

            std::string outpath = "data/client_files/" + filename;
            std::ofstream outfile(outpath, std::ios::binary);
            if (!outfile.is_open()) { log_event("Error opening file for writing: " + outpath); close(sock); continue; }

            log_event("Downloading " + filename + " (" + std::to_string(total) + " bytes) ...");

            long long written = 0;
            if (!leftover.empty()) { outfile.write(leftover.data(), leftover.size()); written += (long long)leftover.size(); }

            char buffer[BUFFER_SIZE];
            while (written < total) {
                ssize_t need = (ssize_t)std::min<long long>(BUFFER_SIZE, total - written);
                ssize_t n = read(sock, buffer, need);
                if (n <= 0) { log_event("Connection closed before receiving full file."); break; }
                outfile.write(buffer, n);
                written += n;
            }

            outfile.close();
            close(sock);

            if (written == total) {
                try {
                    std::string local = sha256_file(outpath);
                    if (local == sha_hex) log_event("File downloaded successfully (SHA-256 verified).");
                    else log_event("WARNING: SHA-256 mismatch! Expected " + sha_hex + " got " + local);
                } catch (const std::exception &e) {
                    log_event(std::string("Hashing error: ") + e.what());
                }
            } else {
                log_event("Download incomplete. Removing partial file.");
                std::remove(outpath.c_str());
            }
            continue;
        }

        else if (cmd.rfind("GETENC ", 0) == 0) {
            std::string filename = cmd.substr(7);
            filename.erase(0, filename.find_first_not_of(" \t\n\r"));
            filename.erase(filename.find_last_not_of(" \t\n\r") + 1);
            if (filename.empty()) { log_event("No filename provided."); close(sock); continue; }

            std::string password;
            std::cout << "Password: ";
            std::getline(std::cin, password);

            std::string wire = "GETENC " + filename + " " + password + "\n";
            send(sock, wire.c_str(), wire.size(), 0);

            std::string header, leftover;
            if (!read_until_header(sock, header, leftover)) {
                log_event("Failed to read response header."); close(sock); continue;
            }

            std::istringstream iss(header);
            std::string first; iss >> first;
            if (first != "OK") { std::string rest; std::getline(iss, rest); std::cerr << "ERROR from server:" << rest << "\n"; close(sock); continue; }

            std::string size_str, sha_hex, iv_hex, line;
            while (std::getline(iss, line)) {
                if (line.rfind("SIZE ", 0) == 0) size_str = line.substr(5);
                else if (line.rfind("SHA256 ", 0) == 0) sha_hex = line.substr(7);
                else if (line.rfind("IV ", 0) == 0) iv_hex = line.substr(3);
            }
            auto trim = [](std::string &s){ s.erase(0, s.find_first_not_of(" \t\r\n")); s.erase(s.find_last_not_of(" \t\r\n")+1); };
            trim(size_str); trim(sha_hex); trim(iv_hex);
            if (size_str.empty() || sha_hex.empty() || iv_hex.empty()) { log_event("Invalid header (missing SIZE/SHA256/IV)"); close(sock); continue; }

            long long cipher_total = -1; try { cipher_total = std::stoll(size_str); } catch (...) {}
            if (cipher_total < 0) { log_event("Bad SIZE"); close(sock); continue; }

            unsigned char key[32]; kdf_sha256_key32(password, key);
            std::vector<unsigned char> ivb = hex_to_bytes(iv_hex);
            if (ivb.size() != 16) { log_event("Bad IV length"); close(sock); continue; }
            unsigned char iv[16]; std::copy(ivb.begin(), ivb.end(), iv);

            std::string outpath = "data/client_files/" + filename;
            log_event("Downloading " + filename + " (encrypted " + std::to_string(cipher_total) + " bytes) ...");

            try {
                aes256_cbc_decrypt_socket_to_file(sock, cipher_total, outpath, key, iv);
                close(sock);
                std::string local = sha256_file(outpath);
                if (local == sha_hex) log_event("Encrypted download verified (SHA-256 OK).");
                else log_event("WARNING: SHA-256 mismatch after decrypt!");
            } catch (const std::exception &e) {
                log_event(std::string("Decryption error: ") + e.what());
                close(sock);
            }
            continue;
        }

        else if (cmd.rfind("PUT ", 0) == 0) {
            std::string local = cmd.substr(4);
            local.erase(0, local.find_first_not_of(" \t\n\r"));
            local.erase(local.find_last_not_of(" \t\n\r") + 1);
            if (local.empty() || !fs::exists(local) || !fs::is_regular_file(local)) {
                log_event("Local file not found: " + local); close(sock); continue;
            }
            std::string filename = fs::path(local).filename().string();
            auto fsize = fs::file_size(local);
            std::string hash = sha256_file(local);

            std::ostringstream oss;
            oss << "PUT\nNAME " << filename
                << "\nSIZE " << fsize
                << "\nSHA256 " << hash
                << "\n\n";
            std::string header = oss.str();
            send(sock, header.c_str(), header.size(), 0);

            std::ifstream in(local, std::ios::binary);
            std::vector<char> buf(BUFFER_SIZE);
            while (in) {
                in.read(buf.data(), buf.size());
                std::streamsize got = in.gcount();
                if (got > 0) {
                    ssize_t w = ::write(sock, buf.data(), got);
                    if (w != got) { log_event("Socket write failed during PUT"); break; }
                }
            }

            std::string rep, leftover;
            if (!read_until_header(sock, rep, leftover)) { log_event("No server reply."); close(sock); continue; }
            std::istringstream ir(rep);
            std::string first; ir >> first;
            std::string rest; std::getline(ir, rest);
            if (first == "OK") log_event("Upload complete.");
            else std::cerr << "ERROR from server:" << rest << "\n";

            close(sock);
            continue;
        }

        else if (cmd.rfind("PUTENC ", 0) == 0) {
            std::string local = cmd.substr(7);
            local.erase(0, local.find_first_not_of(" \t\n\r"));
            local.erase(local.find_last_not_of(" \t\n\r") + 1);
            if (local.empty() || !fs::exists(local) || !fs::is_regular_file(local)) {
                log_event("Local file not found: " + local); close(sock); continue;
            }

            std::string password;
            std::cout << "Password: ";
            std::getline(std::cin, password);

            std::string filename = fs::path(local).filename().string();
            auto fsize = fs::file_size(local);
            size_t pad = 16 - (fsize % 16); if (pad == 0) pad = 16;
            size_t cipher_bytes = fsize + pad;
            std::string plain_hash = sha256_file(local);

            unsigned char key[32]; kdf_sha256_key32(password, key);
            unsigned char iv[16];
            if (!RAND_bytes(iv, sizeof(iv))) { log_event("Failed to generate IV"); close(sock); continue; }

            std::ostringstream oss;
            oss << "PUTENC\nNAME " << filename
                << "\nSIZE " << cipher_bytes
                << "\nSHA256 " << plain_hash
                << "\nIV " << to_hex(iv, sizeof(iv))
                << "\n\n";
            std::string header = oss.str();
            send(sock, header.c_str(), header.size(), 0);

            try {
                aes256_cbc_encrypt_file_to_socket(local, sock, key, iv);
            } catch (const std::exception& e) {
                log_event(std::string("Encrypt/send failed: ") + e.what());
                close(sock); continue;
            }

            std::string rep, leftover;
            if (!read_until_header(sock, rep, leftover)) { log_event("No server reply."); close(sock); continue; }
            std::istringstream ir(rep);
            std::string first; ir >> first;
            std::string rest; std::getline(ir, rest);
            if (first == "OK") log_event("Encrypted upload complete.");
            else std::cerr << "ERROR from server:" << rest << "\n";

            close(sock);
            continue;
        }

        else {
            send(sock, cmd.c_str(), cmd.size(), 0);
            char buffer[BUFFER_SIZE];
            int bytes;
            while ((bytes = read(sock, buffer, sizeof(buffer))) > 0) {
                std::cout.write(buffer, bytes);
            }
            close(sock);
        }
    }
}
