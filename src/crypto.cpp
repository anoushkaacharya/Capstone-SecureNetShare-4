#include "crypto.hpp"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <fstream>
#include <vector>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <unistd.h>
std::string to_hex(const unsigned char* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    return oss.str();
}
std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
    if (hex.size() % 2 != 0) throw std::runtime_error("hex_to_bytes: odd length");
    std::vector<unsigned char> out(hex.size()/2);
    for (size_t i = 0; i < out.size(); ++i) {
        unsigned int v;
        std::istringstream iss(hex.substr(2*i, 2));
        iss >> std::hex >> v;
        out[i] = static_cast<unsigned char>(v);
    }
    return out;
}
void kdf_sha256_key32(const std::string& pass, unsigned char out_key[32]) {
    SHA256_CTX c; SHA256_Init(&c);
    SHA256_Update(&c, pass.data(), pass.size());
    SHA256_Final(out_key, &c);
}
static std::string to_hex2(const unsigned char* data, size_t len) { return to_hex(data, len); }

std::string sha256_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("sha256_file: cannot open: " + path);

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("sha256_file: ctx new failed");
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx); throw std::runtime_error("sha256_file: init failed");
    }

    std::vector<char> buf(8192);
    while (f) {
        f.read(buf.data(), buf.size());
        std::streamsize got = f.gcount();
        if (got > 0 && EVP_DigestUpdate(ctx, buf.data(), (size_t)got) != 1) {
            EVP_MD_CTX_free(ctx); throw std::runtime_error("sha256_file: update failed");
        }
    }

    unsigned char out[EVP_MAX_MD_SIZE]; unsigned int outlen=0;
    if (EVP_DigestFinal_ex(ctx, out, &outlen) != 1) {
        EVP_MD_CTX_free(ctx); throw std::runtime_error("sha256_file: final failed");
    }
    EVP_MD_CTX_free(ctx);
    return to_hex2(out, outlen);
}
size_t aes256_cbc_encrypt_file_to_socket(
    const std::string& path, int sock,
    const unsigned char key[32], const unsigned char iv[16])
{
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("encrypt: cannot open input file");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("encrypt: ctx new failed");
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("encrypt: init failed");
    }

    const size_t BUFSZ = 8192;
    std::vector<unsigned char> inbuf(BUFSZ);
    std::vector<unsigned char> outbuf(BUFSZ + EVP_MAX_BLOCK_LENGTH);

    size_t total_written = 0;
    while (in) {
        in.read(reinterpret_cast<char*>(inbuf.data()), inbuf.size());
        std::streamsize got = in.gcount();
        if (got > 0) {
            int outlen = 0;
            if (EVP_EncryptUpdate(ctx, outbuf.data(), &outlen, inbuf.data(), (int)got) != 1) {
                EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("encrypt: update failed");
            }
            if (outlen > 0) {
                ssize_t w = ::write(sock, outbuf.data(), outlen);
                if (w != outlen) { EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("encrypt: socket write failed"); }
                total_written += (size_t)w;
            }
        }
    }
    int finallen = 0;
    if (EVP_EncryptFinal_ex(ctx, outbuf.data(), &finallen) != 1) {
        EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("encrypt: final failed");
    }
    if (finallen > 0) {
        ssize_t w = ::write(sock, outbuf.data(), finallen);
        if (w != finallen) { EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("encrypt: socket write final failed"); }
        total_written += (size_t)w;
    }
    EVP_CIPHER_CTX_free(ctx);
    return total_written;
}

size_t aes256_cbc_decrypt_socket_to_file(
    int sock, size_t cipher_bytes, const std::string& out_path,
    const unsigned char key[32], const unsigned char iv[16])
{
    std::ofstream out(out_path, std::ios::binary);
    if (!out) throw std::runtime_error("decrypt: cannot open output file");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("decrypt: ctx new failed");
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("decrypt: init failed");
    }

    const size_t BUFSZ = 8192;
    std::vector<unsigned char> inbuf(BUFSZ);
    std::vector<unsigned char> outbuf(BUFSZ + EVP_MAX_BLOCK_LENGTH);

    size_t remaining = cipher_bytes;
    size_t total_plain = 0;
    while (remaining > 0) {
        size_t want = std::min(remaining, inbuf.size());
        ssize_t r = ::read(sock, inbuf.data(), want);
        if (r <= 0) { EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("decrypt: socket read failed/closed"); }
        remaining -= (size_t)r;

        int outlen = 0;
        if (EVP_DecryptUpdate(ctx, outbuf.data(), &outlen, inbuf.data(), (int)r) != 1) {
            EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("decrypt: update failed (bad key/iv?)");
        }
        if (outlen > 0) {
            out.write(reinterpret_cast<char*>(outbuf.data()), outlen);
            total_plain += (size_t)outlen;
        }
    }
    int finallen = 0;
    if (EVP_DecryptFinal_ex(ctx, outbuf.data(), &finallen) != 1) {
        EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("decrypt: final failed (wrong password?)");
    }
    if (finallen > 0) {
        out.write(reinterpret_cast<char*>(outbuf.data()), finallen);
        total_plain += (size_t)finallen;
    }
    EVP_CIPHER_CTX_free(ctx);
    return total_plain;
}
