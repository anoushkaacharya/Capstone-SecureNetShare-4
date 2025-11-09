#ifndef CRYPTO_HPP
#define CRYPTO_HPP

#include <string>
#include <vector>
std::string sha256_file(const std::string& path);
std::string to_hex(const unsigned char* data, size_t len);
std::vector<unsigned char> hex_to_bytes(const std::string& hex);
void kdf_sha256_key32(const std::string& pass, unsigned char out_key[32]);
size_t aes256_cbc_encrypt_file_to_socket(
    const std::string& path, int sock,
    const unsigned char key[32], const unsigned char iv[16]);
size_t aes256_cbc_decrypt_socket_to_file(
    int sock, size_t cipher_bytes, const std::string& out_path,
    const unsigned char key[32], const unsigned char iv[16]);

#endif
