#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iostream>
#include <vector>
#include <thread>
#include <string>
#include <cstdio>

#pragma comment(lib, "ws2_32.lib")

// Encrypt AES-256-CBC
std::vector<unsigned char> encryptAES(const std::string &plaintext,
    const unsigned char key[32], const unsigned char iv[16])
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> ciphertext(plaintext.size() + 32);

    int len = 0, ciphertext_len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                      (unsigned char*)plaintext.c_str(), plaintext.size());
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;

    ciphertext.resize(ciphertext_len);
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}

// Decrypt AES-256-CBC
std::string decryptAES(const unsigned char *ciphertext, int ciphertext_len,
    const unsigned char key[32], const unsigned char iv[16])
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> plaintext(ciphertext_len + 32);

    int len = 0, plaintext_len = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                      ciphertext, ciphertext_len);
    plaintext_len = len;

    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    plaintext_len += len;

    plaintext.resize(plaintext_len);
    EVP_CIPHER_CTX_free(ctx);

    return std::string(plaintext.begin(), plaintext.end());
}

// Receiver thread
void receiverThread(int listenPort,
                    const unsigned char key[32],
                    const unsigned char iv[16])
{
    SOCKET recvSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    sockaddr_in recvAddr{};
    recvAddr.sin_family = AF_INET;
    recvAddr.sin_addr.s_addr = INADDR_ANY;
    recvAddr.sin_port = htons(listenPort);

    bind(recvSock, (sockaddr*)&recvAddr, sizeof(recvAddr));

    std::cout << "Receiver running on port " << listenPort << "...\n";

    while (true)
    {
        unsigned char buffer[2048];

        sockaddr_in sender{};
        int senderSize = sizeof(sender);

        int bytes = recvfrom(recvSock, (char*)buffer, sizeof(buffer), 0,
            (sockaddr*)&sender, &senderSize);

        if (bytes > 0)
        {
            std::string plain = decryptAES(buffer, bytes, key, iv);
            std::cout << "\n🔐 Received: " << plain << "\n> ";
        }
    }
}

// Convert hex → bytes
void hexToBytes(const std::string &hex, unsigned char* out, int maxLen)
{
    for (int i = 0; i < maxLen; i++) {
        std::string byteStr = hex.substr(i * 2, 2);
        out[i] = (unsigned char)strtol(byteStr.c_str(), nullptr, 16);
    }
}

// Print bytes as HEX
void printHex(const unsigned char* data, int len)
{
    for (int i = 0; i < len; i++)
        printf("%02X", data[i]);
}

int main()
{
    // Init Winsock
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    // Key/IV buffers
    unsigned char key[32];
    unsigned char iv[16];

    // ---- KEY/IV MODE ----
    int mode;
    std::cout << "AES KEY/IV MODE:\n";
    std::cout << "1. Generate new AES key & IV (host)\n";
    std::cout << "2. Enter existing AES key & IV (join)\n";
    std::cout << "Choose (1/2): ";
    std::cin >> mode;

    if (mode == 1)
    {
        RAND_bytes(key, sizeof(key));
        RAND_bytes(iv, sizeof(iv));

        std::cout << "\n=== SHARE THESE WITH THE OTHER PERSON ===\n";
        std::cout << "KEY (64 hex chars): ";
        printHex(key, 32);
        std::cout << "\n";

        std::cout << "IV  (32 hex chars): ";
        printHex(iv, 16);
        std::cout << "\n";
        std::cout << "=========================================\n\n";
    }
    else if (mode == 2)
    {
        std::string keyHex, ivHex;

        std::cout << "Enter KEY (64 hex chars): ";
        std::cin >> keyHex;

        std::cout << "Enter IV  (32 hex chars): ";
        std::cin >> ivHex;

        if (keyHex.length() != 64 || ivHex.length() != 32)
        {
            std::cout << "Invalid key/IV length.\n";
            return 0;
        }

        hexToBytes(keyHex, key, 32);
        hexToBytes(ivHex, iv, 16);

        std::cout << "Key/IV loaded.\n\n";
    }
    else
    {
        std::cout << "Invalid choice.\n";
        return 0;
    }

    // ---- Network params ----
    std::string targetIp;
    int targetPort, listenPort;

    std::cout << "Enter target IP: ";
    std::cin >> targetIp;

    std::cout << "Enter target port: ";
    std::cin >> targetPort;

    std::cout << "Enter local listening port: ";
    std::cin >> listenPort;

    // Start receiver thread
    std::thread t(receiverThread, listenPort, key, iv);
    t.detach();

    // Sender socket
    SOCKET sendSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_port = htons(targetPort);
    target.sin_addr.s_addr = inet_addr(targetIp.c_str());

    std::cin.ignore(); // clear input
    std::cout << "\nReady! Type messages below.\n\n";

    while (true)
    {
        std::string msg;
        std::cout << "> ";
        std::getline(std::cin, msg);

        auto encrypted = encryptAES(msg, key, iv);

        sendto(sendSock, (char*)encrypted.data(), encrypted.size(), 0,
               (sockaddr*)&target, sizeof(target));
    }

    closesocket(sendSock);
    WSACleanup();
    return 0;
}
