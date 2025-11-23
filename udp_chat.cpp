#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iostream>
#include <thread>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

// =========================
// AES256 Encrypt Function
// =========================
std::vector<unsigned char> encryptAES(const std::string &plaintext,
                                      const unsigned char key[32],
                                      const unsigned char iv[16])
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

// =========================
// AES256 Decrypt Function
// =========================
std::string decryptAES(const unsigned char *ciphertext, int ciphertext_len,
                       const unsigned char key[32],
                       const unsigned char iv[16])
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

// =====================================
// RECEIVER THREAD (decrypts messages)
// =====================================
void receiver_thread(int listen_port,
                     const unsigned char key[32],
                     const unsigned char iv[16])
{
    SOCKET recvSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    sockaddr_in recvAddr{};
    recvAddr.sin_family = AF_INET;
    recvAddr.sin_addr.s_addr = INADDR_ANY;
    recvAddr.sin_port = htons(listen_port);

    bind(recvSock, (sockaddr*)&recvAddr, sizeof(recvAddr));

    std::cout << "Receiver running on port " << listen_port << "...\n";

    while (true)
    {
        unsigned char buffer[2048];
        sockaddr_in sender{};
        int senderSize = sizeof(sender);

        int bytes = recvfrom(recvSock, (char*)buffer, sizeof(buffer), 0,
            (sockaddr*)&sender, &senderSize);

        if (bytes > 0)
        {
            std::string decrypted = decryptAES(buffer, bytes, key, iv);
            std::cout << "\n🔐 Received (decrypted): " << decrypted << "\n> ";
        }
    }
}

// ==============================
// MAIN (Sender + Receiver)
// ==============================
int main()
{
    // Initialize Winsock
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    // --- AES key and IV (shared secret) ---
    unsigned char key[32];
    unsigned char iv[16];

    // Generate random key+iv (OR hard-code for testing)
    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));

    auto printHex = [](const unsigned char* data, int len) {
        for (int i = 0; i < len; i++)
            printf("%02X", data[i]);
    };

    std::cout << "===========================\n";
    std::cout << " AES-256 CHAT CRYPTO KEYS\n";
    std::cout << "===========================\n";

    std::cout << "KEY (32 bytes) : ";
    printHex(key, 32);
    std::cout << "\n";

    std::cout << "IV  (16 bytes) : ";
    printHex(iv, 16);
    std::cout << "\n\n";

    std::cout << "Share KEY + IV with the person running the other copy.\n";
    std::cout << "They must paste EXACT same values.\n\n";


    std::string target_ip;
    int target_port, listen_port;

    std::cout << "Enter target IP: ";
    std::cin >> target_ip;

    std::cout << "Enter target port: ";
    std::cin >> target_port;

    std::cout << "Enter local listening port: ";
    std::cin >> listen_port;

    // Start receiver thread
    std::thread recvThread(receiver_thread, listen_port, key, iv);
    recvThread.detach();

    // Sender
    SOCKET sendSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_port = htons(target_port);
    target.sin_addr.s_addr = inet_addr(target_ip.c_str());

    std::cout << "\nType your messages (AES encrypted):\n";

    std::cin.ignore();
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
