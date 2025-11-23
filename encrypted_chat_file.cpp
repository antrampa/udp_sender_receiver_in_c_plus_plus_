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
#include <fstream>
#include <mutex>
#include <atomic>
#include <chrono>

#pragma comment(lib, "ws2_32.lib")

// ========== CONFIG ==========
const int PLAINTEXT_CHUNK = 1024; // bytes per file plaintext chunk (safe for UDP)
const int MAX_UDP_PACKET = 1400;  // don't exceed typical MTU

// ========== AES helpers (binary-safe) ==========
std::vector<unsigned char> encryptAES_bin(const unsigned char* data, int data_len,
    const unsigned char key[32], const unsigned char iv[16])
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> ciphertext(data_len + 32);
    int len = 0, ciphertext_len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, data, data_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;

    ciphertext.resize(ciphertext_len);
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

std::vector<unsigned char> encryptAES_str(const std::string& s,
    const unsigned char key[32], const unsigned char iv[16])
{
    return encryptAES_bin((const unsigned char*)s.data(), (int)s.size(), key, iv);
}

std::vector<unsigned char> decryptAES_bin(const unsigned char* ciphertext, int ciphertext_len,
    const unsigned char key[32], const unsigned char iv[16], bool &ok)
{
    ok = false;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> plaintext(ciphertext_len + 32);
    int len = 0, plaintext_len = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    if (!EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    plaintext_len = len;

    if (!EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) {
        // decryption failed (bad padding / wrong key)
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    plaintext_len += len;

    plaintext.resize(plaintext_len);
    EVP_CIPHER_CTX_free(ctx);
    ok = true;
    return plaintext;
}

std::string bytesToHex(const unsigned char* data, int len) {
    std::string out;
    char buf[3];
    for (int i = 0; i < len; ++i) {
        sprintf(buf, "%02X", data[i]);
        out += buf;
    }
    return out;
}

void hexToBytes(const std::string &hex, unsigned char* out, int maxLen) {
    for (int i = 0; i < maxLen; i++) {
        std::string byteStr = hex.substr(i * 2, 2);
        out[i] = (unsigned char)strtol(byteStr.c_str(), nullptr, 16);
    }
}

void printHex(const unsigned char* data, int len) {
    for (int i = 0; i < len; i++) printf("%02X", data[i]);
}

// ========== File-transfer shared state ==========
std::mutex fileMutex;
std::ofstream recvFile;
std::atomic<bool> transferActive(false);
std::uint64_t expectedFileSize = 0;
std::uint64_t receivedBytesCount = 0;
std::string recvFilename;

// ========== Receiver thread ==========
void receiverThread(int listenPort, const unsigned char key[32], const unsigned char iv[16]) {
    SOCKET recvSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (recvSock == INVALID_SOCKET) {
        std::cout << "Receiver: socket() failed\n";
        return;
    }

    sockaddr_in recvAddr{};
    recvAddr.sin_family = AF_INET;
    recvAddr.sin_addr.s_addr = INADDR_ANY;
    recvAddr.sin_port = htons(listenPort);

    if (bind(recvSock, (sockaddr*)&recvAddr, sizeof(recvAddr)) == SOCKET_ERROR) {
        std::cout << "Receiver: bind() failed\n";
        closesocket(recvSock);
        return;
    }

    std::cout << "Receiver running on port " << listenPort << "...\n";

    while (true) {
        unsigned char buffer[2048];
        sockaddr_in sender{};
        int senderSize = sizeof(sender);

        int bytes = recvfrom(recvSock, (char*)buffer, sizeof(buffer), 0,
            (sockaddr*)&sender, &senderSize);

        if (bytes <= 0) continue;

        bool ok;
        auto plain = decryptAES_bin(buffer, bytes, key, iv, ok);
        if (!ok) {
            // Could be wrong key/IV or garbage packet - ignore
            // std::cout << "[!] Decryption failed (maybe wrong key)\n";
            continue;
        }

        // interpret plaintext
        // plaintext is binary-safe, but we used textual prefixes:
        const std::string prefix_file_start = "FILE_START|";
        const std::string prefix_file_chunk = "FILE_CHUNK|";
        const std::string prefix_msg = "MSG|";

        if (plain.size() >= prefix_file_start.size() &&
            std::equal(prefix_file_start.begin(), prefix_file_start.end(), plain.begin())) {
            // FILE_START|filename|size
            std::string payload((char*)plain.data(), plain.size());
            // parse
            size_t p1 = payload.find('|', 0); // after FILE_START
            size_t p2 = payload.find('|', p1 + 1);
            if (p1 == std::string::npos || p2 == std::string::npos) continue;
            std::string filename = payload.substr(p1 + 1, p2 - (p1 + 1));
            std::string sizeStr = payload.substr(p2 + 1);
            uint64_t fsize = std::stoull(sizeStr);

            std::lock_guard<std::mutex> lk(fileMutex);
            if (recvFile.is_open()) recvFile.close();
            recvFile.open(filename, std::ios::binary);
            if (!recvFile.is_open()) {
                std::cout << "\n[!] Failed to open file for writing: " << filename << "\n> ";
                transferActive = false;
                expectedFileSize = 0;
                receivedBytesCount = 0;
                recvFilename.clear();
                continue;
            }
            expectedFileSize = fsize;
            receivedBytesCount = 0;
            recvFilename = filename;
            transferActive = true;
            std::cout << "\n📥 Incoming file: " << filename << "  (" << fsize << " bytes)\n> ";
        }
        else if (plain.size() >= prefix_file_chunk.size() &&
            std::equal(prefix_file_chunk.begin(), prefix_file_chunk.end(), plain.begin())) {
            // FILE_CHUNK|<binary chunk after prefix>
            // find end of header (first '|' after prefix name) — design: prefix only then raw data: we used "FILE_CHUNK|" and then raw data without extra header
            // We'll just strip prefix and write the remaining bytes
            size_t headerLen = prefix_file_chunk.size();
            size_t chunkLen = plain.size() - headerLen;
            if (chunkLen == 0) continue;

            std::lock_guard<std::mutex> lk(fileMutex);
            if (!transferActive || !recvFile.is_open()) {
                // no active transfer -> ignore
                continue;
            }
            recvFile.write((char*)plain.data() + headerLen, chunkLen);
            receivedBytesCount += chunkLen;

            // periodic progress
            std::cout << "\r📥 Receiving " << recvFilename << " : " << receivedBytesCount << "/" << expectedFileSize << " bytes" << std::flush;

            if (receivedBytesCount >= expectedFileSize) {
                recvFile.close();
                transferActive = false;
                std::cout << "\n✅ File received: " << recvFilename << " (" << receivedBytesCount << " bytes)\n> ";
                expectedFileSize = 0;
                receivedBytesCount = 0;
                recvFilename.clear();
            }
        }
        else if (plain.size() >= prefix_msg.size() &&
                 std::equal(prefix_msg.begin(), prefix_msg.end(), plain.begin())) {
            // MSG|actual text
            std::string payload((char*)plain.data() + prefix_msg.size(), plain.size() - prefix_msg.size());
            std::cout << "\n🔐 Received: " << payload << "\n> ";
        }
        else {
            // unknown packet - ignore
            continue;
        }
    }

    closesocket(recvSock);
}

// ========== Sending helpers ==========
bool send_encrypted(SOCKET sock, const sockaddr_in& target, const unsigned char key[32], const unsigned char iv[16],
    const unsigned char* data, int data_len)
{
    auto ciph = encryptAES_bin(data, data_len, key, iv);
    int sent = sendto(sock, (char*)ciph.data(), (int)ciph.size(), 0, (sockaddr*)&target, sizeof(target));
    return sent == (int)ciph.size();
}

// ========== Main ==========
int main()
{
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        std::cout << "WSAStartup failed\n";
        return 1;
    }

    unsigned char key[32];
    unsigned char iv[16];

    int mode;
    std::cout << "AES KEY/IV MODE:\n";
    std::cout << "1. Generate new AES key & IV (host)\n";
    std::cout << "2. Enter existing AES key & IV (join)\n";
    std::cout << "Choose (1/2): ";
    std::cin >> mode;

    if (mode == 1) {
        RAND_bytes(key, sizeof(key));
        RAND_bytes(iv, sizeof(iv));
        std::cout << "\n=== SHARE THESE WITH THE OTHER PERSON ===\n";
        std::cout << "KEY (64 hex chars): ";
        printHex(key, 32);
        std::cout << "\nIV  (32 hex chars): ";
        printHex(iv, 16);
        std::cout << "\n=========================================\n\n";
    }
    else if (mode == 2) {
        std::string keyHex, ivHex;
        std::cout << "Enter KEY (64 hex chars): ";
        std::cin >> keyHex;
        std::cout << "Enter IV  (32 hex chars): ";
        std::cin >> ivHex;
        if (keyHex.length() != 64 || ivHex.length() != 32) {
            std::cout << "Invalid key/IV length.\n";
            return 1;
        }
        hexToBytes(keyHex, key, 32);
        hexToBytes(ivHex, iv, 16);
        std::cout << "Key/IV loaded.\n\n";
    } else {
        std::cout << "Invalid choice.\n";
        return 1;
    }

    std::string targetIp;
    int targetPort, listenPort;
    std::cout << "Enter target IP: ";
    std::cin >> targetIp;
    std::cout << "Enter target port: ";
    std::cin >> targetPort;
    std::cout << "Enter local listening port: ";
    std::cin >> listenPort;

    // start receiver
    std::thread recvT(receiverThread, listenPort, key, iv);
    recvT.detach();

    // create sender socket
    SOCKET sendSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sendSock == INVALID_SOCKET) {
        std::cout << "Failed to create send socket\n";
        WSACleanup();
        return 1;
    }

    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_port = htons(targetPort);
    target.sin_addr.s_addr = inet_addr(targetIp.c_str());

    std::cin.ignore(); // clear newline

    std::cout << "\nType messages to send. To send a file type:\n";
    std::cout << "/sendfile C:\\path\\to\\file.ext\n\n";

    while (true) {
        std::string line;
        std::cout << "> ";
        std::getline(std::cin, line);
        if (line.empty()) continue;

        if (line.rfind("/sendfile ", 0) == 0) {
            // send file
            std::string path = line.substr(10);
            // open file
            std::ifstream ifs(path, std::ios::binary | std::ios::ate);
            if (!ifs.is_open()) {
                std::cout << "[!] Failed to open file: " << path << "\n";
                continue;
            }
            std::streamsize fsize = ifs.tellg();
            ifs.seekg(0, std::ios::beg);

            // extract filename only (last path component)
            size_t pos = path.find_last_of("\\/");
            std::string filename = (pos == std::string::npos) ? path : path.substr(pos + 1);

            // send FILE_START|filename|size
            std::string hdr = "FILE_START|" + filename + "|" + std::to_string((unsigned long long)fsize);
            if (!send_encrypted(sendSock, target, key, iv, (const unsigned char*)hdr.data(), (int)hdr.size())) {
                std::cout << "[!] Failed to send file header\n";
                ifs.close();
                continue;
            }
            std::cout << "📤 Sending file: " << filename << " (" << fsize << " bytes)\n";

            // send chunks
            std::vector<char> buffer(PLAINTEXT_CHUNK);
            uint64_t bytesLeft = (uint64_t)fsize;
            while (bytesLeft > 0) {
                int toRead = (int)std::min<uint64_t>(PLAINTEXT_CHUNK, bytesLeft);
                ifs.read(buffer.data(), toRead);
                std::streamsize actuallyRead = ifs.gcount();
                if (actuallyRead <= 0) break;

                // build plaintext: "FILE_CHUNK|" + raw bytes
                std::string chunkPrefix = "FILE_CHUNK|";
                // allocate temp plain vector
                std::vector<unsigned char> plain;
                plain.reserve(chunkPrefix.size() + actuallyRead);
                plain.insert(plain.end(), chunkPrefix.begin(), chunkPrefix.end());
                plain.insert(plain.end(), buffer.data(), buffer.data() + actuallyRead);

                if (!send_encrypted(sendSock, target, key, iv, plain.data(), (int)plain.size())) {
                    std::cout << "[!] Failed to send a chunk\n";
                    break;
                }

                bytesLeft -= actuallyRead;
                // small sleep to avoid flooding (adjustable)
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
            ifs.close();
            std::cout << "📤 File transfer completed (header+chunks sent). Waiting for remote to confirm receipt.\n";
        }
        else if (line == "/quit" || line == "/exit") {
            break;
        }
        else {
            // normal message: prefix MSG|
            std::string payload = "MSG|" + line;
            if (!send_encrypted(sendSock, target, key, iv, (const unsigned char*)payload.data(), (int)payload.size())) {
                std::cout << "[!] Failed to send message\n";
            }
        }
    }

    closesocket(sendSock);
    WSACleanup();
    return 0;
}
