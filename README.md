To deploy 

g++ encrypted_chat_file.cpp -o chat.exe  -lssl -lcrypto  -lcrypt32 -lbcrypt -lncrypt -ladvapi32 -lws2_32 -static

If -static gives trouble, omit it:

g++ encrypted_chat_file.cpp -o chat.exe \
  -lssl -lcrypto \
  -lcrypt32 -lbcrypt -lncrypt -ladvapi32 \
  -lws2_32

To send file run

/sendfile C:\Users\You\Desktop\bigfile.zip
