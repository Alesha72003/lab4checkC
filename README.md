# Проверка ключа 4 лабы

Для сборки нужен openssl и iconv для Windows.

Команды сборки:
- **Linux**: `gcc -lcrypto check.c -o check`
- **Windows**: `gcc -l:libcrypto.a -l:libiconv.a -lws2_32 -o check.exe`
