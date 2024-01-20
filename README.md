# Проверка ключа 4 лабы

Для сборки нужен openssl и iconv для Windows.

Команды сборки:
- **Linux**: `gcc check.c -lcrypto -o check`
- **Windows**: `gcc check.c -l:libcrypto.a -l:libiconv.a -lws2_32 -lmsvcrt -lcrypt32 -o check.exe`
