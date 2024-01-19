#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#ifdef __WIN32

#include <windows.h>
#include <iconv.h>
#define MAXSIZEINPUT 1024

#endif


size_t calcDecodeLength(const char* b64input) { //Calculates the length of a decoded string
	size_t len = strlen(b64input),
		padding = 0;

	if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
		padding = 2;
	else if (b64input[len-1] == '=') //last char is =
		padding = 1;

	return (len*3)/4 - padding;
}

char* base64_decode(const char* input, unsigned char** buffer, size_t* length) {
    BIO *bio, *b64;

    int decodeLen = calcDecodeLength(input);
	*buffer = (unsigned char*)malloc(decodeLen + 1);
	(*buffer)[decodeLen] = '\0';

    bio = BIO_new_mem_buf(input, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);  // Ignore newlines - stop newline filter from being applied

    // Get buffer for decoded data
    *length = BIO_read(bio, *buffer, strlen(input));
	assert(*length == decodeLen); //length should equal decodeLen, else something went horribly wrong
	BIO_free_all(bio);


    return 0;
}

int verify_signature(const char *message, const char *signature_base64, const char *public_key_pem) {
    // Инициализация библиотеки OpenSSL
    OpenSSL_add_all_algorithms();

    // Загрузка открытого ключа
    BIO *bio = BIO_new_mem_buf((void *)public_key_pem, -1);
    EVP_PKEY *public_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!public_key) {
        fprintf(stderr, "Ошибка при загрузке открытого ключа\n");
        ERR_print_errors_fp(stderr);
        return 0;  // Проверка неудачна
    }

    // Декодирование base64-подписи
    unsigned char *decoded_signature;
    size_t length;
    if (base64_decode(signature_base64, &decoded_signature, &length)) {
        fprintf(stderr, "Ошибка при декодировании подписи\n");
        ERR_print_errors_fp(stderr);
        return 0;  // Проверка неудачна
    }

    // Проверка подписи
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    EVP_VerifyInit(md_ctx, EVP_sha256());
    EVP_VerifyUpdate(md_ctx, message, strlen(message));

    int verify_result = EVP_VerifyFinal(md_ctx, decoded_signature, length, public_key);
    EVP_MD_CTX_free(md_ctx);

    // Освобождение ресурсов
    free(decoded_signature);
    EVP_PKEY_free(public_key);

    return verify_result;
}

int input(char* prompt, char** string) {
    size_t length;
    fputs(prompt, stdout);

#ifdef __WIN32
    length = MAXSIZEINPUT;
    *string = (char*)malloc(length);

    if (fgets(*string, length, stdin) == NULL) {
#else
    getline(string, &length, stdin);
    if (length < 0) {
#endif
        puts("Error with read data\n");
        free(*string);
        return 1;
    }
    length = strlen(*string);
    *(*string + length - 1) = 0;
    return 0;
}

int parseMessage(char* buff, size_t length) {
    char *name, *group;
    int part;

    input("Введите ФИО: ", &name);
    input("Введите группу: ", &group);

    
    fputs("Введите номер части: ", stdout);
    if (scanf("%d", &part) != 1) {
        fprintf(stderr, "Invalid input part \n");
        return 0;
    }
    getc(stdin);

    snprintf(buff, length, "{\"name\":\"%s\",\"group\":\"%s\",\"part\":%d}", name, group, part);

    free(name);
    free(group);

#ifdef __WIN32
    char* tmpbuff = (char*)malloc(length);
    const iconv_t cp1251ToUTF8 = iconv_open("UTF-8", "CP1251");
    char* src = buff;
    size_t srcLength = strlen(buff);
    char* dst = tmpbuff;
    size_t dstLength = srcLength*2;
    if (iconv(cp1251ToUTF8, &src, &srcLength, &dst, &dstLength) == -1) {
        puts("Error in reencoding");
        iconv_close(cp1251ToUTF8);
        return 0;
    }
    *dst = 0;

    strncpy(buff, tmpbuff, length);
    free(tmpbuff);
    iconv_close(cp1251ToUTF8);
#endif

    return 1;
}

int main() {
    const char *public_key_pem = "-----BEGIN PUBLIC KEY-----\n\
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvdDpC8Y1iHCCNfSXNUgS\n\
ylp3LdnZwJeixbkfqQv2xQa9VTWQ4n/1BQvaz8oqTLy8EP7cx1XQsR4qXplQE6hB\n\
AllY5eSLMQigZj56saZwKFVKI+mk6AOHW9dnZjcmYg/pvcQbyijZmkjlLlQ0oN1J\n\
fHV6UCTC7OcKeeiqkAsTG2T2p20p4ZKoA4zLiUHhhOuS9VGfsURTt7vus+rm7LeC\n\
DWBNG6R6EatJ2ApBUYDm8h6gvj6AS97JMZ3H+GC4u/JQfEc28BUHreZTEMpPg4JU\n\
SNp391nvkwaQBMlxHcQ3nalWy6TUOWzxki3JV1zsIkcb2gbGSKbhj67kBNyXxiif\n\
BkiQGX54BuNPc6TtmhQi10x+fikDvp7Q/JpcHHfJYrzHLTCIy42kxp03NQlpwLbA\n\
yAnNM5BCFP7s664ME188evkx94lpI//ysKAy16YcmiB+iSiFSqgaI9FDMqcP/QbP\n\
c6mcUp1EFrGp4lVMhfu27+SchQA/4E7v5VmYoRq1wlZUi3s34KgkSeoDob8pW1in\n\
jD70QycAEizZjeXfyiEP30TukGuew4SOI/BicikOp366s5UTxkS7rB07ecycjEEO\n\
W2K0notj+8o27bJR7drxTvE97pHK/7SJL6y4n5l0ZddKT2PuMmwyRxgppxIruKdW\n\
f1D4p43fWIE4Xzk4gbwD1p0CAwEAAQ==\n\
-----END PUBLIC KEY-----\n";

#ifdef __WIN32
    SetConsoleCP(1251);
    SetConsoleOutputCP(1251);
#endif

    char message[256];
    if(!parseMessage(message, sizeof(message))){
        return 1;
    }
    // puts(message);

    char *signature_base64;
    input("Введите ключ: ", &signature_base64);

    int result = verify_signature(message, signature_base64, public_key_pem);
    free(signature_base64);

    if (result) {
        printf("OK\n");
    } else {
        printf("Подпись неверна\n");
    }

    return 0;
}
