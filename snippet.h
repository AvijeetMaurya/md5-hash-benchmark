#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/ssl.h>

static void calculate_md5(const void* buf, size_t buf_size, unsigned char* res) {
    EVP_MD_CTX* mdctx;
    unsigned int md5_digest_len = uint32_t(EVP_MD_size(EVP_md5()));

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_md5(), nullptr);

    EVP_DigestUpdate(mdctx, buf, buf_size);

    EVP_DigestFinal_ex(mdctx, res, &md5_digest_len);
    EVP_MD_CTX_free(mdctx);
}