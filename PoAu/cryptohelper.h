#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/sha.h> //SHA256()



int padding = RSA_NO_PADDING; // With no padding option, keylength and data length should be identical




RSA* createRSA(unsigned char* key, int public1){
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL)
    {
        printf( "Failed to create key BIO");
        return 0;
    }
    if(public1)
    {
        rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa,NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }
    if(rsa == NULL)
    {
        printf( "Failed to create RSA");
    }
    BIO_free_all(keybio);

    return rsa;
}

int private_encrypt(unsigned char* data, int data_len,unsigned char* key, unsigned char* encrypted)
{
    RSA* rsa = createRSA(key,0);
    int result = RSA_private_encrypt(RSA_size(rsa),data,encrypted,rsa,padding);

    //std::cout<<data<<std::endl;
//    std::cout<<std::endl;
//    for(int i=0;i<64;i++){
//        printf("%02x",data[i]);
//    }
//    std::cout<<std::endl;

    unsigned long err;
    if((err = ERR_get_error())) {
        SSL_load_error_strings();
        ERR_load_crypto_strings();
        std::cout<<ERR_error_string(err, NULL)<<std::endl;
        std::cout<<ERR_reason_error_string(err)<<std::endl;
    }
    RSA_free(rsa);
    return result;
}

int public_decrypt(unsigned char* enc_data, int data_len, unsigned char* key, unsigned char* decrypted)
{
    RSA* rsa = createRSA(key,1);
    int  result = RSA_public_decrypt(RSA_size(rsa), enc_data, decrypted, rsa, padding);
    RSA_free(rsa);
    return result;
}


int generatemykeypair(unsigned char* mypublickey, unsigned char* myprivatekey){
    const int kBits = 512;
    const int kExp = 3;

    int keylen;

    RSA *rsa = RSA_generate_key(kBits, kExp, 0, 0);

    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(bio, rsa);
    keylen = BIO_pending(bio);
    BIO_read(bio, mypublickey, keylen);

    //printf("%s\n", mypublickey);
    //printf("%d\n", keylen);

    /* To get the C-string PEM form: */
    BIO *bio2 = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio2, rsa, NULL, NULL, 0, NULL, NULL);
    keylen = BIO_pending(bio2);
    BIO_read(bio2, myprivatekey, keylen);

    //printf("%s\n", myprivatekey);
    //printf("%d\n", keylen);

    return 0;
}
