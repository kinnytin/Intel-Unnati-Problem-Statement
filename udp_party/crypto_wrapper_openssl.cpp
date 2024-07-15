#include <stdlib.h>
#include <string.h>
#include "utils.h"
#include "crypto_wrapper.h"

#ifdef OPENSSL
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

#include <openssl/err.h>

#ifdef WIN
#pragma comment (lib, "libcrypto.lib")
#pragma comment (lib, "openssl.lib")
#endif // #ifdef WIN

static constexpr size_t PEM_BUFFER_SIZE_BYTES	= 10000;
static constexpr size_t HASH_SIZE_BYTES			= 32; //To be define by the participants
static constexpr size_t IV_SIZE_BYTES			= 12; //To be define by the participants
static constexpr size_t GMAC_SIZE_BYTES			= 16; //To be define by the participants 


bool CryptoWrapper::hmac_SHA256(IN const BYTE* key, size_t keySizeBytes, IN const BYTE* message, IN size_t messageSizeBytes, OUT BYTE* macBuffer, IN size_t macBufferSizeBytes)
{
	EVP_MD_CTX* ctx = NULL;
	EVP_PKEY* pkey = NULL;
	int rc;

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL)
	{
		goto err;
	}

	pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key, keySizeBytes);
	if (pkey == NULL) {
		goto err;
	}

	rc = EVP_DigestSignInit(ctx, NULL, EVP_get_digestbyname("SHA256"), NULL, pkey);

	if (rc == 0) {
		goto err;
	}

	rc = EVP_DigestSignUpdate(ctx,message,messageSizeBytes);

	if (rc == 0) {
		goto err;
	}

	rc = EVP_DigestSignFinal(ctx, macBuffer, &macBufferSizeBytes);

	if (rc == 0) {
		goto err;
	}

	return true;

err:
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	return false;
}

bool CryptoWrapper::deriveKey_HKDF_SHA256(IN const BYTE* salt, IN size_t saltSizeBytes,
	IN const BYTE* secretMaterial, IN size_t secretMaterialSizeBytes,
	IN const BYTE* context, IN size_t contextSizeBytes,
	OUT BYTE* outputBuffer, IN size_t outputBufferSizeBytes)
{
	bool ret = false;
	EVP_PKEY_CTX* pctx = NULL;

	int res;

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if(pctx == NULL)
	{
		printf("failed to get HKDF context\n");
		goto err;	
	}

	res = EVP_PKEY_derive_init(pctx);

	if (res <= 0) {
		if (res == -2)
		goto err;
	}

	res = EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256());

	if (res <= 0) {
		if (res == -2)
		goto err;
	}

	res = EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, saltSizeBytes);

	if (res <= 0) {
		if (res == -2)
		goto err;
	}

	res = EVP_PKEY_CTX_set1_hkdf_key(pctx, secretMaterial, secretMaterialSizeBytes);

	if (res <= 0) {
		if (res == -2)
		goto err;
	}

	res = EVP_PKEY_CTX_add1_hkdf_info(pctx, context, contextSizeBytes);

	if (res <= 0) {
		if (res == -2)
		goto err;
	}

	res = EVP_PKEY_derive(pctx, outputBuffer, &outputBufferSizeBytes);

	if (res <= 0) {
		if (res == -2)
		goto err;
	}

	ret = true;

err:
	EVP_PKEY_CTX_free(pctx);

	return ret;


}

size_t CryptoWrapper::getCiphertextSizeAES_GCM256(IN size_t plaintextSizeBytes)
{
	return plaintextSizeBytes + IV_SIZE_BYTES + GMAC_SIZE_BYTES;
}

size_t CryptoWrapper::getPlaintextSizeAES_GCM256(IN size_t ciphertextSizeBytes)
{
	return (ciphertextSizeBytes > IV_SIZE_BYTES + GMAC_SIZE_BYTES ? ciphertextSizeBytes - IV_SIZE_BYTES - GMAC_SIZE_BYTES : 0);
}

bool CryptoWrapper::encryptAES_GCM256(IN const BYTE* key, IN size_t keySizeBytes,
	IN const BYTE* plaintext, IN size_t plaintextSizeBytes,
	IN const BYTE* aad, IN size_t aadSizeBytes,
	OUT BYTE* ciphertextBuffer, IN size_t ciphertextBufferSizeBytes, OUT size_t* pCiphertextSizeBytes)
{
	BYTE iv[IV_SIZE_BYTES];
	BYTE mac[GMAC_SIZE_BYTES];
	size_t ciphertextSizeBytes = getCiphertextSizeAES_GCM256(plaintextSizeBytes);
	
	if ((plaintext == NULL || plaintextSizeBytes == 0) && (aad == NULL || aadSizeBytes == 0))
	{
		return false;
	}

	if (ciphertextBuffer == NULL || ciphertextBufferSizeBytes == 0)
	{
		if (pCiphertextSizeBytes != NULL)
		{
			*pCiphertextSizeBytes = ciphertextSizeBytes;
			return true;
		}
		else
		{
			return false;
		}
	}

	if (ciphertextBufferSizeBytes < ciphertextSizeBytes)
	{
		return false;
	}

	EVP_CIPHER_CTX* ctctx = EVP_CIPHER_CTX_new();
	int len;
	int ctlen;
	bool ret = false;

	if (ctctx == NULL) {
		goto end;
	}

	if (!EVP_EncryptInit_ex(ctctx,EVP_aes_256_gcm(), NULL, NULL, NULL)) {
		goto end;
	}

	if (!EVP_CIPHER_CTX_ctrl(ctctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE_BYTES, NULL))
	{
		goto end;
	}

	if (!EVP_EncryptInit_ex(ctctx,NULL, NULL, key, iv)) {
		goto end;
	}

	if(!EVP_EncryptUpdate(ctctx,NULL, &len, aad, aadSizeBytes)) {
		goto end;
	}

	if (!EVP_EncryptUpdate(ctctx, ciphertextBuffer, &len, plaintext, plaintextSizeBytes)) {
		goto end;
	}

	ctlen = len;

	if (!EVP_EncryptFinal_ex(ctctx, ciphertextBuffer+len, &len)) {
		goto end;
	}

	ctlen += len;

	if (!EVP_CIPHER_CTX_ctrl(ctctx, EVP_CTRL_GCM_GET_TAG, GMAC_SIZE_BYTES, mac)) {
		goto end;
	}

	memcpy(ciphertextBuffer + ctlen, mac, GMAC_SIZE_BYTES);

	if (pCiphertextSizeBytes != NULL)
		*pCiphertextSizeBytes = ciphertextSizeBytes;

	ret = true;

end:
	EVP_CIPHER_CTX_free(ctctx);
	return ret;
}

bool CryptoWrapper::decryptAES_GCM256(IN const BYTE* key, IN size_t keySizeBytes,
	IN const BYTE* ciphertext, IN size_t ciphertextSizeBytes,
	IN const BYTE* aad, IN size_t aadSizeBytes,
	OUT BYTE* plaintextBuffer, IN size_t plaintextBufferSizeBytes, OUT size_t* pPlaintextSizeBytes)
{
	if (ciphertext == NULL || ciphertextSizeBytes < (IV_SIZE_BYTES + GMAC_SIZE_BYTES))
	{
		return false;
	}

	size_t plaintextSizeBytes = getPlaintextSizeAES_GCM256(ciphertextSizeBytes);
	
	if (plaintextBuffer == NULL || plaintextBufferSizeBytes == 0)
	{
		if (pPlaintextSizeBytes != NULL)
		{
			*pPlaintextSizeBytes = plaintextSizeBytes;
			return true;
		}
		else
		{
			return false;
		}
	}
	
	if (plaintextBufferSizeBytes < plaintextSizeBytes)
	{
		return false;
	}

	BYTE iv[IV_SIZE_BYTES];
	BYTE mac[GMAC_SIZE_BYTES];

	// extracting the MAC 
	memcpy(mac,ciphertext + ciphertextSizeBytes - GMAC_SIZE_BYTES, GMAC_SIZE_BYTES);

	EVP_CIPHER_CTX* ptctx = EVP_CIPHER_CTX_new();
	int len;
	int ptlen;
	bool ret = false;

	if (!ptctx) {
		goto end;
	}

	if (!EVP_DecryptInit_ex(ptctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
		goto end;
	}

	if (!EVP_CIPHER_CTX_ctrl(ptctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE_BYTES, NULL)) {
		goto end;
	}

	if (!EVP_DecryptInit_ex(ptctx, NULL, NULL, key, iv)) {
		goto end;
	}

	if (!EVP_DecryptUpdate(ptctx, NULL, &len, aad, aadSizeBytes)) {
		goto end;
	}

	if (!EVP_DecryptUpdate(ptctx, plaintextBuffer, &len, ciphertext, ciphertextSizeBytes)) {
		goto end;
	}
	ptlen = len;

	if(!EVP_CIPHER_CTX_ctrl(ptctx, EVP_CTRL_GCM_SET_TAG, GMAC_SIZE_BYTES, mac)) {
		goto end;
	}

	if (!EVP_DecryptFinal_ex(ptctx, plaintextBuffer + len, &len))
		ptlen += len;
	else {
		goto end;
	}

	if (pPlaintextSizeBytes != NULL)
		*pPlaintextSizeBytes = plaintextSizeBytes;

	ret = true;

end:
	EVP_CIPHER_CTX_free(ptctx);
	return ret;
}

bool CryptoWrapper::readRSAKeyFromFile(IN const char* keyFilename, IN const char* filePassword, OUT KeypairContext** pKeyContext)
{
	BIO* bio = NULL;
	EVP_PKEY* pkey = NULL;
	EVP_PKEY_CTX* ctx = NULL;
	bool ret = false;

	bio = BIO_new_file(keyFilename, "rb");
	if (bio == NULL) {
		goto end;
	}

	pkey = PEM_read_bio_PrivateKey_ex(bio, &pkey, NULL, (void *) filePassword, NULL, NULL);
	assert(pkey != NULL);
	if (pkey == NULL) {
		goto end;
	}
	
	ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (ctx == NULL) {
		goto end;
	}

	*pKeyContext = ctx;

	ret = true;

end:
	// required for that pKeyContext
	EVP_PKEY_free(pkey);
	BIO_free(bio);
	return ret;
}


bool CryptoWrapper::signMessageRsa3072Pss(IN const BYTE* message, IN size_t messageSizeBytes, IN KeypairContext* privateKeyContext, OUT BYTE* signatureBuffer, IN size_t signatureBufferSizeBytes)
{

	if(!message || !messageSizeBytes || !privateKeyContext)
		return false;

	*signatureBuffer = NULL;

	EVP_MD_CTX* md_ctx = NULL;
	const EVP_MD* md;
	EVP_PKEY* pkey = EVP_PKEY_CTX_get0_pkey(privateKeyContext);
	bool ret = false;
	int rc;

	assert(pkey != NULL);
	if (pkey == NULL) {
		goto end;
	}

	md_ctx = EVP_MD_CTX_create();
	assert(md_ctx != NULL);
	if (md_ctx == NULL) {
		goto end;
	}

	md = EVP_get_digestbyname("SHA384");
	assert(md != NULL);
	if (md == NULL) {
		goto end;
	}

	rc = EVP_DigestInit_ex(md_ctx, md, NULL);
	assert(rc == 1);
	if (rc != 1) {
		goto end;
	}

	rc = EVP_DigestSignInit(md_ctx, NULL, md, NULL, pkey);
	assert(rc == 1);
	if (rc != 1) {
		goto end;
	}

	rc = EVP_DigestSignUpdate(md_ctx, message, messageSizeBytes);
	assert(rc == 1);
	if (rc != 1) {
		goto end;
	}

	rc = EVP_DigestSignFinal(md_ctx, signatureBuffer, &signatureBufferSizeBytes);  // not updating signatureBufferSizeBytes, i dont know why
	assert(rc == 1);
	if (rc != 1) {
		goto end;
	}

	ret = true;

end:
	EVP_MD_CTX_destroy(md_ctx);
	return ret;

}


bool CryptoWrapper::verifyMessageRsa3072Pss(IN const BYTE* message, IN size_t messageSizeBytes, IN KeypairContext* publicKeyContext, IN const BYTE* signature, IN size_t signatureSizeBytes, OUT bool* result)
{
	if (!message || !messageSizeBytes || !publicKeyContext || !signature || !signatureSizeBytes)
		return false;

	EVP_MD_CTX* md_ctx = NULL;
	const EVP_MD* md;
	EVP_PKEY* pkey = EVP_PKEY_CTX_get0_pkey(publicKeyContext);
	bool ret = false;
	int rc;

	assert(pkey != NULL);
	if (pkey == NULL) {
		goto end;
	}

	md_ctx = EVP_MD_CTX_create();
	assert(md_ctx != NULL);
	if (md_ctx == NULL) {
		goto end;
	}

	md = EVP_get_digestbyname("SHA384");
	assert(md != NULL);
	if (md == NULL) {
		goto end;
	}

	rc = EVP_DigestInit_ex(md_ctx, md, NULL);
	assert(rc == 1);
	if (rc != 1) {
		goto end;
	}

	rc = EVP_DigestVerifyInit(md_ctx, NULL, md, NULL, pkey);
	assert(rc == 1);
	if (rc != 1) {
		goto end;
	}

	rc = EVP_DigestVerifyUpdate(md_ctx, message, messageSizeBytes);
	assert(rc == 1);
	if (rc != 1) {
		goto end;
	}

	rc = EVP_DigestVerifyFinal(md_ctx, signature, signatureSizeBytes); 
	//verification stops when the message is tampered
	if (rc != 1) {
		goto end;
	}

	ret = true;

end:
	EVP_MD_CTX_destroy(md_ctx);
	*result = ret;
	return ret;
}


void CryptoWrapper::cleanKeyContext(INOUT KeypairContext** pKeyContext)
{
	if (*pKeyContext != NULL)
	{
		EVP_PKEY_CTX_free(*pKeyContext);
		*pKeyContext = NULL;
	}
}

//useful if key is used instead of keyPairContext
bool CryptoWrapper::writePublicKeyToPemBuffer(IN KeypairContext* keyContext, OUT BYTE* publicKeyPemBuffer, IN size_t publicKeyBufferSizeBytes)
{
	bool ret = false;
	EVP_PKEY* key = NULL;
	BIGNUM* pubKey = NULL;
	int rc;

	if (keyContext == NULL || publicKeyPemBuffer == NULL) {
		goto err;
	}

	key = EVP_PKEY_CTX_get0_pkey(keyContext);
	if (key == NULL) {
		goto err;
	}

	if (EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_PUB_KEY, &pubKey) != 1) {
		unsigned long errCode = ERR_get_error();
		goto err;
	}

	rc = BN_bn2bin(pubKey, publicKeyPemBuffer);
	if (rc <= 0) {
		goto err;
	}

	ret = true;

err:
	BN_free(pubKey);
	EVP_PKEY_free(key);
	// EVP_PKEY_CTX_free(keyContext); i don't know why but cleaning this context affects the creation of derivation context at getDhSharedSecret. 
	return ret;
}

bool CryptoWrapper::loadPublicKeyFromPemBuffer(INOUT KeypairContext* context, IN const BYTE* publicKeyPemBuffer, IN size_t publicKeyBufferSizeBytes)
{

	err:
	return false;
}

// no need to regenerate it at creatingPeerPublicKey, we only have public key which is not enough to create a peerKey at creatingPeerPublicKey, will be useful if the creatingPeerPublicKey accepts the current user context with which we can get p and g values easily 
bool generateDhParameters(BIGNUM **p, BIGNUM **g) {
	unsigned char generator = 2;
	*p = BN_get_rfc3526_prime_3072(NULL);
	if (*p == NULL)
		return false;

	*g = BN_bin2bn(&generator, 1, NULL);
	if (*g == NULL)
		return false;

	return true;
}

bool CryptoWrapper::startDh(OUT DhContext** pDhContext, OUT BYTE* publicKeyBuffer, IN size_t publicKeyBufferSizeBytes)
{
	bool ret = false;
	BIGNUM* p = NULL;
	BIGNUM* g = NULL;

	int rc = 0;
	OSSL_PARAM_BLD* bld = NULL;
	OSSL_PARAM *params = NULL;
	EVP_PKEY* paramKey = NULL;
	EVP_PKEY_CTX* paramKeyCtx = NULL;
	EVP_PKEY* keyPair = NULL;
	EVP_PKEY_CTX* keyGenCtx = NULL;
	EVP_PKEY_CTX* keyPairCtx = NULL;

	if (!generateDhParameters(&p, &g)) {
		goto err;
	}

	bld = OSSL_PARAM_BLD_new();
	if (bld == NULL) {
		goto err;
	}

	rc = OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p);
	if (rc == 0) {
		goto err;
	}

	rc = OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g);
	if (rc == 0) {
		goto err;
	}

	params = OSSL_PARAM_BLD_to_param(bld);
	if (params == NULL) {
		goto err;
	}

	paramKeyCtx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
	if (paramKeyCtx == NULL) {
		goto err;
	}

	rc = EVP_PKEY_fromdata_init(paramKeyCtx);
	if (rc <= 0) {
		goto err;
	}

	rc = EVP_PKEY_fromdata(paramKeyCtx, &paramKey, EVP_PKEY_KEY_PARAMETERS, params);
	if (rc <= 0) {
		goto err;
	}

	keyGenCtx = EVP_PKEY_CTX_new_from_pkey(NULL,paramKey, NULL);
	if (keyGenCtx == NULL) {
		goto err;
	}

	rc = EVP_PKEY_keygen_init(keyGenCtx);
	if (rc <= 0) {
		goto err;
	}

	rc = EVP_PKEY_generate(keyGenCtx, &keyPair);
	if (rc <= 0) {
		goto err;
	}

	keyPairCtx = EVP_PKEY_CTX_new_from_pkey(NULL, keyPair, NULL);
	if (keyPairCtx == NULL) {
		goto err;
	}

	if (!writePublicKeyToPemBuffer(keyPairCtx, publicKeyBuffer, publicKeyBufferSizeBytes)) {
		goto err;
	}

	*pDhContext = keyPair;

	ret = true;

err:
	BN_free(p);
	BN_free(g);
	OSSL_PARAM_BLD_free(bld);
	OSSL_PARAM_free(params);
	EVP_PKEY_free(paramKey);
	EVP_PKEY_CTX_free(paramKeyCtx);
	EVP_PKEY_CTX_free(keyGenCtx);

	return ret;
}

bool CreatePeerPublicKey(const BYTE* peerPublicKey, size_t peerPublicKeySizeBytes, EVP_PKEY** genPeerPublicKey)
{
	bool ret = false;
	BIGNUM* pubKey = NULL;
	BIGNUM* p = NULL;
	BIGNUM* g = NULL;
	OSSL_PARAM* params = NULL;
	OSSL_PARAM_BLD* bld = NULL;
	EVP_PKEY_CTX* peerKeyCtx = NULL;
	EVP_PKEY* peerKey = NULL;
	int rc;

	if (!generateDhParameters(&p, &g)) {
		goto err;
	}

	pubKey = BN_bin2bn(peerPublicKey, peerPublicKeySizeBytes, NULL);
	if (pubKey == NULL) {
		goto err;
	}

	bld = OSSL_PARAM_BLD_new();
	if (bld == NULL) {
		goto err;
	}

	rc = OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p);
	if (rc <= 0) {
		goto err;
	}

	rc = OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g);
	if (rc <= 0) {
		goto err;
	}

	rc = OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY, pubKey);
	if (rc <= 0) {
		goto err;
	}

	params = OSSL_PARAM_BLD_to_param(bld);
	if (params == NULL) {
		goto err;
	}

	peerKeyCtx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
	if (peerKeyCtx == NULL) {
		goto err;
	}

	rc = EVP_PKEY_fromdata_init(peerKeyCtx);
	if (rc <= 0) {
		goto err;
	}

	rc = EVP_PKEY_fromdata(peerKeyCtx, &peerKey, EVP_PKEY_PUBLIC_KEY, params);
	if (rc <= 0) {
		goto err;
	}

	*genPeerPublicKey = peerKey;

	ret = true;

err:
	BN_free(pubKey);
	BN_free(p);
	BN_free(g);
	OSSL_PARAM_BLD_free(bld);
	OSSL_PARAM_free(params);
	EVP_PKEY_CTX_free(peerKeyCtx);
	return ret;
}

bool CryptoWrapper::getDhSharedSecret(INOUT DhContext* dhContext, IN const BYTE* peerPublicKey, IN size_t peerPublicKeySizeBytes, OUT BYTE* sharedSecretBuffer, IN size_t sharedSecretBufferSizeBytes)
{

	bool ret = false;
	EVP_PKEY* genPeerPublicKey = NULL;
	EVP_PKEY_CTX* derivationCtx = NULL;

	int rc = 0;

	if (dhContext == NULL || peerPublicKey == NULL || sharedSecretBuffer == NULL)
		goto err;

	if (!CreatePeerPublicKey(peerPublicKey, peerPublicKeySizeBytes, &genPeerPublicKey))
		goto err;

	derivationCtx = EVP_PKEY_CTX_new(dhContext, NULL);
	if (derivationCtx == NULL) {
		goto err;
	}


	rc = EVP_PKEY_derive_init(derivationCtx);
	if(rc != 1) {
		goto err;
	}


	rc = EVP_PKEY_derive_set_peer(derivationCtx, genPeerPublicKey);
	if(rc != 1) {
		goto err;
	}


	rc = EVP_PKEY_derive(derivationCtx, sharedSecretBuffer, &sharedSecretBufferSizeBytes);
	if(rc != 1) {
		goto err;
	}

	ret = true;

err:
	EVP_PKEY_CTX_free(derivationCtx);
	EVP_PKEY_free(genPeerPublicKey);
	return ret;
}

void CryptoWrapper::cleanDhContext(INOUT DhContext** pDhContext)
{
	if (*pDhContext != NULL)
	{
		EVP_PKEY_free(*pDhContext);
		*pDhContext = NULL;
	}
}

X509* loadCertificate(const BYTE* certBuffer, size_t certSizeBytes)
{
	int ret = 0;
	BIO* bio = NULL;
	X509* cert = NULL;

	bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
	{
		printf("BIO_new() fail \n");
		goto err;
	}

	ret = BIO_write(bio, (const void*)certBuffer, (int)certSizeBytes);
	if (ret <= 0)
	{
		printf("BIO_write() fail \n");
		goto err;
	}

	cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (cert == NULL)
	{
		printf("PEM_read_bio_X509() fail \n");
		goto err;
	}

err:
	BIO_free(bio);

	return cert;
}

bool CryptoWrapper::checkCertificate(IN const BYTE* cACcertBuffer, IN size_t cACertSizeBytes, IN const BYTE* certBuffer, IN size_t certSizeBytes, IN const char* expectedCN)
{
	int ret = 0;
	X509* userCert = NULL;
	X509* caCert = NULL;

	X509_STORE* trustStore = NULL;
	X509_STORE_CTX* storeCtx = NULL;
	int rc;

	caCert = loadCertificate(cACcertBuffer, cACertSizeBytes);
	if (caCert == NULL)
	{
			goto err;
	}

	userCert = loadCertificate(certBuffer, certSizeBytes);
	if (userCert == NULL)
	{
		goto err;
	}

	trustStore = X509_STORE_new();
	if (trustStore == NULL)
	{
		goto err;
	}

	rc = X509_STORE_add_cert(trustStore, caCert);
	if (rc != 1) {	
		goto err;
	}

	storeCtx = X509_STORE_CTX_new();
	if (storeCtx == NULL)
	{
		goto err;
	}

	rc = X509_STORE_CTX_init(storeCtx, trustStore, userCert, NULL);
	if (rc != 1)
	{
		goto err;
	}

	rc = X509_verify_cert(storeCtx);
	if (rc != 1)
	{
		goto err;
	}

	rc = X509_check_host(userCert, expectedCN, strlen(expectedCN), X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS, NULL);
	if (rc != 1)
	{
		goto err;
	}

	ret = true;

err:
	X509_free(caCert);
	X509_free(userCert);
	X509_STORE_free(trustStore);
	X509_STORE_CTX_free(storeCtx);
	return ret;
}


bool CryptoWrapper::getPublicKeyFromCertificate(IN const BYTE* certBuffer, IN size_t certSizeBytes, OUT KeypairContext** pPublicKeyContext)
{
	bool ret = false;
	X509* x509 = NULL;
	EVP_PKEY* pkey = NULL;
	EVP_PKEY_CTX* ctx = NULL;

	x509 = loadCertificate(certBuffer, certSizeBytes);
	if (x509 == NULL) {
		goto err;
	}

	pkey = X509_get_pubkey(x509);
	if (pkey == NULL) {
		goto err;
	}

	ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (ctx == NULL) {
		goto err;
	}
	*pPublicKeyContext = ctx;

	ret = true;

err:
	X509_free(x509);
	EVP_PKEY_free(pkey);

	return ret;
}

#endif // #ifdef OPENSSL

/*
* 
* Usefull links
* -------------------------
* *  
* https://www.intel.com/content/www/us/en/develop/documentation/cpp-compiler-developer-guide-and-reference/top/compiler-reference/intrinsics/intrinsics-for-later-gen-core-proc-instruct-exts/intrinsics-gen-rand-nums-from-16-32-64-bit-ints/rdrand16-step-rdrand32-step-rdrand64-step.html
* https://wiki.openssl.org/index.php/OpenSSL_3.0
* https://www.rfc-editor.org/rfc/rfc3526
* 
* 
* Usefull APIs
* -------------------------
* 
* EVP_MD_CTX_new
* EVP_PKEY_new_raw_private_key
* EVP_DigestSignInit
* EVP_DigestSignUpdate
* EVP_PKEY_CTX_new_id
* EVP_PKEY_derive_init
* EVP_PKEY_CTX_set_hkdf_md
* EVP_PKEY_CTX_set1_hkdf_salt
* EVP_PKEY_CTX_set1_hkdf_key
* EVP_PKEY_derive
* EVP_CIPHER_CTX_new
* EVP_EncryptInit_ex
* EVP_EncryptUpdate
* EVP_EncryptFinal_ex
* EVP_CIPHER_CTX_ctrl
* EVP_DecryptInit_ex
* EVP_DecryptUpdate
* EVP_DecryptFinal_ex
* OSSL_PARAM_BLD_new
* OSSL_PARAM_BLD_push_BN
* EVP_PKEY_CTX_new_from_name
* EVP_PKEY_fromdata_init
* EVP_PKEY_fromdata
* EVP_PKEY_CTX_new
* EVP_PKEY_derive_init
* EVP_PKEY_derive_set_peer
* EVP_PKEY_derive_init
* BIO_new
* BIO_write
* PEM_read_bio_X509
* X509_STORE_new
* X509_STORE_CTX_new
* X509_STORE_add_cert
* X509_verify_cert
* X509_check_host
*
*
*
*/
