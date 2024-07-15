#include <list>
#include <stdio.h>
#include <cstring>
#include <cstdarg>
#include <cstdlib>
#include "session.h"
#include "utils.h"
#include "crypto_wrapper.h"


#ifdef WIN
#pragma warning(disable:4996) 
#endif // #ifdef WIN


static constexpr size_t MAX_CONTEXT_SIZE = 100;


Session::Session(const char* keyFilename, char* password, const char* certFilename, const char* rootCaFilename, const char* peerIdentity)
{
    _state = UNINITIALIZED_SESSION_STATE;

    _localSocket = new Socket(0);
    if (!_localSocket->valid())
    {
        return;
    }
    _pReferenceCounter = new ReferenceCounter();
    _pReferenceCounter->AddRef();

    _sessionId = 0;
    _outgoingMessageCounter = 0;
    _incomingMessageCounter = 0;

    // Init crypto part
    _privateKeyFilename = keyFilename;
    _privateKeyPassword = password;
    _localCertFilename = certFilename;
    _rootCaCertFilename = rootCaFilename;
    _expectedRemoteIdentityString = peerIdentity;
    memset(_sessionKey, 0, SYMMETRIC_KEY_SIZE_BYTES);

    _state = INITIALIZED_SESSION_STATE;
}


Session::Session(const Session& other)
{
    _state = UNINITIALIZED_SESSION_STATE;
    _pReferenceCounter = other._pReferenceCounter;
    _pReferenceCounter->AddRef();

    _localSocket = other._localSocket;

    _sessionId = 0;
    _outgoingMessageCounter = 0;
    _incomingMessageCounter = 0;

    // Init crypto part
    _privateKeyFilename = other._privateKeyFilename;
    _privateKeyPassword = other._privateKeyPassword;
    _localCertFilename = other._localCertFilename;
    _rootCaCertFilename = other._rootCaCertFilename;
    _expectedRemoteIdentityString = other._expectedRemoteIdentityString;
    memset(_sessionKey, 0, SYMMETRIC_KEY_SIZE_BYTES);

    _state = INITIALIZED_SESSION_STATE;
}


void Session::closeSession()
{
    if (active())
    {
        ByteSmartPtr encryptedMessage = prepareEncryptedMessage(GOODBYE_SESSION_MESSAGE, NULL, 0);
        if (encryptedMessage != NULL)
        {
            sendMessageInternal(GOODBYE_SESSION_MESSAGE, encryptedMessage, encryptedMessage.size());
            _state = GOODBYE_SESSION_MESSAGE;
        }
    }
}


void Session::destroySession()
{
    cleanDhData();
    if (_pReferenceCounter != NULL && _pReferenceCounter->Release() == 0)
    {
        delete _localSocket;
        _localSocket = NULL;
        delete _pReferenceCounter;
        _pReferenceCounter = NULL;

        if (_privateKeyPassword != NULL)
        {
            Utils::secureCleanMemory((BYTE*) _privateKeyPassword, sizeof(_privateKeyPassword));
        }
    }
    else
    {
        _pReferenceCounter = NULL;
    }

    _state = DEACTIVATED_SESSION_STATE;
}


bool Session::active()
{
    return (_state == INITIALIZED_SESSION_STATE ||
        (_state >= FIRST_SESSION_MESSAGE_TYPE && _state <= LAST_SESSION_MESSAGE_TYPE));
}


void Session::setRemoteAddress(const char* remoteIpAddress, unsigned int remotePort) 
{
        memset(&(_remoteAddress), 0, sizeof(sockaddr_in));
        _remoteAddress.sin_family = AF_INET;
        _remoteAddress.sin_port = htons(remotePort);
        _remoteAddress.sin_addr.s_addr = inet_addr(remoteIpAddress);
}


void Session::prepareMessageHeader(MessageHeader* header, unsigned int type, size_t messageSize)
{
    header->sessionId = _sessionId;
    header->messageType = type;
    header->messageCounter =_outgoingMessageCounter;
    header->payloadSize = (unsigned int)messageSize;
}


bool Session::sendMessageInternal(unsigned int type, const BYTE* message, size_t messageSize)
{
    if (!active())
    {
        return false;
    }

    MessageHeader header;
    prepareMessageHeader(&header, type, messageSize);

    ByteSmartPtr messageBufferSmartPtr = concat(2, &header, sizeof(header), message, messageSize);
    if (messageBufferSmartPtr == NULL)
    {
        return false;
    }

    bool result = _localSocket->send(messageBufferSmartPtr, messageBufferSmartPtr.size(), &(_remoteAddress));
    if (result)
    {
        _outgoingMessageCounter++;
    }

    return result;
}


void Session::cleanDhData()
{
    // ...
    CryptoWrapper::cleanDhContext(&_dhContext);
}


void Session::deriveMacKey(BYTE* macKeyBuffer)
{
    char keyDerivationContext[MAX_CONTEXT_SIZE];
    if (sprintf_s(keyDerivationContext, MAX_CONTEXT_SIZE, "MAC over certificate key %d", _sessionId) <= 0)
    {
        exit(0);
    }

    size_t sessionIdSize = sizeof(_sessionId);
    size_t rootCaCertFilenameSize = sizeof(_rootCaCertFilename);

    BYTE *salt = new BYTE[rootCaCertFilenameSize+sessionIdSize];
    memcpy(salt, &_sessionId, sessionIdSize);
    memcpy(salt+sessionIdSize, _rootCaCertFilename, rootCaCertFilenameSize);
    
    // ...
    if (!CryptoWrapper::deriveKey_HKDF_SHA256( salt, sizeof(salt), _sharedDhSecretBuffer, DH_KEY_SIZE_BYTES, (BYTE*)keyDerivationContext, MAX_CONTEXT_SIZE, macKeyBuffer, 131)) {
        printf("Error in deriving MAC key at deriveMacKey\n");
    }

    delete[] salt;
}


void Session::deriveSessionKey()
{
    char keyDerivationContext[MAX_CONTEXT_SIZE];
    if (sprintf_s(keyDerivationContext, MAX_CONTEXT_SIZE, "ENC session key %d", _sessionId) <= 0)
    {
        exit(0);
    }

    // since the session key and mac key should be independent we are here using the root certificate itself as a salt.
    size_t sessionIdSize = sizeof(_sessionId);
    ByteSmartPtr rootCertBuffer = Utils::readBufferFromFile(_rootCaCertFilename);
    BYTE* salt = new BYTE[rootCertBuffer.size()+sessionIdSize];
    memcpy(salt, &_sessionId, sessionIdSize);
    memcpy(salt + sessionIdSize, rootCertBuffer, rootCertBuffer.size());

    if (!CryptoWrapper::deriveKey_HKDF_SHA256(salt, sizeof(salt), _sharedDhSecretBuffer, DH_KEY_SIZE_BYTES, (BYTE*)keyDerivationContext, MAX_CONTEXT_SIZE, _sessionKey, SYMMETRIC_KEY_SIZE_BYTES)) {
        printf("Error in deriving session key at deriveSessionKey\n");
    }

    delete[] salt;
}


ByteSmartPtr Session::prepareSigmaMessage(unsigned int messageType)
{
    if (messageType != 2 && messageType != 3)
    {
        return 0;
    }

    // get my certificate
    ByteSmartPtr certBufferSmartPtr = Utils::readBufferFromFile(_localCertFilename);
    if (certBufferSmartPtr == NULL)
    {
        printf("prepareDhMessage - Error reading certificate filename - %s\n", _localCertFilename);
        return NULL;
    }

    // get my private key for signing
    KeypairContext* privateKeyContext = NULL;
    if (!CryptoWrapper::readRSAKeyFromFile(_privateKeyFilename, _privateKeyPassword, &privateKeyContext))
    {
        printf("prepareDhMessage #%d - Error during readRSAKeyFromFile - %s\n", messageType, _privateKeyFilename);
        cleanDhData();
        return NULL;
    }

    ByteSmartPtr conacatenatedPublicKeysSmartPtr = concat(2, _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES, _remoteDhPublicKeyBuffer, DH_KEY_SIZE_BYTES);
    if (conacatenatedPublicKeysSmartPtr == NULL)
    {
        printf("prepareDhMessage #%d failed - Error concatenating public keys\n", messageType);
        cleanDhData();
        return NULL;
    }

    BYTE signature[SIGNATURE_SIZE_BYTES];

    // signing with concadinated public keys
    if (!CryptoWrapper::signMessageRsa3072Pss(conacatenatedPublicKeysSmartPtr, conacatenatedPublicKeysSmartPtr.size(), privateKeyContext, signature, SIGNATURE_SIZE_BYTES)) {
        printf("Error in signing over concatenated public keys with my permanenet private key at prepareSigmaMessage #%d\n", messageType);
        cleanDhData();
        return NULL;
    }

    // Now we will calculate the MAC over my certiicate
    BYTE calculatedMac[HMAC_SIZE_BYTES];

    // size is 131 because we going get HMAC for large data
    BYTE macKey[131];
    deriveMacKey(macKey);

    if (!CryptoWrapper::hmac_SHA256(macKey, sizeof(macKey), certBufferSmartPtr, certBufferSmartPtr.size(), calculatedMac, HMAC_SIZE_BYTES))
    {
        printf("Error in calculating mac at prepareSigmaMessage #%d", messageType);
        cleanDhData();
        return NULL;
    }

    // pack all of the parts together
    ByteSmartPtr messageToSend = packMessageParts(4, _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES, (BYTE*)certBufferSmartPtr, certBufferSmartPtr.size(), signature, SIGNATURE_SIZE_BYTES, calculatedMac, HMAC_SIZE_BYTES);
    Utils::secureCleanMemory(calculatedMac, HMAC_SIZE_BYTES);
    return messageToSend;
}


bool Session::verifySigmaMessage(unsigned int messageType, const BYTE* pPayload, size_t payloadSize)
{
    if (messageType != 2 && messageType != 3)
    {
        return false;
    }

    unsigned int expectedNumberOfParts = 4;
    unsigned int partIndex = 0;

    std::vector<MessagePart> parts;
    if (!unpackMessageParts(pPayload, payloadSize, parts) || parts.size() != expectedNumberOfParts)
    {
        printf("verifySigmaMessage #%d failed - number of message parts is wrong\n", messageType);
        return false;
    }

    // Extracting remote public key
    if (parts[partIndex].partSize != DH_KEY_SIZE_BYTES) {
        printf("verifySigmaMessage #%d failed - unexpected remote public key size\n", messageType);
        return false;
    }
    if (messageType == 2)
        memcpy_s(_remoteDhPublicKeyBuffer, DH_KEY_SIZE_BYTES, parts[partIndex].part, parts[partIndex].partSize);
    else {
        BYTE remoteDhPublicKeyBufferRcvd[DH_KEY_SIZE_BYTES];
        memcpy_s(remoteDhPublicKeyBufferRcvd, DH_KEY_SIZE_BYTES, parts[partIndex].part, parts[partIndex].partSize);
        
        // verifying that remoteDhPublicKeyBuffer received in SIGMA message#1 and SIGMA message#3 are same.
        if (memcmp(_remoteDhPublicKeyBuffer, remoteDhPublicKeyBufferRcvd, DH_KEY_SIZE_BYTES) != 0) {
            printf("Remote public key buffer doesn't match SIGMA#1 != SIGMA#3\n");
            return false;
        }
    }
    partIndex++;

    // Extracting remote certificate
    size_t remoteCertSize = parts[partIndex].partSize;
    BYTE *remoteCert = new BYTE[remoteCertSize];
    memcpy(remoteCert, parts[partIndex].part, remoteCertSize);
    partIndex++;

    // Extracting signature (remote | local)
    if (parts[partIndex].partSize != SIGNATURE_SIZE_BYTES) {
        printf("verifySigmaMessage #%d failed - unexpected signature size\n", messageType);
        return false;
    }
    BYTE signature[SIGNATURE_SIZE_BYTES];
    memcpy_s(signature, SIGNATURE_SIZE_BYTES, parts[partIndex].part, parts[partIndex].partSize);
    partIndex++;

    // Extracting MAC
    if (parts[partIndex].partSize != HMAC_SIZE_BYTES) {
        printf("verifySigmaMessage #%d failed - unexpected MAC size\n", messageType);
        return false;
    }
    BYTE MAC[HMAC_SIZE_BYTES];
    memcpy_s(MAC, HMAC_SIZE_BYTES, parts[partIndex].part, parts[partIndex].partSize);

    // Verify certificate
    ByteSmartPtr rootCaCertBuffer = Utils::readBufferFromFile(_rootCaCertFilename);
    if (!CryptoWrapper::checkCertificate(rootCaCertBuffer, rootCaCertBuffer.size(), remoteCert, remoteCertSize, _expectedRemoteIdentityString)) {
        printf("Error in certificate checking at verifySigmaMessage #%d\n", messageType);
        return false;
    }

    // Verify signature
    bool isSignatureOk = false;
    KeypairContext* publicKey = NULL;
    if (!CryptoWrapper::getPublicKeyFromCertificate(remoteCert, remoteCertSize, &publicKey)) {
        printf("Error in getting public key from certificate at verifySigmaMessage #%d\n", messageType);
        return false;
    }

    ByteSmartPtr concatenatedPublicKeysSmartPtr = concat(2, _remoteDhPublicKeyBuffer, DH_KEY_SIZE_BYTES, _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES);
    if (concatenatedPublicKeysSmartPtr == NULL)
    {
        printf("verifySigmaMessage #%d failed - Error concatenating public keys\n", messageType);
        return false;
    }

    if (!CryptoWrapper::verifyMessageRsa3072Pss(concatenatedPublicKeysSmartPtr, concatenatedPublicKeysSmartPtr.size(), publicKey, signature, SIGNATURE_SIZE_BYTES, &isSignatureOk)) {
        printf("Error in verifying the signature at verifySigmaMessage #%d\n", messageType);
        return false;
    }

    if (!isSignatureOk) {
        printf("Signature doesn't match at verifySigmaMessage #%d\n", messageType);
        return false;
    }

    if (messageType == 2)
    {
        if (!CryptoWrapper::getDhSharedSecret(_dhContext, _remoteDhPublicKeyBuffer, DH_KEY_SIZE_BYTES, _sharedDhSecretBuffer, DH_KEY_SIZE_BYTES)) {
            printf("Error in getting the shared secret at verifySigmaMessage\n");
            return false;
        }
    }

    BYTE macKey[131];
    deriveMacKey(macKey);

    BYTE resultMac[HMAC_SIZE_BYTES];

    if (!CryptoWrapper::hmac_SHA256(macKey, sizeof(macKey), remoteCert, remoteCertSize, resultMac, HMAC_SIZE_BYTES)) {
        printf("Error in getting mac at verifySigmaMessage #%d\n", messageType);
        return false;
    }

    if (CRYPTO_memcmp(MAC, resultMac, HMAC_SIZE_BYTES) != 0) {
        printf("MAC doesn't match at verifySigmaMessage #%d\n", messageType);
        return false;
    }

    delete[] remoteCert;

    return true;
}


ByteSmartPtr Session::prepareEncryptedMessage(unsigned int messageType, const BYTE* message, size_t messageSize)
{
    size_t encryptedMessageSize = 0;

    BYTE* ciphertext = (BYTE*)Utils::allocateBuffer(MESSAGE_BUFFER_SIZE_BYTES);
    if (ciphertext == NULL)
    {
        return NULL;
    }

    // preparing aad by combinig messageType
    size_t size_t_size = sizeof(messageType);
    BYTE* aad = new BYTE[size_t_size];
    memcpy(aad, &messageType, size_t_size);

    if (!CryptoWrapper::encryptAES_GCM256(_sessionKey, SYMMETRIC_KEY_SIZE_BYTES, message, messageSize, aad, sizeof(aad), ciphertext, MESSAGE_BUFFER_SIZE_BYTES, &encryptedMessageSize)) {
        printf("Error in encrypting the message at prepareEncryptedMessage\n");
        return NULL;
    }

    ByteSmartPtr result(ciphertext, encryptedMessageSize);
    return result;
}


bool Session::decryptMessage(MessageHeader* header, BYTE* buffer, size_t* pPlaintextSize)
{

    size_t ciphertextSize = header->payloadSize;
    size_t plaintextSize = CryptoWrapper::getPlaintextSizeAES_GCM256(ciphertextSize);

    // preparing aad by combinig messageType
    size_t size_t_size = sizeof(header->messageType);
    BYTE* aad = new BYTE[size_t_size];
    memcpy(aad, &header->messageType, size_t_size);
    
    if (!CryptoWrapper::decryptAES_GCM256(_sessionKey, SYMMETRIC_KEY_SIZE_BYTES, buffer, ciphertextSize, aad, sizeof(aad), buffer, MESSAGE_BUFFER_SIZE_BYTES, NULL)) {
        printf("Error in decrypting at decryptMessage\n");
        return false;
    }

    if (pPlaintextSize != NULL)
    {
        *pPlaintextSize = plaintextSize;
    }

    return true;
}


bool Session::sendDataMessage(const BYTE* message, size_t messageSize)
{
    if (!active() || _state != DATA_SESSION_MESSAGE)
    {
        return false;
    }

    ByteSmartPtr encryptedMessage = prepareEncryptedMessage(DATA_SESSION_MESSAGE, message, messageSize);
    if (encryptedMessage == NULL)
    {
        return false;
    }

    return sendMessageInternal(DATA_SESSION_MESSAGE, encryptedMessage, encryptedMessage.size());
}


ByteSmartPtr Session::concat(unsigned int numOfParts, ...)
{
    va_list args;
    va_start(args, numOfParts);
    size_t totalSize = 0;
    std::list<MessagePart> partsList;

    // build a list and count the desired size for buffer
    for (unsigned int i = 0; i < numOfParts; i++)
    {
        MessagePart messagePart;
        messagePart.part = va_arg(args, const BYTE*);
        messagePart.partSize = va_arg(args, unsigned int);
        totalSize += messagePart.partSize;
        partsList.push_back(messagePart);
    }
    va_end(args);

    // allocate required buffer size (will be released by the smart pointer logic)
    BYTE* buffer = (BYTE*)Utils::allocateBuffer(totalSize);
    if (buffer == NULL)
    {
        return NULL;
    }

    // copy the parts into the new buffer
    BYTE* pos = buffer;
    size_t spaceLeft = totalSize;
    for (std::list<MessagePart>::iterator it = partsList.begin(); it != partsList.end(); it++)
    {
        memcpy_s(pos, spaceLeft, it->part, it->partSize);
        pos += it->partSize;
        spaceLeft -= it->partSize;
    }

    ByteSmartPtr result(buffer, totalSize);
    return result;
}


ByteSmartPtr Session::packMessageParts(unsigned int numOfParts, ...)
{
    va_list args;
    va_start(args, numOfParts);
    size_t totalSize = 0;
    std::list<MessagePart> partsList;

    // build a list and count the desired size for buffer
    for (unsigned int i = 0; i < numOfParts; i++)
    {
        MessagePart messagePart;
        messagePart.part = va_arg(args, const BYTE*);
        messagePart.partSize = va_arg(args, unsigned int);
        totalSize += (messagePart.partSize + sizeof(size_t));
        partsList.push_back(messagePart);
    }
    va_end(args);

    // allocate required buffer size (will be released by caller's smart pointer)
    BYTE* buffer = (BYTE*)Utils::allocateBuffer(totalSize);
    if (buffer == NULL)
    {
        return NULL;
    }

    // copy the parts into the new buffer
    std::list<MessagePart>::iterator it = partsList.begin();
    BYTE* pos = buffer;
    size_t spaceLeft = totalSize;
    for (; it != partsList.end(); it++)
    {
        memcpy_s(pos, spaceLeft, (void*)&(it->partSize), sizeof(size_t));
        pos += sizeof(size_t);
        spaceLeft -= sizeof(size_t);
        memcpy_s(pos, spaceLeft, it->part, it->partSize);
        pos += it->partSize;
        spaceLeft -= it->partSize;
    }

    ByteSmartPtr result(buffer, totalSize);
    return result;
}


bool Session::unpackMessageParts(const BYTE* buffer, size_t bufferSize, std::vector<MessagePart>& result)
{
    std::list<MessagePart> partsList;
    size_t pos = 0;
    while (pos < bufferSize)
    {
        if (pos + sizeof(size_t) >= bufferSize)
        {
            return false;
        }

        size_t* partSize = (size_t*)(buffer + pos);
        pos += sizeof(size_t);
        if (*partSize == 0 || (pos + *partSize) > bufferSize)
            return false;

        MessagePart messagePart;
        messagePart.partSize = *partSize;
        messagePart.part = (buffer + pos);
        partsList.push_back(messagePart);
        pos += *partSize;
    }

    result.resize(partsList.size());
    unsigned int i = 0;
    for (std::list<MessagePart>::iterator it = partsList.begin(); it != partsList.end(); it++)
    {
        result[i].part = it->part;
        result[i].partSize = it->partSize;
        i++;
    }
    return true;
}















