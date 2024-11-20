/// @file
/// @brief Пример подписи и проверки подписи.
///
/// В примере продемонстрированы следующие задачи:
/// - Получение контекста CSP функцией CryptAcquireContext.
/// - Подпись сообщения в различных режимах.
/// - Проверка подписи.
/// - Освобождение ресурсов.
///
/// Для корректной работы данного примера должен существовать контейнер с закрытым ключем 
/// (его можно скопировать из текущей директории в директорию с ключами по умолчанию), и соответствующий 
/// ему сертификат находится в текущей директории (для тестового контейнера он уже есть).
/// 
/// Если пароль на контейнер не корректный, то он будет запрошен в окне.
/// 
/// @warning Данный код предназначен только для ознакомления с возможностями CryptoAPI. В реальных приложениях
/// необходимо реализовать корректную обработку ошибок и освобождение ресурсов.
///
/// @copyright Copyright (c) InfoTeCS. All Rights Reserved.

#include <cstdlib>
#include <cstring>
#include <vector>
#include <fstream>
#include <iostream>

#include <windows.h>
#include <wincrypt.h>
#include <cspsdk/importitccsp.h>


#define MY_MESSAGE_FILE         "C:/Users/Vadim/Desktop/pivo/vipnet/samples/common/cryptoapi/pkcs7/pkcs7_simple_sign/test.txt"
#define MY_CERTIFICATE_FILE     "./test-signer.cer"
#define MY_CONTAINER_FILE_W     L"./test-signer-cnt"
#define MY_CONTAINER_PASSWORD   "11111111"

using namespace std;

static void HandleError( const char * s );
void writeToP7SFile(const std::vector<BYTE>& data, const std::string& outputFileName) {
    // Открываем файл для записи
    std::ofstream outFile(outputFileName, std::ios::binary);
    if (!outFile) {
        std::cerr << "Failed to open file for writing: " << outputFileName << std::endl;
        return;
    }

    // Записываем данные в файл
    outFile.write(reinterpret_cast<const char*>(data.data()), data.size());

    // Проверяем успешность записи
    if (outFile.good()) {
        std::cout << "File successfully written: " << outputFileName << std::endl;
    }
    else {
        std::cerr << "Error writing to file: " << outputFileName << std::endl;
    }

    outFile.close();
}
static std::vector<BYTE> LoadFile( const char * path );
PCCERT_CONTEXT GetRecipientCert(HCERTSTORE hCertStore, wchar_t* pSubject) {
    wchar_t* subject(pSubject);
    PCCERT_CONTEXT pCertContext(0);
    DWORD dwSize(0);
    CRYPT_KEY_PROV_INFO* pKeyInfo(0);

    int mustFree;
    DWORD dwKeySpec = 0;
    HCRYPTPROV hProv;

    for (;;) {
        if (subject) {
            // Если указан Subject Name, то ищем сертификат по нему, получаем его контекст
            pCertContext = CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                CERT_FIND_SUBJECT_STR_W, subject, pCertContext);
            if (pCertContext)
                return pCertContext;
        }
        else {
            // Находим следующий сертифкат, получаем его контекст
            pCertContext = CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                CERT_FIND_ANY, 0, pCertContext);
        }

        if (pCertContext) {
            if (!CryptAcquireCertificatePrivateKey(pCertContext, 0, 0, &hProv, &dwKeySpec, &mustFree)) {
                if (mustFree)
                    CryptReleaseContext(hProv, 0);
                continue;
            }

            // Получаем размер свойств сертификата
            if (!(CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, 0, &dwSize))) {
                cout << "Certificate property was not got" << endl;
                return 0;
            }

            if (pKeyInfo)
                free(pKeyInfo);

            // Выделяем память
            pKeyInfo = (CRYPT_KEY_PROV_INFO*)malloc(dwSize);

            if (!pKeyInfo) {
                cout << "Error occured during the time of memory allocating" << endl;
                return 0;
            }

            // Получаем свойства сертификата
            if (!(CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, pKeyInfo, &dwSize))) {
                free(pKeyInfo);
                cout << "Certificate property was not got" << endl;
                return 0;
            }

            if (mustFree)
                CryptReleaseContext(hProv, 0);
            free(pKeyInfo);
            return pCertContext;

        }
        else {
            cout << "Certificate with private key was not found" << endl;
            return 0;
        }
    }
}

static PCCERT_CONTEXT GetSignCertificate( const char * certPath , const wchar_t *containerPath,
    const char *containerPassword );


static void SignMessage( PCCERT_CONTEXT cert, const BOOL detached, const std::vector<BYTE> & message,
    std::vector<BYTE> & signature );

static void VerifyAttachedSign( const std::vector<BYTE> & signature, std::vector<BYTE> & message );

static void VerifyDetachedSign( const std::vector<BYTE> & signature, const std::vector<BYTE> & message );


int main()
{
    std::vector<BYTE> sourceMessage = LoadFile( MY_MESSAGE_FILE );

    HCERTSTORE hStoreHandle = CertOpenSystemStore(0, "MY");

    if (!hStoreHandle) {
        cout << "Store handle was not got" << endl;
        return false;
    }
    wchar_t* pSubject = L"vadim";
    // Получаем сертификат для подписания
    PCCERT_CONTEXT cert = GetRecipientCert(hStoreHandle, pSubject);
    {
        std::vector<BYTE> signAttached;
        SignMessage( cert, FALSE, sourceMessage, signAttached );
        writeToP7SFile(signAttached, "C:/Users/Vadim/Desktop/pivo/vipnet/samples/common/cryptoapi/pkcs7/pkcs7_simple_sign/sign.p7s");
        std::vector<BYTE> message;
        VerifyAttachedSign( signAttached, message );
    }

    {
        std::vector<BYTE> signDetached;
        SignMessage( cert, TRUE, sourceMessage, signDetached );
        VerifyDetachedSign( signDetached, sourceMessage );
    }

    CertFreeCertificateContext( cert );
    return 0;
}

static void HandleError( const char * s )
{
    std::cerr << "\nAn error occurred in running the program.\n";
    std::cerr << s << "\n";
    std::cerr << "Error number 0x" << std::hex << GetLastError() << "\n";
    std::cerr << "Program terminating.\n";
    exit( 1 );
}

static std::vector<BYTE> LoadFile( const char * path )
{
    if( !path )
    {
        HandleError( "Invalid file path." );
    }
    std::vector<BYTE> data;
    std::ifstream ifs( path, std::ifstream::binary );
    if( !ifs.is_open() )
    {
        std::cerr << "Error opening file '" << path << "'\n";
        HandleError( "Error opening file." );
    }
    ifs.seekg( 0, ifs.end );
    size_t size = ifs.tellg();
    if( !size )
    {
        std::cerr << "Attempt to load empty file '" << path << "'\n";
        HandleError( "Attempt to load empty file." );
    }
    data.resize( size );
    ifs.seekg( 0, ifs.beg );
    ifs.read( ( char* )&data[0], size );
    if( ifs.bad() )
    {
        std::cerr << "Error reading file '" << path << "'\n";
        HandleError( "Error reading file." );
    }
    return data;
}

static void SignMessage( PCCERT_CONTEXT cert, const BOOL detached, const std::vector<BYTE> & message,
    std::vector<BYTE> & signature )
{
    std::cout << "\nSigning message in " << ( detached ? "detached" : "attached" ) << " mode.\n";

    if( !cert )
    {
        HandleError( "Invalid parameter." );
    }

    CRYPT_SIGN_MESSAGE_PARA signParam;
    memset( &signParam, 0, sizeof( signParam ) );
    signParam.cbSize = sizeof( signParam );
    signParam.dwMsgEncodingType = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;
    signParam.pSigningCert = cert;
    signParam.HashAlgorithm.pszObjId = const_cast<LPSTR>( szOID_CSP2012_HASH_SIGN_256 );
    signParam.cMsgCert = 1;
    signParam.rgpMsgCert = &cert;

    // Опционально добавляем метку времени
    FILETIME ts;
    GetSystemTimeAsFileTime( &ts );

    DWORD tsLen = 0;
    if( !CryptEncodeObject( PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, szOID_RSA_signingTime, &ts, NULL, &tsLen ) )
    {
        HandleError( "First CryptEncodeObject() call failed." );
    }

    std::vector<BYTE> tsBuf( tsLen );
    if( !CryptEncodeObject( PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, szOID_RSA_signingTime, &ts, &tsBuf[0], &tsLen ) )
    {
        HandleError( "Second CryptEncodeObject() call failed." );
    }

    CRYPT_ATTR_BLOB tsBlob;
    memset( &tsBlob, 0, sizeof( tsBlob ) );
    CRYPT_ATTRIBUTE tsAttr;
    memset( &tsAttr, 0, sizeof( tsAttr ) );

    tsBlob.cbData = tsLen;
    tsBlob.pbData = &tsBuf[0];
    tsAttr.pszObjId = ( LPSTR )szOID_RSA_signingTime;
    tsAttr.cValue = 1;
    tsAttr.rgValue = &tsBlob;
    signParam.cAuthAttr = 1;
    signParam.rgAuthAttr = &tsAttr;


    const BYTE *messagePtr = &message[0];
    DWORD messageSize = message.size();
    DWORD signSize = 0;

    if( !CryptSignMessage( &signParam, detached, 1, &messagePtr, &messageSize, NULL, &signSize ) )
    {
        HandleError( "First CryptSignMessage() failed." );
    }

    signature.resize( signSize );
    if( !CryptSignMessage( &signParam, detached, 1, &messagePtr, &messageSize, &signature[0], &signSize ) )
    {
        HandleError( "Second CryptSignMessage() failed." );
    }

    std::cout << "Message has been signed. Signed message size: " << signSize << "\n";
}


static void VerifyAttachedSign(const std::vector<BYTE> & signature, std::vector<BYTE> & message )
{
    std::cout << "\nVerifying attached signature.\n";

    CRYPT_VERIFY_MESSAGE_PARA verifyParam;
    memset( &verifyParam, 0, sizeof( verifyParam ) );
    verifyParam.cbSize = sizeof( verifyParam );
    verifyParam.dwMsgAndCertEncodingType = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;

    DWORD messageSize = 0;
    if( !CryptVerifyMessageSignature( &verifyParam, 0, &signature[0], ( DWORD )signature.size(), NULL, &messageSize,
        NULL ) )
    {
        HandleError( "First CryptVerifyMessageSignature() call failed." );
    }

    PCCERT_CONTEXT cert = NULL;
    message.resize( messageSize );
    if( !CryptVerifyMessageSignature( &verifyParam, 0, &signature[0], ( DWORD )signature.size(),  &message[0],
        &messageSize, &cert ) )
    {
        HandleError( "Second CryptVerifyMessageSignature() call failed." );
    }

    char certName[512] = {0};
    if( !CertNameToStr( X509_ASN_ENCODING, &cert->pCertInfo->Subject, CERT_SIMPLE_NAME_STR, certName,
        sizeof( certName ) ) )
    {
        HandleError( "CertNameToStr() failed." );
    }

    CertFreeCertificateContext( cert );

    std::cout << "Signature is valid. Source message size: " << message.size() << " bytes, certificate: " <<
        certName << "\n";
}


static void VerifyDetachedSign( const std::vector<BYTE> & signature, const std::vector<BYTE> & message )
{
    std::cout << "\nVerifying detached signature.\n";

    CRYPT_VERIFY_MESSAGE_PARA verifyParam;
    memset( &verifyParam, 0, sizeof( verifyParam ) );
    verifyParam.cbSize = sizeof( verifyParam );
    verifyParam.dwMsgAndCertEncodingType = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;

    const BYTE *messagePtr = &message[0];
    DWORD messageSize = ( DWORD )message.size();
    PCCERT_CONTEXT cert = NULL;

    if( !CryptVerifyDetachedMessageSignature( &verifyParam, 0, &signature[0], ( DWORD )signature.size(),
        1, &messagePtr, &messageSize, &cert ) )
    {
        HandleError( "CryptVerifyDetachedMessageSignature() failed." );
    }

    char certName[512] = {0};
    if( !CertNameToStr( X509_ASN_ENCODING, &cert->pCertInfo->Subject, CERT_SIMPLE_NAME_STR, certName,
        sizeof( certName ) ) )
    {
        HandleError( "CertNameToStr() failed." );
    }

    CertFreeCertificateContext( cert );

    std::cout << "Signature is valid. Certificate: " << certName << "\n";
}
