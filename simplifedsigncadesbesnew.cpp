#pragma warning(disable:4996)

#include <iterator>
#include <vector>
#include <iostream>
#include <wchar.h>
#include <cstdlib>

#ifdef _WIN32
#include <tchar.h>
#else
#include <cstdio>
#include "reader/tchar.h"
#endif

#include "cades.h"

using namespace std;

#include "../samples_util.h"

// Функция создания подписи
bool CreateSignature(PCCERT_CONTEXT context, const vector<unsigned char>& data) {
    // Задаем параметры 
    CRYPT_SIGN_MESSAGE_PARA signPara = { sizeof(signPara) };
    signPara.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    signPara.pSigningCert = context;
    signPara.HashAlgorithm.pszObjId = (LPSTR)GetHashOid(context);

    std::cout << "Hash Algorithm OID: " << signPara.HashAlgorithm.pszObjId << std::endl;

    CADES_SIGN_PARA cadesSignPara = { sizeof(cadesSignPara) };
    cadesSignPara.dwCadesType = CADES_BES; // Указываем тип усовершенствованной подписи CADES_BES

    CADES_SIGN_MESSAGE_PARA para = { sizeof(para) };
    para.pSignMessagePara = &signPara;
    para.pCadesSignPara = &cadesSignPara;

    const unsigned char* pbToBeSigned[] = { &data[0] };
    DWORD cbToBeSigned[] = { (DWORD)data.size() };

    CERT_CHAIN_PARA ChainPara = { sizeof(ChainPara) };
    PCCERT_CHAIN_CONTEXT pChainContext = NULL;

    std::vector<PCCERT_CONTEXT> certs;

    if (CertGetCertificateChain(NULL, context, NULL, NULL, &ChainPara, 0, NULL, &pChainContext)) {
        for (DWORD i = 0; i < pChainContext->rgpChain[0]->cElement - 1; ++i) {
            certs.push_back(pChainContext->rgpChain[0]->rgpElement[i]->pCertContext);
        }
    }

    // Добавляем в сообщение цепочку сертификатов без корневого
    if (!certs.empty()) {
        signPara.cMsgCert = (DWORD)certs.size();
        signPara.rgpMsgCert = &certs[0];
    }

    PCRYPT_DATA_BLOB pSignedMessage = 0;
    // Создаем подписанное сообщение
    if (!CadesSignMessage(&para, 0, 1, pbToBeSigned, cbToBeSigned, &pSignedMessage)) {
        cout << "CadesSignMessage() failed" << endl;
        return false;
    }

    if (pChainContext)
        CertFreeCertificateChain(pChainContext);

    vector<unsigned char> message(pSignedMessage->cbData);
    copy(pSignedMessage->pbData, pSignedMessage->pbData + pSignedMessage->cbData, message.begin());

    // Сохраняем результат в файл sign.dat
    if (SaveVectorToFile<unsigned char>("sign.dat", message)) {
        cout << "Signature was not saved" << endl;
        return false;
    }

    cout << "Signature was saved successfully" << endl;

    // Освобождаем структуру с закодированным подписанным сообщением
    if (!CadesFreeBlob(pSignedMessage)) {
        cout << "CadesFreeBlob() failed" << endl;
        return false;
    }

    return true;
}


bool SignCadesBes(wchar_t* certName, vector<unsigned char>& data) {
    // Открываем хранилище сертификатов пользователя
    HCERTSTORE hStoreHandle = CertOpenSystemStore(0, "MY");

    if (!hStoreHandle) {
        cout << "Store handle was not got" << endl;
        return false;
    }

    // Получаем сертификат для подписания
    PCCERT_CONTEXT context = GetRecipientCert(hStoreHandle, certName);

    if (!context) {
        cout << "There is no certificate with the specified name." << endl;
        return false;
    }

    // Создаем подпись
    if (!CreateSignature(context, data)) {
        cout << "Failed to create signature" << endl;
        return false;
    }
    // Закрываем хранилище
    if (!CertCloseStore(hStoreHandle, 0)) {
        cout << "Certificate store handle was not closed." << endl;
        return false;
    }

    // Освобождаем контекст сертификата
    if (context)
        CertFreeCertificateContext(context);
    return true;

}
int main() {
    setlocale(LC_ALL, "ru_RU.UTF-8");
    // Указываем имя сертификата
    wchar_t* certName = L"vadim"; // Замените на имя вашего сертификата
    // Формируем данные для подписания
    vector<unsigned char> data(10, 25); // Пример данных (10 байтов со значением 25)
    if (!SignCadesBes(certName, data)) {
        cout << "Bad!\n";
        return -1;
    }
    return 0;
}
