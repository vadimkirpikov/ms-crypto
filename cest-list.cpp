#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <string>
#include <vector>

#pragma comment(lib, "Crypt32.lib")

// Структура для хранения сертификатов
struct CertificateInfo {
    std::string subjectName;
    PCCERT_CONTEXT certContext;
};

// Функция для получения всех сертификатов из хранилища
std::vector<CertificateInfo> GetCertificatesFromStore() {
    std::vector<CertificateInfo> certificates;

    // Открываем хранилище сертификатов "Личное"
    HCERTSTORE hStore = CertOpenSystemStore(0, L"MY");
    if (!hStore) {
        std::cerr << "Ошибка открытия хранилища: " << GetLastError() << std::endl;
        return certificates;
    }

    // Указатель на контекст сертификата
    PCCERT_CONTEXT pCertContext = nullptr;

    // Перечисляем сертификаты в хранилище
    while ((pCertContext = CertEnumCertificatesInStore(hStore, pCertContext)) != nullptr) {
        // Получаем размер строки для имени сертификата (Subject)
        DWORD subjectSize = CertNameToStrA(
            X509_ASN_ENCODING,
            &pCertContext->pCertInfo->Subject,
            CERT_X500_NAME_STR,
            nullptr,
            0
        );

        if (subjectSize == 0) {
            std::cerr << "Ошибка получения размера имени сертификата: " << GetLastError() << std::endl;
            continue;
        }

        std::string subjectName(subjectSize, '\0');

        // Получаем имя сертификата
        if (CertNameToStrA(
            X509_ASN_ENCODING,
            &pCertContext->pCertInfo->Subject,
            CERT_X500_NAME_STR,
            &subjectName[0],
            subjectSize
        ) == 0) {
            std::cerr << "Ошибка получения имени сертификата: " << GetLastError() << std::endl;
            continue;
        }

        // Добавляем сертификат в вектор
        certificates.push_back({ subjectName, pCertContext });
    }

    // Закрываем хранилище
    CertCloseStore(hStore, CERT_CLOSE_STORE_FORCE_FLAG);

    return certificates;
}

// Функция для вывода имени одного сертификата
void PrintCertificateName(const CertificateInfo& certInfo) {
    std::cout << "Имя сертификата: " << certInfo.subjectName << std::endl;
}

// Функция для вывода списка имен всех сертификатов
void ListAllCertificates(const std::vector<CertificateInfo>& certificates) {
    if (certificates.empty()) {
        std::cout << "Сертификаты не найдены." << std::endl;
        return;
    }

    std::cout << "Список сертификатов:" << std::endl;
    for (const auto& cert : certificates) {
        PrintCertificateName(cert);
    }
}

int main() {
    // Устанавливаем локализацию для русскоязычного вывода
    setlocale(LC_ALL, "rus");

    // Получаем сертификаты из хранилища
    std::vector<CertificateInfo> certificates = GetCertificatesFromStore();

    // Выводим список всех сертификатов
    ListAllCertificates(certificates);

    // Ввод для завершения программы
    std::string s;
    std::cin >> s;
    return 0;
}
