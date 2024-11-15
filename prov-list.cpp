#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <string>

#pragma comment(lib, "Crypt32.lib")

// Функция для вывода всех криптопровайдеров
void ListCryptographicProviders() {
    DWORD dwIndex = 0;
    DWORD dwProvType = 0;
    wchar_t providerName[1024];
    DWORD providerNameSize = sizeof(providerName);

    // Перебираем все доступные криптопровайдеры
    while (CryptEnumProviders(dwIndex, NULL, NULL, &dwProvType, providerName, &providerNameSize)) {
        std::wcout << "Provider " << providerName << std::endl;
        providerNameSize = sizeof(providerName);  // Сбрасываем размер для следующей итерации
        dwIndex++;
    }
}

int main() {
    ListCryptographicProviders();

    std::string s;
    std::cin >> s;

    return 0;
}
