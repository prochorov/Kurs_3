#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <cstring>
#include <openssl/md5.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>

using namespace std;

// Структура для хранения информации о клиентах
struct Client {
    string id;
    string password;
};

// Функция для чтения базы клиентов из файла
vector<Client> readClientsFromFile(const string& filename) {
    vector<Client> clients;
    ifstream file(filename);
    if (file.is_open()) {
        string line;
        while (getline(file, line)) {
            size_t pos = line.find(':');
            if (pos != string::npos) {
                Client client;
                client.id = line.substr(0, pos);
                client.password = line.substr(pos + 1);
                clients.push_back(client);
            }
        }
        file.close();
    }
    return clients;
}

// Функция для аутентификации клиента
bool authenticateClient(int clientSocket, const vector<Client>& clients) {
    // Принимаем идентификатор клиента
    char idBuffer[256];
    int idSize = recv(clientSocket, idBuffer, sizeof(idBuffer), 0);
    if (idSize <= 0) {
        return false; // Ошибка или разрыв соединения
    }
    idBuffer[idSize] = '\0';

    // Ищем клиента в базе
    string idToAuthenticate(idBuffer);
    string password;
    for (const auto& client : clients) {
        if (client.id == idToAuthenticate) {
            password = client.password;
            break;
        }
    }

    if (password.empty()) {
        send(clientSocket, "ERR", 3, 0); // Клиент не найден
        return false;
    }

    // Генерируем случайное число SALT и отправляем его клиенту
    uint64_t salt = rand(); // Замените на генерацию реального случайного числа
    send(clientSocket, &salt, sizeof(salt), 0);

    // Принимаем хэш пароля от клиента
    char hashBuffer[MD5_DIGEST_LENGTH];
    recv(clientSocket, hashBuffer, sizeof(hashBuffer), 0);

    // Вычисляем хэш (MD5(SALT || PASSWORD)) и сравниваем с полученным
    MD5_CTX md5Context;
    MD5_Init(&md5Context);
    MD5_Update(&md5Context, &salt, sizeof(salt));
    MD5_Update(&md5Context, password.c_str(), password.size());
    unsigned char computedHash[MD5_DIGEST_LENGTH];
    MD5_Final(computedHash, &md5Context);

    if (memcmp(hashBuffer, computedHash, MD5_DIGEST_LENGTH) == 0) {
        send(clientSocket, "OK", 2, 0); // Аутентификация успешна
        return true;
    } else {
        send(clientSocket, "ERR", 3, 0); // Неверный пароль
        return false;
    }
}

// Функция для выполнения вычислений над данными
int64_t calculateAverage(const vector<int64_t>& data) {
    int64_t sum = 0;
    for (int64_t value : data) {
        sum += value;
    }
    
    // Дополнительная логика для обработки переполнения
    if (sum > INT64_MAX) {
        return INT64_MAX;
    } else if (sum < INT64_MIN) {
        return INT64_MIN;
    }
    
    return sum / data.size();
}

int main(int argc, char* argv[]) {
    // Разбор параметров командной строки

    // Создание серверного сокета и настройка сетевого соединения
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        perror("Ошибка при создании соксета");
        return 1;
    }

    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(33333); // Порт по умолчанию
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    if (bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) == -1) {
        perror("Ошибка при привязке соксета к адресу");
        return 1;
    }

    if (listen(serverSocket, 5) == -1) {
        perror("Ошибка при прослушивании соксета");
        return 1;
    }

    vector<Client> clients = readClientsFromFile("clients.txt");

    while (true) {
        sockaddr_in clientAddress;
        socklen_t clientAddressSize = sizeof(clientAddress);
        int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddress, &clientAddressSize);
        if (clientSocket == -1) {
            perror("Ошибка при принятии клиента");
            continue;
        }

        // Аутентификация клиента
        if (!authenticateClient(clientSocket, clients)) {
            close(clientSocket);
            continue;
        }

        // Принятие данных от клиента
        int32_t numVectors;
        recv(clientSocket, &numVectors, sizeof(numVectors), 0);
        numVectors = ntohl(numVectors); // Порядок байтов в сети может отличаться

        for (int i = 0; i < numVectors; ++i) {
            int32_t vectorSize;
            recv(clientSocket, &vectorSize, sizeof(vectorSize), 0);
            vectorSize = ntohl(vectorSize); // Порядок байтов в сети может отличаться

            vector<int64_t> data(vectorSize);
            recv(clientSocket, data.data(), vectorSize * sizeof(int64_t), 0);

            int64_t result = calculateAverage(data);

            // Отправляем результат клиенту
            send(clientSocket, &result, sizeof(result), 0);
        }

        close(clientSocket); // Завершаем сеанс с клиентом
    }

    close(serverSocket); // Завершаем сервер

    return 0;
}
