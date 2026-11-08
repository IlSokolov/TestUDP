//Клиентская часть приложения

//Импорты

#include <winsock2.h>
#include <WS2tcpip.h>
#include <mswsock.h>

#include "../secure_zero.h"
#include "../settings.hpp"
#include "../transport.hpp"

#include <cstdint>
#include <algorithm>
#include <array>
#include <vector>
#include <chrono>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>

//Подключение зависимости Ws2_32.lib для winsock2
#pragma comment(lib, "Ws2_32.lib")

//Класс, предоставляющий интерфейс для клиентского взаимодействия
class UDPClient
{
public:

    /*
        Конструктор, который инициализирует использование библиотеки Windows Sockets,
        создает дескриптор сокета и устанавливает адрес сервера

        Принимаемые аргументы:
            const char* ip - IP-адрес сервера
            std::uint16_t port - порт сервера
    */
    UDPClient(const char* ip, std::uint16_t port) {

        int result = WSAStartup(MAKEWORD(2, 2), &wsdt);

        if (result != 0) throw std::runtime_error("WSAStartup failed");

        winsock_initialized = true;

        client_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

        if (client_socket == INVALID_SOCKET) {
            cleanup();
            throw std::runtime_error("Socket creation failed");
        }

        BOOL enableReset = FALSE;
        DWORD bytesReturned = 0;

        if (WSAIoctl(client_socket, SIO_UDP_CONNRESET, &enableReset, sizeof(enableReset), nullptr, 0, &bytesReturned, nullptr, nullptr) == SOCKET_ERROR) {
            const int error = WSAGetLastError();
            cleanup();
            throw std::runtime_error("WSAIoctl failed. WSA error: " + std::to_string(error));
        }

        server.sin_family = AF_INET;
        server.sin_port = htons(port);

        if (InetPtonA(AF_INET, ip, &server.sin_addr) != 1) {
            cleanup();
            throw std::runtime_error("Invalid server IP address");
        }
    }

    /*
        Деструктор
        Вызывает метод, который корректно завершает работу клиента
    */
    ~UDPClient() {
        cleanup();
    }

    /*
        Оператор присваивания и конструктор копирования удалены
    */
    UDPClient(const UDPClient&) = delete;
    UDPClient& operator=(const UDPClient&) = delete;

    /*
        Метод, который генерирует случайные значения для client_random и exchange_id
    */
    void generateRandom() {

        Util::generateRandomBytes(client_random);

        std::array<std::uint8_t, 4> id_bytes{};
        Util::generateRandomBytes(id_bytes);

        exchange_id = (static_cast<std::uint32_t>(id_bytes[0]) << 24) |
                      (static_cast<std::uint32_t>(id_bytes[1]) << 16) |
                      (static_cast<std::uint32_t>(id_bytes[2]) << 8) |
                       static_cast<std::uint32_t>(id_bytes[3]);
    }

    /*
        Метод, который формирует сообщение INIT

        Возвращаемое значение:
            UdpTransport::Packet - сформированный пакет INIT
    */
    UdpTransport::Packet buildInit() {

        UdpTransport::Packet payload(client_random.begin(), client_random.end());

        return Util::makePacket(Util::MessageType::INIT, exchange_id, payload);
    }

    /*
        Метод, который формирует секрет из случайных значений клиента и сервера
    */
    void deriveSecret() {
        secret = Util::calculateSecret(exchange_id, client_random, server_random, nonce);
    }

    /*
        Метод, который вычисляет HMAC и формирует сообщение CONFIRM

        Возвращаемое значение:
            UdpTransport::Packet - сформированный пакет CONFIRM
    */
    UdpTransport::Packet buildConfirm() {

        auto hmac = Util::calculateHmac(Util::MessageType::CONFIRM, exchange_id, secret, client_random, server_random, nonce);

        UdpTransport::Packet payload(hmac.begin(), hmac.end());

        return Util::makePacket(Util::MessageType::CONFIRM, exchange_id, payload);
    }

    /*
        Метод, который отправляет пакет серверу

        Принимаемые аргументы:
            const UdpTransport::Packet& packet - пакет, который необходимо отправить
    */
    void sendTo(const UdpTransport::Packet& packet) {

        if (exchange_timer.expired()) {
            resetExchange();
            throw std::runtime_error("Exchange timed out");
        }

        UdpTransport::sendDatagram(client_socket, packet, server);
    }

    /*
        Метод, который запускает таймер жизни цикла обмена
    */
    void startExchangeTimeout() {
        exchange_timer.start();
    }

    /*
        Метод, который очищает секреты после окончания цикла обмена
    */
    void resetExchange() noexcept {

        secure_zero(client_random.data(), client_random.size());
        secure_zero(server_random.data(), server_random.size());
        secure_zero(nonce.data(), nonce.size());
        secure_zero(secret.data(), secret.size());

        exchange_id = 0;

        exchange_timer.reset();
    }

    /*
        Метод, который проверяет активность цикла обмена

        Возвращаемое значение:
            bool - true, если обмен активен, иначе false
    */
    bool exchangeActive() const noexcept {
        return exchange_timer.active();
    }

    /*
        Метод, который проверяет INIT_ACK от сервера и извлекает случайные значения

        Принимаемые аргументы:
            const UdpTransport::Packet& packet - пакет INIT_ACK полученный от сервера

        Возвращаемое значение:
            bool - true, если пакет корректный, иначе false
    */
    bool acceptInitAck(const UdpTransport::Packet& packet) {

        Util::ParsedPacket parsed;

        if (!Util::parsePacket(packet, parsed)) return false;

        if (parsed.type != Util::MessageType::INIT_ACK || parsed.exchange_id != exchange_id) return false;

        std::copy_n(parsed.payload.begin(), 32, server_random.begin());
        std::copy_n(parsed.payload.begin() + 32, 32, nonce.begin());

        deriveSecret();

        return true;
    }

    /*
        Метод, который проверяет CONFIRM_ACK от сервера с помощью HMAC

        Принимаемые аргументы:
            const std::vector<std::uint8_t>& packet - пакет CONFIRM_ACK полученный от сервера

        Возвращаемое значение:
            bool - true, если HMAC совпадает, иначе false
    */
    bool verifyConfirmAck(const UdpTransport::Packet& packet) {

        Util::ParsedPacket parsed;

        if (!Util::parsePacket(packet, parsed)) return false;

        if (parsed.type != Util::MessageType::CONFIRM_ACK || parsed.exchange_id != exchange_id) return false;

        const auto expected_hmac = Util::calculateHmac(Util::MessageType::CONFIRM_ACK, exchange_id, secret, client_random, server_random, nonce);

        return Util::constantTimeEqual(expected_hmac.data(), parsed.payload.data(), expected_hmac.size());
    }

    /*
        Метод, который получает пакет от сервера

        Принимаемые аргументы:
            UdpTransport::Packet& packet - переменная, в которую записывается полученный пакет
            const timeval* max_wait - максимальное время ожидания пакета

        Возвращаемое значение:
            enum class UdpTransport::ReceiveStatus - состояние получения пакета
    */
    UdpTransport::ReceiveStatus receiveFrom(UdpTransport::Packet& packet, const timeval* max_wait = nullptr) {
        auto timeout = exchange_timer.remaining();

        if (timeout && timeout->tv_sec == 0 && timeout->tv_usec == 0) {
            resetExchange();
            return UdpTransport::ReceiveStatus::Timeout;
        }

        if (max_wait != nullptr) {
            if (!timeout ||
                max_wait->tv_sec < timeout->tv_sec ||
                (max_wait->tv_sec == timeout->tv_sec && max_wait->tv_usec < timeout->tv_usec)) {
                timeout = *max_wait;
            }
        }

        sockaddr_in sender{};

        auto status = UdpTransport::receiveDatagram(client_socket, packet, sender, timeout ? &*timeout : nullptr);

        if (exchange_timer.expired()) {
            UdpTransport::clearPacket(packet);
            resetExchange();
            return UdpTransport::ReceiveStatus::Timeout;
        }

        if (status == UdpTransport::ReceiveStatus::Timeout) {
            return status;
        }

        if (status != UdpTransport::ReceiveStatus::Received) return status;

        if (!UdpTransport::sameEndpoint(sender, server)) {
            UdpTransport::clearPacket(packet);
            return UdpTransport::ReceiveStatus::UnexpectedSender;
        }

        return status;
    }

    /*
        Метод, который возвращает exchange_id

        Возвращаемое значение:
            std::uint32_t - идентификатор текущего обмена
    */
    std::uint32_t getExchangeId() const {
        return exchange_id;
    }

    /*
        Метод, который очищает секреты, закрывает сокет
        и прекращает использование библиотеки DLL Winsock 2
    */
    void cleanup() {
        resetExchange();

        if (client_socket != INVALID_SOCKET) {
            closesocket(client_socket);
            client_socket = INVALID_SOCKET;
        }

        if (winsock_initialized) {
            WSACleanup();
            winsock_initialized = false;
        }
    }

private:
    std::uint32_t exchange_id{};

    std::array<std::uint8_t, 32> client_random{};
    std::array<std::uint8_t, 32> server_random{};
    std::array<std::uint8_t, 32> nonce{};
    std::array<std::uint8_t, 32> secret{};

    WSADATA wsdt{};
    SOCKET client_socket = INVALID_SOCKET;
    sockaddr_in server{};

    bool winsock_initialized = false;

    UdpTransport::ExchangeTimer exchange_timer;
};

/*
    Точка входа в программу
    описывает логику клиентского цикла обмена
*/
int main() {

    try {

        constexpr int MAX_RETRANSMISSIONS = 4;
        constexpr auto RETRY_INTERVAL = std::chrono::seconds(1);

        UDPClient client("127.0.0.1", 8080);

        client.generateRandom();

        auto init_packet = client.buildInit();

        client.startExchangeTimeout();

        client.sendTo(init_packet);

        std::cout << "INIT sent, exchange = " << client.getExchangeId() << '\n';

        /*
            Функция, которая ожидает ответ сервера и повторно отправляет пакет,
            если ответ не был получен

            Принимаемые аргументы:
                const UdpTransport::Packet& outgoing - пакет для отправки
                auto validate - функция проверки полученного ответа
                const char* retry_name - название повторно отправляемого сообщения
                const char* invalid_message - сообщение об ошибке при неверном ответе

            Возвращаемое значение:
                bool - true, если ответ получен и прошел проверку, иначе false
        */
        auto waitForResponse = [&](const UdpTransport::Packet& outgoing, auto validate, const char* retry_name, const char* invalid_message) -> bool {

                int retries = 0;
                auto next_retry = std::chrono::steady_clock::now() + RETRY_INTERVAL;

                UdpTransport::Packet response;

                while (true) {

                    std::optional<timeval> wait_timeout;

                    if (retries < MAX_RETRANSMISSIONS) {

                        auto remaining = next_retry - std::chrono::steady_clock::now();

                        if (remaining < std::chrono::steady_clock::duration::zero()) {
                            remaining = std::chrono::steady_clock::duration::zero();
                        }

                        const auto microseconds = std::chrono::ceil<std::chrono::microseconds>(remaining).count();

                        timeval timeout{};
                        timeout.tv_sec = static_cast<long>(microseconds / 1'000'000);
                        timeout.tv_usec = static_cast<long>(microseconds % 1'000'000);

                        wait_timeout = timeout;
                    }

                    auto status = client.receiveFrom(response, wait_timeout ? &*wait_timeout : nullptr);

                    if (status == UdpTransport::ReceiveStatus::Timeout) {
                        if (!client.exchangeActive()) {
                            std::cerr << "Exchange timeout\n";
                            UdpTransport::clearPacket(response);
                            return false;
                        }

                        if (retries < MAX_RETRANSMISSIONS && std::chrono::steady_clock::now() >= next_retry) {

                            client.sendTo(outgoing);

                            ++retries;

                            std::cout << retry_name << " retransmitted ("
                                << retries << "/" << MAX_RETRANSMISSIONS << ")\n";

                            next_retry = std::chrono::steady_clock::now() + RETRY_INTERVAL;
                        }

                        continue;
                    }

                    if (status != UdpTransport::ReceiveStatus::Received) {
                        std::cerr << "Invalid datagram\n";
                        UdpTransport::clearPacket(response);
                        continue;
                    }

                    if (!validate(response)) {
                        std::cerr << invalid_message << '\n';
                        UdpTransport::clearPacket(response);
                        continue;
                    }

                    UdpTransport::clearPacket(response);
                    return true;
                }
            };

        //Ожидание ответа INIT_ACK с повторной отправкой INIT
        if (!waitForResponse(init_packet,
            [&](const UdpTransport::Packet& packet) {
                return client.acceptInitAck(packet);
            },
            "INIT", "Invalid INIT_ACK")) {

            UdpTransport::clearPacket(init_packet);

            return 1;
        }

        UdpTransport::clearPacket(init_packet);

        std::cout << "INIT_ACK received\n";

        auto confirm_packet = client.buildConfirm();

        client.sendTo(confirm_packet);

        std::cout << "CONFIRM sent\n";

        //Ожидание ответа CONFIRM_ACK с повторной отправкой CONFIRM
        if (!waitForResponse(confirm_packet,
            [&](const UdpTransport::Packet& packet) {
                return client.verifyConfirmAck(packet);
            },
            "CONFIRM", "Invalid CONFIRM_ACK")) {

            UdpTransport::clearPacket(confirm_packet);
            return 1;
        }

        UdpTransport::clearPacket(confirm_packet);

        const auto exchange_id = client.getExchangeId();

        std::cout << "ok exchange=" << exchange_id << ";\n";

        client.resetExchange();

        return 0;
    }
    catch (const std::exception& exception) {
        std::cerr << "Client error: " << exception.what() << '\n';
        return 1;
    }
}
