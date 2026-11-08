//Серверная часть приложения
    
//Импорты

#include <winsock2.h>
#include "../secure_zero.h"
#include "../settings.hpp"
#include "../transport.hpp"

#include <algorithm>
#include <cstdint>
#include <unordered_set>
#include <array>
#include <vector>
#include <chrono>
#include <iostream>
#include <stdexcept>

//Подключение зависимости Ws2_32.lib для winsock2
#pragma comment(lib, "Ws2_32.lib")

//Класс, предоставляющий интерфейс для серверного взаимодействия
class UDPServer
{
public:

    /*
        Явный конструктор, не допускает неявного преобразования типов
        инициализирует использование библиотеки Windows Sockets
        создает дескриптор сокета и устанавливает параметры соединения

        Принимаемые аргументы:
            std::uint16_t port - порт, по которому будет доступен сервер
    */
    explicit UDPServer(std::uint16_t port) {

        int result = WSAStartup(MAKEWORD(2, 2), &wsdt);

        if (result != 0) throw std::runtime_error("WSAStartup failed");

        winsock_initialized = true;

        server_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

        if (server_socket == INVALID_SOCKET) {
            cleanup();
            throw std::runtime_error("Socket creation failed");
        }

        server.sin_family = AF_INET;
        server.sin_addr.s_addr = htonl(INADDR_ANY);
        server.sin_port = htons(port);

        if (bind(server_socket, reinterpret_cast<sockaddr*>(&server), sizeof(server)) == SOCKET_ERROR) {
            cleanup();
            throw std::runtime_error("Bind failed");
        }
    }

    /*
        Деструктор
        Вызывает метод, котрый корректно завершает цикл обмена
    */
    ~UDPServer() {
        cleanup();
    }

    /*
        Оператор присваивания и конструктор копирования удалены 
    */
    UDPServer(const UDPServer&) = delete;
    UDPServer& operator=(const UDPServer&) = delete;

    /*
        Метод, который генерирует рандомные значения для server_random и nonce
    */
    void generateRandom() {
        Util::generateRandomBytes(server_random);
        Util::generateRandomBytes(nonce);
    }

    /*
        Метод, который формирует сообщение INIT_ACK

        Возвращаемое значение:
            using UdpTransport::Packet - алиас для нераспаршенного пакета сообщения
    */
    UdpTransport::Packet buildInitAck() {

        std::vector<std::uint8_t> payload;

        payload.insert(payload.end(), server_random.begin(), server_random.end());
        payload.insert(payload.end(), nonce.begin(), nonce.end());

        return Util::makePacket(Util::MessageType::INIT_ACK, exchange_id, payload);
    }

    /*
        Метод, который формирует секрет из 32 байтов хэша 
    */
    void deriveSecret() {
        secret = Util::calculateSecret(exchange_id, client_random, server_random, nonce);
    }

    /*
        Метод, который вычисляет hmac и формирует сообщение CONFIRM_ACK

        Возвращаемое значение:
            using UdpTransport::Packet - алиас для нераспаршенного пакета сообщения
    */
    UdpTransport::Packet buildConfirmAck() {

        auto hmac = Util::calculateHmac(Util::MessageType::CONFIRM_ACK, exchange_id, secret, client_random, server_random, nonce);

        UdpTransport::Packet payload(hmac.begin(), hmac.end());

        return Util::makePacket(Util::MessageType::CONFIRM_ACK, exchange_id, payload);
    }

    /*
        Метод, который запускает таймер жизни цикла обмена
    */
    void startExchangeTimeout() {
        exchange_timer.start();
    }

    /*
        Метод, который очищает секреты после окончания времени жизни цикла обмена
    */
    void resetExchange() noexcept {

        secure_zero(client_random.data(), client_random.size());
        secure_zero(server_random.data(), server_random.size());
        secure_zero(nonce.data(), nonce.size());
        secure_zero(secret.data(), secret.size());

        exchange_id = 0;

        client = {};
        client_known = false;

        exchange_timer.reset();
    }

    /*
        Метод, который устанавливает клиента-отправителя

        Принимаемые аргументы:
            sockaddr_in& sender - адрес транспорта и порт клиента
    */
    void setClient(const sockaddr_in& sender) {

        if (sender.sin_family != AF_INET) {
            throw std::invalid_argument("Invalid client address");
        }

        client = sender;
        client_known = true;
    }

    /*
        Метод, который проверяет что пакет пришел от того же клиента, с которым сервер начал текущий обмен.

        Принимаемые аргументы:
            sockaddr_in& sender - адрес транспорта и порт клиента
    */
    bool isSameClient(const sockaddr_in& sender) const {
        return client_known && UdpTransport::sameEndpoint(client, sender);
    }

    /*
        Метод, который проверяет что пришел идентичный INIT

        Принимаемые аргументы:
            const UdpTransport::Packet& packet - пакет INIT полученный от клиента
            const sockaddr_in& sender - адрес транспорта и порт клиента

        Возвращаемое значение:
            bool - false, если INIT различный, true, если идентичный
    */
    bool isDuplicateInit(const UdpTransport::Packet& packet, const sockaddr_in& sender) const {

        if (!exchange_timer.active() || !isSameClient(sender)) return false;

        Util::ParsedPacket parsed;

        if (!Util::parsePacket(packet, parsed)) return false;

        if (parsed.type != Util::MessageType::INIT || parsed.exchange_id != exchange_id) return false;

        if (parsed.payload.size() != client_random.size()) return false;

        return Util::constantTimeEqual(parsed.payload.data(), client_random.data(), client_random.size());
    }

    /*
        Метод, который сохраняет информацию об успешно завершённом обмене

        Принимаемые аргументы:
            const UdpTransport::Packet& confirm_packet - пакет CONFIRM полученный от клиента
            const UdpTransport::Packet& confirm_ack_packet - пакет CONFIRM_ACK сформированный сервером
    */
    void rememberCompletedExchange(const UdpTransport::Packet& confirm_packet, const UdpTransport::Packet& confirm_ack_packet) {

        clearCompletedExchange();

        completed_confirm_packet = confirm_packet;
        completed_confirm_ack_packet = confirm_ack_packet;
        completed_client = client;

        completed_cache_expiration = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        completed_exchange_valid = true;
    }

    /*
        Метод, который повторно отправляет CONFIRM_ACK, если первоначальный ответ не дошел до клиента

        Принимаемые аргументы:
            const UdpTransport::Packet& packet - пакет CONFIRM_ACK сформированный сервером
            const sockaddr_in& sender - адрес транспорта и порт клиента
    */
    bool resendCompletedConfirmAck(const UdpTransport::Packet& packet, const sockaddr_in& sender) {

        if (!completed_exchange_valid) return false;

        if (std::chrono::steady_clock::now() >= completed_cache_expiration) {
            clearCompletedExchange();
            return false;
        }

        if (!UdpTransport::sameEndpoint(sender, completed_client)) return false;

        if (packet.size() != completed_confirm_packet.size()) return false;

        if (!Util::constantTimeEqual(packet.data(), completed_confirm_packet.data(), packet.size())) {
            return false;
        }

        UdpTransport::sendDatagram(server_socket, completed_confirm_ack_packet, completed_client);

        return true;
    }

    /*
        Метод, который отправляет пакет клиенту

        Принимаемые аргументы:
            const UdpTransport::Packet& packet - пакет, который необходимо отправить
    */
    void sendTo(const UdpTransport::Packet& packet) {
        if (!client_known) {
            throw std::runtime_error("Client address is not set");
        }

        if (exchange_timer.expired()) {
            resetExchange();
            throw std::runtime_error("Exchange timed out");
        }

        UdpTransport::sendDatagram(server_socket, packet, client);
    }

    /*
        Метод, который проверяет INIT от клиента и начинает цикл обмена

        Принимаемые аргументы:
            const UdpTransport::Packet& packet - пакет INIT полученный от клиента
            const sockaddr_in& sender - адрес транспорта и порт клиента

        Возвращаемое значение:
            bool - false, если пакет неверной структуры, true, если пакет правильно сформирован
    */
    bool acceptInit(const UdpTransport::Packet& packet, const sockaddr_in& sender) {

        Util::ParsedPacket parsed;

        if (!Util::parsePacket(packet, parsed)) return false;

        if (parsed.type != Util::MessageType::INIT) return false;

        if (exchange_ids.count(parsed.exchange_id) != 0) return false;

        exchange_id = parsed.exchange_id;

        std::copy(parsed.payload.begin(), parsed.payload.end(), client_random.begin());

        exchange_ids.insert(exchange_id);

        setClient(sender);

        generateRandom();
        deriveSecret();

        startExchangeTimeout();

        return true;
    }

    /*
        Метод, который проверяет CONFIRM от клиента

        Принимаемые аргументы:
            const UdpTransport::Packet& packet - пакет CONFIRM полученный от клиента

        Возвращаемое значение:
            bool - false, если пакет неверной структуры, true, если пакет правильно сформирован
    */
    bool verifyConfirm(const UdpTransport::Packet& packet) {

        Util::ParsedPacket parsed;

        if (!Util::parsePacket(packet, parsed)) return false;

        if (parsed.type != Util::MessageType::CONFIRM || parsed.exchange_id != exchange_id) return false;

        const auto expected_hmac = Util::calculateHmac(Util::MessageType::CONFIRM, exchange_id, secret, client_random, server_random, nonce);

        return Util::constantTimeEqual(expected_hmac.data(), parsed.payload.data(), expected_hmac.size());
    }

    /*
        Метод, который получает пакет от клиента 

        Принимаемые аргументы:
            const UdpTransport::Packet& packet - пакет полученный от клиента
            const sockaddr_in& sender - адрес транспорта и порт клиента

        Возвращаемое значение:
            enum class UdpTransport::ReceiveStatus - перечисление состояний соединения
    */
    UdpTransport::ReceiveStatus receiveFrom(UdpTransport::Packet& packet, sockaddr_in& sender) {

        auto timeout = exchange_timer.remaining();

        if (timeout && timeout->tv_sec == 0 && timeout->tv_usec == 0) {
            resetExchange();
            return UdpTransport::ReceiveStatus::Timeout;
        }

        auto status = UdpTransport::receiveDatagram(server_socket, packet, sender, timeout ? &*timeout : nullptr);

        if (exchange_timer.expired()) {
            UdpTransport::clearPacket(packet);
            resetExchange();
            return UdpTransport::ReceiveStatus::Timeout;
        }

        if (status == UdpTransport::ReceiveStatus::Timeout) {
            if (exchange_timer.active()) resetExchange();
            return status;
        }

        return status;
    }
    
    /*
        Метод, который возвращает exchange_id 

        Возвращаемое значение:
            std::uint32_t exchange_id - id обмена
    */
    std::uint32_t getExchangeId() const {
        return exchange_id;
    }

    /*
        Метод, который очищает информацию об успешно завершённом обмене
    */
    void clearCompletedExchange() noexcept {
        UdpTransport::clearPacket(completed_confirm_packet);
        UdpTransport::clearPacket(completed_confirm_ack_packet);

        completed_client = {};
        completed_cache_expiration = {};
        completed_exchange_valid = false;
    }

    /*
        Метод, который очищает секреты, информацию об успешно завершённом обмене,
        закрывает сокет и прекращает использование библиотеки DLL Winsock 2
    */
    void cleanup() {

        resetExchange();
        clearCompletedExchange();

        if (server_socket != INVALID_SOCKET) {
            closesocket(server_socket);
            server_socket = INVALID_SOCKET;
        }

        if (winsock_initialized) {
            WSACleanup();
            winsock_initialized = false;
        }
    }

    std::uint32_t exchange_id{};

    std::unordered_set<std::uint32_t> exchange_ids;

    std::array<std::uint8_t, 32> client_random{};
    std::array<std::uint8_t, 32> server_random{};
    std::array<std::uint8_t, 32> nonce{};
    std::array<std::uint8_t, 32> secret{};

    UdpTransport::Packet completed_confirm_packet;
    UdpTransport::Packet completed_confirm_ack_packet;

    sockaddr_in completed_client{};
    std::chrono::steady_clock::time_point completed_cache_expiration{};

    bool completed_exchange_valid = false;

    WSADATA wsdt{};
    SOCKET server_socket = INVALID_SOCKET;
    sockaddr_in server{}, client{};

    bool winsock_initialized = false;
    bool client_known = false;

    UdpTransport::ExchangeTimer exchange_timer;
};

/*
    Точка входа в программу
    описывает логику серверного цикла обмена
*/
int main() {

    try {
        
        UDPServer server(8080);

        std::cout << "Server started on port 8080\n";

        while (true) {

            UdpTransport::Packet request;
            sockaddr_in sender{};

            auto status = server.receiveFrom(request, sender);

            if (status != UdpTransport::ReceiveStatus::Received) {
                std::cerr << "Invalid datagram\n";
                UdpTransport::clearPacket(request);
                continue;
            }

            if (server.resendCompletedConfirmAck(request, sender)) {
                std::cout << "Duplicate CONFIRM received, CONFIRM_ACK resent\n";
                UdpTransport::clearPacket(request);
                continue;
            }

            if (!server.acceptInit(request, sender)) {
                std::cerr << "Invalid INIT or exchange_id already used\n";
                UdpTransport::clearPacket(request);
                continue;
            }

            UdpTransport::clearPacket(request);

            std::cout << "INIT received, exchange = " << server.getExchangeId() << '\n';

            auto init_ack = server.buildInitAck();

            server.sendTo(init_ack);

            std::cout << "INIT_ACK sent\n";

            bool completed = false;

            while (!completed) {

                sockaddr_in sender_address{};

                status = server.receiveFrom(request, sender_address);

                if (status == UdpTransport::ReceiveStatus::Timeout) {
                    std::cerr << "Exchange timeout\n";
                    break;
                }

                if (status != UdpTransport::ReceiveStatus::Received) {
                    std::cerr << "Invalid datagram\n";
                    UdpTransport::clearPacket(request);
                    continue;
                }

                if (server.resendCompletedConfirmAck(request, sender_address)) {
                    std::cout << "Duplicate CONFIRM received, CONFIRM_ACK resent\n";
                    UdpTransport::clearPacket(request);
                    continue;
                }

                if (server.isDuplicateInit(request, sender_address)) {

                    server.sendTo(init_ack);

                    std::cout << "Duplicate INIT received, INIT_ACK resent\n";

                    UdpTransport::clearPacket(request);
                    continue;
                }

                if (!server.isSameClient(sender_address)) {
                    std::cerr << "Unexpected client address\n";
                    UdpTransport::clearPacket(request);
                    continue;
                }

                if (!server.verifyConfirm(request)) {
                    std::cerr << "Invalid CONFIRM or HMAC mismatch\n";
                    UdpTransport::clearPacket(request);
                    continue;
                }

                auto confirm_ack = server.buildConfirmAck();

                const auto exchange_id = server.getExchangeId();

                server.rememberCompletedExchange(request, confirm_ack);

                UdpTransport::clearPacket(request);

                server.sendTo(confirm_ack);

                UdpTransport::clearPacket(confirm_ack);
                UdpTransport::clearPacket(init_ack);

                std::cout << "ok exchange=" << exchange_id << ";\n";

                server.resetExchange();

                completed = true;
            }

            UdpTransport::clearPacket(init_ack);

            if (!completed) {
                server.resetExchange();
            }
        }
    }
    catch (const std::exception& exception) {
        std::cerr << "Server error: " << exception.what() << '\n';
        return 1;
    }
}