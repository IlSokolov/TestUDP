#include <winsock2.h>
#include <WS2tcpip.h>
#include "../secure_zero.h"
#include "../settings.hpp"
#include "../transport.hpp"

#include <mswsock.h>
#include <cstdint>
#include <array>
#include <vector>
#include <chrono>
#include <iostream>
#include <optional>

#pragma comment(lib, "Ws2_32.lib")

class UDPClient
{
public:
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

    ~UDPClient() {
        cleanup();
    }

    UDPClient(const UDPClient&) = delete;
    UDPClient& operator=(const UDPClient&) = delete;

    void generateRandom() {

        Util::generateRandomBytes(client_random);
        
        exchange_id = 0;

        std::array<std::uint8_t, 4> id_bytes{};
        Util::generateRandomBytes(id_bytes);

        exchange_id = (static_cast<std::uint32_t>(id_bytes[0]) << 24) |
                      (static_cast<std::uint32_t>(id_bytes[1]) << 16) |
                      (static_cast<std::uint32_t>(id_bytes[2]) << 8) |
                       static_cast<std::uint32_t>(id_bytes[3]);
    }

    std::vector<std::uint8_t> buildInit() {

        std::vector<std::uint8_t> payload(client_random.begin(), client_random.end());

        return Util::makePacket(Util::MessageType::INIT, exchange_id, payload);
    }

    void deriveSecret() {
        secret = Util::calculateSecret(exchange_id, client_random, server_random, nonce);
    }

    std::vector<std::uint8_t> buildConfirm() {
        auto hmac = Util::calculateHmac(Util::MessageType::CONFIRM, exchange_id, secret, client_random, server_random, nonce);

        std::vector<std::uint8_t> payload(hmac.begin(), hmac.end());

        return Util::makePacket( Util::MessageType::CONFIRM, exchange_id, payload);
    }

    bool sendTo(const UdpTransport::Packet& packet) const{
        UdpTransport::sendDatagram(client_socket, packet, server);
        return true;
    }

    void startExchangeTimeout() {
        exchange_timer.start();
    }

    void resetExchange() noexcept{

        secure_zero(client_random.data(), client_random.size());
        secure_zero(server_random.data(), server_random.size());
        secure_zero(nonce.data(), nonce.size());
        secure_zero(secret.data(), secret.size());

        exchange_id = 0;

        exchange_timer.reset();
    }

    void sendTo(const UdpTransport::Packet& packet) {

        if (exchange_timer.expired()) {
            resetExchange();
            throw std::runtime_error("Exchange timed out");
        }

        UdpTransport::sendDatagram( client_socket, packet, server);
    }

    bool acceptInitAck(const std::vector<std::uint8_t>& packet) {

        Util::ParsedPacket parsed;

        if (!Util::parsePacket(packet, parsed)) return false;

        if (parsed.type != Util::MessageType::INIT_ACK || parsed.exchange_id != exchange_id) return false;
        
        std::copy_n( parsed.payload.begin(), 32, server_random.begin());

        std::copy_n( parsed.payload.begin() + 32, 32, nonce.begin());

        deriveSecret();

        return true;
    }

    bool verifyConfirmAck(const std::vector<std::uint8_t>& packet) {

        Util::ParsedPacket parsed;

        if (!Util::parsePacket(packet, parsed)) return false;

        if (parsed.type != Util::MessageType::CONFIRM_ACK || parsed.exchange_id != exchange_id) return false;
        
        const auto expected_hmac = Util::calculateHmac(Util::MessageType::CONFIRM_ACK, exchange_id, secret, client_random, server_random, nonce);

        return Util::constantTimeEqual( expected_hmac.data(), parsed.payload.data(), expected_hmac.size());
    }

    UdpTransport::ReceiveStatus receiveFrom(UdpTransport::Packet& packet) {

        auto timeout = exchange_timer.remaining();

        if (timeout && timeout->tv_sec == 0 && timeout->tv_usec == 0) {
            resetExchange();
            return UdpTransport::ReceiveStatus::Timeout;
        }

        sockaddr_in sender{};

        auto status = UdpTransport::receiveDatagram( client_socket, packet, sender, timeout ? &*timeout : nullptr);

        if (exchange_timer.expired()) {

            UdpTransport::clearPacket(packet);
            resetExchange();

            return UdpTransport::ReceiveStatus::Timeout;
        }

        if (status == UdpTransport::ReceiveStatus::Timeout) {
            if (exchange_timer.active()) resetExchange();
            return status;
        }

        if (status != UdpTransport::ReceiveStatus::Received) return status;

        if (!UdpTransport::sameEndpoint(sender, server)) {
            UdpTransport::clearPacket(packet);
            return UdpTransport::ReceiveStatus::UnexpectedSender;
        }

        return status;
    }

    const std::array<std::uint8_t, 32>& getClientRandom() const{
        return client_random;
    }

    const std::array<std::uint8_t, 32>& getServerRandom() const{
        return server_random;
    }

    const std::array<std::uint8_t, 32>& getNonce() const{
        return nonce;
    }

    std::uint32_t getExchangeId() const{
        return exchange_id;
    }

    void cleanup() {
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

int main() {

    try {

        UDPClient client("127.0.0.1", 8080);

        client.generateRandom();

        auto init_packet = client.buildInit();

        client.startExchangeTimeout();

        client.sendTo(init_packet);
        UdpTransport::clearPacket(init_packet);

        std::cout << "INIT sent, exchange = " << client.getExchangeId() << '\n';

        UdpTransport::Packet response;

        while (true) {

            auto status = client.receiveFrom(response);

            if (status == UdpTransport::ReceiveStatus::Timeout) {
                std::cerr << "Exchange timeout\n";
                return 1;
            }

            if (status != UdpTransport::ReceiveStatus::Received) {
                std::cerr << "Invalid datagram\n";
                continue;
            }

            if (!client.acceptInitAck(response)) {
                std::cerr << "Invalid INIT_ACK\n";
                UdpTransport::clearPacket(response);
                continue;
            }

            UdpTransport::clearPacket(response);
            break;
        }

        std::cout << "INIT_ACK received\n";

        auto confirm_packet = client.buildConfirm();

        client.sendTo(confirm_packet);
        UdpTransport::clearPacket(confirm_packet);

        std::cout << "CONFIRM sent\n";

        while (true) {

            auto status = client.receiveFrom(response);

            if (status == UdpTransport::ReceiveStatus::Timeout) {
                std::cerr << "Exchange timeout\n";
                return 1;
            }

            if (status != UdpTransport::ReceiveStatus::Received) {
                std::cerr << "Invalid datagram\n";
                continue;
            }

            if (!client.verifyConfirmAck(response)) {
                std::cerr << "Invalid CONFIRM_ACK\n";
                UdpTransport::clearPacket(response);
                continue;
            }

            UdpTransport::clearPacket(response);

            const auto exchange_id = client.getExchangeId();

            std::cout << "ok exchange=" << exchange_id << ";\n";

            client.resetExchange();

            return 0;
        }
    }
    catch (const std::exception& exception) {
        std::cerr << "Client error: "<< exception.what() << '\n';
        return 1;
    }
}