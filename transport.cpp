#include "transport.hpp"

namespace UdpTransport
{

    bool sameEndpoint(const sockaddr_in& first, const sockaddr_in& second) {
        return first.sin_family == second.sin_family && first.sin_addr.s_addr == second.sin_addr.s_addr && first.sin_port == second.sin_port;
    }

    void sendDatagram(SOCKET socket, const Packet& packet, const sockaddr_in& destination) {

        if (socket == INVALID_SOCKET) throw std::runtime_error("Invalid socket");

        if (packet.size() > MAX_PACKET_SIZE) throw std::runtime_error("Packet is too large");

        const char* data = packet.empty() ? "" : reinterpret_cast<const char*>(packet.data());

        const int sent = sendto(socket, data, static_cast<int>(packet.size()), 0, reinterpret_cast<const sockaddr*>(&destination), sizeof(destination));

        if (sent == SOCKET_ERROR) throw std::runtime_error("sendto failed. WSA error: " + std::to_string(WSAGetLastError()));

        if (static_cast<std::size_t>(sent) != packet.size()) throw std::runtime_error("Incomplete UDP datagram send");
    }

    ReceiveStatus receiveDatagram(SOCKET socket, Packet& packet, sockaddr_in& sender, const timeval* timeout) {

        if (socket == INVALID_SOCKET) throw std::runtime_error("Invalid socket");

        if (!packet.empty()) {
            secure_zero(packet.data(), packet.size());
            packet.clear();
        }

        fd_set read_set;

        FD_ZERO(&read_set);
        FD_SET(socket, &read_set);

        const int ready = select(0, &read_set, nullptr, nullptr, timeout);

        if (ready == SOCKET_ERROR) throw std::runtime_error("select failed. WSA error: " + std::to_string(WSAGetLastError()));
        
        if (ready == 0) return ReceiveStatus::Timeout;

        std::array<char, MAX_PACKET_SIZE + 1> buffer{};

        sockaddr_in remote_address{};
        int address_length = sizeof(remote_address);

        const int received = recvfrom(socket, buffer.data(), static_cast<int>(buffer.size()), 0, reinterpret_cast<sockaddr*>(&remote_address), &address_length);

        if (received == SOCKET_ERROR) {

            const int error = WSAGetLastError();

            secure_zero(buffer.data(), buffer.size());

            if (error == WSAEMSGSIZE) return ReceiveStatus::InvalidDatagram;

            if (error == WSAEWOULDBLOCK) return ReceiveStatus::Timeout;

            throw std::runtime_error("recvfrom failed. WSA error: " + std::to_string(error));
        }

        if (static_cast<std::size_t>(received) > MAX_PACKET_SIZE || address_length < static_cast<int>(sizeof(sockaddr_in)) || remote_address.sin_family != AF_INET) {

            secure_zero(buffer.data(), buffer.size());
            return ReceiveStatus::InvalidDatagram;
        }

        sender = remote_address;

        packet.assign(reinterpret_cast<const std::uint8_t*>(buffer.data()), reinterpret_cast<const std::uint8_t*>(buffer.data()) + received);

        secure_zero(buffer.data(), buffer.size());

        return ReceiveStatus::Received;
    }

    void ExchangeTimer::start() {
        deadline = Clock::now() + std::chrono::seconds(5);
    }

    void ExchangeTimer::reset() noexcept {
        deadline.reset();
    }

    bool ExchangeTimer::active() const noexcept {
        return deadline.has_value();
    }

    bool ExchangeTimer::expired() const noexcept {
        return deadline.has_value() && Clock::now() >= deadline.value();
    }

    std::optional<timeval> ExchangeTimer::remaining() const {

        if (!deadline.has_value()) return std::nullopt;

        const auto now = Clock::now();

        if (now >= deadline.value()) return timeval{ 0, 0 };

        const auto duration = deadline.value() - now;

        const auto microseconds = std::chrono::ceil<std::chrono::microseconds>(duration);

        const auto count = microseconds.count();

        timeval timeout{};

        timeout.tv_sec = static_cast<long>(count / 1'000'000);

        timeout.tv_usec = static_cast<long>(count % 1'000'000);

        return timeout;
    }

    void clearPacket(Packet& packet) noexcept {

        if (!packet.empty()) {
            secure_zero(packet.data(), packet.size());

            packet.clear();
        }
    }
}