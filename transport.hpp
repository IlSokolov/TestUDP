#pragma once

#include <winsock2.h>
#include <WS2tcpip.h>

#include "sha256.h"
#include "hmac_sha256.h"
#include "secure_zero.h"
#include "settings.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <chrono>
#include <iterator>
#include <optional>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace UdpTransport
{
    using Packet = std::vector<std::uint8_t>;

    constexpr std::size_t MAX_PACKET_SIZE = Util::HEADER_SIZE + Util::MAX_PAYLOAD_SIZE;

    enum class ReceiveStatus
    {
        Received,
        Timeout,
        InvalidDatagram,
        UnexpectedSender
    };

    bool sameEndpoint(const sockaddr_in& first, const sockaddr_in& second);

    void sendDatagram(SOCKET socket, const Packet& packet, const sockaddr_in& destination);

    ReceiveStatus receiveDatagram(SOCKET socket, Packet& packet, sockaddr_in& sender, const timeval* timeout = nullptr);

    class ExchangeTimer
    {
    public:
        using Clock = std::chrono::steady_clock;

        void start();

        void reset() noexcept;

        bool active() const noexcept;

        bool expired() const noexcept;

        std::optional<timeval> remaining() const;

    private:
        std::optional<Clock::time_point> deadline;
    };

    void clearPacket(Packet& packet) noexcept;
}