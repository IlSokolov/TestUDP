#pragma once

#include <winsock2.h>
#include <WS2tcpip.h>

#include "sha256.h"
#include "hmac_sha256.h"
#include "secure_zero.h"

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

namespace Util
{
    constexpr std::uint32_t MAGIC = 0x4B455931;
    constexpr std::uint8_t VERSION = 1;

    constexpr std::size_t HEADER_SIZE = 12;
    constexpr std::size_t RANDOM_SIZE = 32;
    constexpr std::size_t HASH_SIZE = 32;
    constexpr std::size_t MAX_PAYLOAD_SIZE = 2048;

    enum class MessageType : std::uint8_t
    {
        INIT = 1,
        INIT_ACK = 2,
        CONFIRM = 3,
        CONFIRM_ACK = 4
    };

    template<std::size_t N>
    void generateRandomBytes(std::array<std::uint8_t, N>& buffer) {

        std::random_device rd;
        std::uniform_int_distribution<unsigned int> distribution(0, 255);

        for (auto& byte : buffer)
            byte = static_cast<std::uint8_t>(distribution(rd));
    }

    void writeUint32BE(std::uint8_t* buffer, std::uint32_t value);

    std::vector<std::uint8_t> makePacket(MessageType type, std::uint32_t exchange_id, const std::vector<std::uint8_t>& payload);

    std::array<std::uint8_t, HASH_SIZE> calculateSecret(std::uint32_t exchange_id,
        const std::array<std::uint8_t, RANDOM_SIZE>& client_random,
        const std::array<std::uint8_t, RANDOM_SIZE>& server_random, const std::array<std::uint8_t, RANDOM_SIZE>& nonce);

    std::array<std::uint8_t, HASH_SIZE> calculateHmac(MessageType type, std::uint32_t exchange_id,
        const std::array<std::uint8_t, HASH_SIZE>& secret,
        const std::array<std::uint8_t, RANDOM_SIZE>& client_random,
        const std::array<std::uint8_t, RANDOM_SIZE>& server_random, const std::array<std::uint8_t, RANDOM_SIZE>& nonce);

    struct ParsedPacket
    {
        MessageType type{};
        std::uint32_t exchange_id{};
        std::vector<std::uint8_t> payload;
    };

    std::uint32_t readUint32BE(const std::uint8_t* buffer);

    bool parsePacket(const std::vector<std::uint8_t>& packet, ParsedPacket& result);

    bool constantTimeEqual(const std::uint8_t* first, const std::uint8_t* second, std::size_t size);
}