#include "settings.hpp"

namespace Util
{

    void writeUint32BE(std::uint8_t* buffer, std::uint32_t value) {

        buffer[0] = static_cast<std::uint8_t>(value >> 24);
        buffer[1] = static_cast<std::uint8_t>(value >> 16);
        buffer[2] = static_cast<std::uint8_t>(value >> 8);
        buffer[3] = static_cast<std::uint8_t>(value);
    }

    std::vector<std::uint8_t> makePacket(MessageType type, std::uint32_t exchange_id, const std::vector<std::uint8_t>& payload) {

        if (payload.size() > MAX_PAYLOAD_SIZE) throw std::runtime_error("Payload is too large");

        std::vector<std::uint8_t> packet(HEADER_SIZE + payload.size());

        writeUint32BE(packet.data(), MAGIC);

        packet[4] = VERSION;
        packet[5] = static_cast<std::uint8_t>(type);
        packet[6] = 0;
        packet[7] = 0;

        writeUint32BE(packet.data() + 8, exchange_id);

        std::copy(payload.begin(), payload.end(), packet.begin() + HEADER_SIZE);

        return packet;
    }

    std::array<std::uint8_t, HASH_SIZE> calculateSecret(std::uint32_t exchange_id,
        const std::array<std::uint8_t, RANDOM_SIZE>& client_random,
        const std::array<std::uint8_t, RANDOM_SIZE>& server_random, const std::array<std::uint8_t, RANDOM_SIZE>& nonce) {

        std::array<std::uint8_t, 100> input{};

        std::size_t offset = 0;

        std::copy(client_random.begin(), client_random.end(), input.begin() + offset);

        offset += RANDOM_SIZE;

        std::copy(server_random.begin(), server_random.end(), input.begin() + offset);

        offset += RANDOM_SIZE;

        std::copy(nonce.begin(), nonce.end(), input.begin() + offset);

        offset += RANDOM_SIZE;

        writeUint32BE(input.data() + offset, exchange_id);

        std::array<std::uint8_t, HASH_SIZE> secret{};

        SHA256_HASH digest{};

        Sha256Calculate(input.data(), static_cast<std::uint32_t>(input.size()), &digest);

        std::copy(std::begin(digest.bytes), std::end(digest.bytes), secret.begin());

        secure_zero(input.data(), input.size());
        secure_zero(&digest, sizeof(digest));

        return secret;
    }

    std::array<std::uint8_t, HASH_SIZE> calculateHmac(MessageType type, std::uint32_t exchange_id, 
        const std::array<std::uint8_t, HASH_SIZE>& secret,
        const std::array<std::uint8_t, RANDOM_SIZE>& client_random,
        const std::array<std::uint8_t, RANDOM_SIZE>& server_random, const std::array<std::uint8_t, RANDOM_SIZE>& nonce) {

        std::array<std::uint8_t, 101> input{};

        std::size_t offset = 0;

        input[offset++] = static_cast<std::uint8_t>(type);

        writeUint32BE(input.data() + offset, exchange_id);
        offset += 4;

        std::copy(client_random.begin(), client_random.end(), input.begin() + offset);

        offset += RANDOM_SIZE;

        std::copy(server_random.begin(), server_random.end(), input.begin() + offset);

        offset += RANDOM_SIZE;

        std::copy(nonce.begin(), nonce.end(), input.begin() + offset);

        std::array<std::uint8_t, HASH_SIZE> result{};

        const auto written = hmac_sha256(secret.data(), secret.size(), input.data(), input.size(), result.data(), result.size());

        secure_zero(input.data(), input.size());

        if (written != result.size()) throw std::runtime_error("HMAC-SHA256 calculation failed");

        return result;
    }

    std::uint32_t readUint32BE(const std::uint8_t* buffer) {
        return (static_cast<std::uint32_t>(buffer[0]) << 24) |
               (static_cast<std::uint32_t>(buffer[1]) << 16) |
               (static_cast<std::uint32_t>(buffer[2]) << 8) |
                static_cast<std::uint32_t>(buffer[3]);
    }

    bool parsePacket(const std::vector<std::uint8_t>& packet, ParsedPacket& result) {

        if (packet.size() < HEADER_SIZE || packet.size() > HEADER_SIZE + MAX_PAYLOAD_SIZE) return false;
        

        if (readUint32BE(packet.data()) != MAGIC) return false;

        if (packet[4] != VERSION) return false;

        if (packet[6] != 0 || packet[7] != 0) return false;

        const auto type = static_cast<MessageType>(packet[5]);

        std::size_t expected_payload_size = 0;

        switch (type)
        {
        case MessageType::INIT:

        case MessageType::CONFIRM:

        case MessageType::CONFIRM_ACK:
            expected_payload_size = 32; break;

        case MessageType::INIT_ACK:
            expected_payload_size = 64; break;

        default: return false;
        }

        const std::size_t payload_size = packet.size() - HEADER_SIZE;

        if (payload_size != expected_payload_size) return false;

        if (!result.payload.empty()) {

            secure_zero(result.payload.data(), result.payload.size());

            result.payload.clear();
        }

        result.type = type;
        result.exchange_id = readUint32BE(packet.data() + 8);

        result.payload.assign(packet.begin() + HEADER_SIZE, packet.end());

        return true;
    }

    bool constantTimeEqual(const std::uint8_t* first, const std::uint8_t* second, std::size_t size) {
        std::uint8_t difference = 0;

        for (std::size_t i = 0; i < size; ++i)
            difference |= first[i] ^ second[i];

        return difference == 0;
    }
}
