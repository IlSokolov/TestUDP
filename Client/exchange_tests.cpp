#include "../settings.hpp"
#include <array>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")

namespace
{
    constexpr std::size_t TEST_HEADER_SIZE = 12;
    constexpr std::uint32_t TEST_EXCHANGE_ID = 0x01020304;

    void expect(bool condition, const std::string& message) {
        if (!condition) throw std::runtime_error(message);
    }

    std::vector<std::uint8_t> makePacket(std::uint8_t type, std::uint32_t exchange_id, std::size_t payload_size) {
        
        std::vector<std::uint8_t> packet(TEST_HEADER_SIZE + payload_size, 0);

        packet[0] = 0x4B;
        packet[1] = 0x45;
        packet[2] = 0x59;
        packet[3] = 0x31;

        packet[4] = 1;
        packet[5] = type;
        packet[6] = 0;
        packet[7] = 0;

        packet[8] = static_cast<std::uint8_t>(exchange_id >> 24);
        packet[9] = static_cast<std::uint8_t>(exchange_id >> 16);
        packet[10] = static_cast<std::uint8_t>(exchange_id >> 8);
        packet[11] = static_cast<std::uint8_t>(exchange_id);

        for (std::size_t i = 0; i < payload_size; ++i)
            packet[TEST_HEADER_SIZE + i] = static_cast<std::uint8_t>(i);

        return packet;
    }

    template<std::size_t N>
    std::array<std::uint8_t, N> makeSequence(std::uint8_t start) {
        std::array<std::uint8_t, N> result{};

        for (std::size_t i = 0; i < N; ++i) result[i] = static_cast<std::uint8_t>(start + i);

        return result;
    }

    int hexDigit(char c) {

        if (c >= '0' && c <= '9') return c - '0';

        if (c >= 'a' && c <= 'f') return c - 'a' + 10;

        if (c >= 'A' && c <= 'F') return c - 'A' + 10;

        throw std::runtime_error("Invalid hexadecimal character");
    }

    template<std::size_t N>
    void expectHex(const std::array<std::uint8_t, N>& actual, const std::string& expected) {
       
        expect(expected.size() == N * 2, "Invalid expected hash length");

        for (std::size_t i = 0; i < N; ++i) {
            
            const auto expected_byte = static_cast<std::uint8_t>((hexDigit(expected[i * 2]) << 4) | hexDigit(expected[i * 2 + 1]));

            expect(actual[i] == expected_byte, "Calculated value does not match expected value");
        }
    }

    //Корректный разбор INIT
    void testParseValidInit() {
        
        const auto packet = makePacket(static_cast<std::uint8_t>(Util::MessageType::INIT), TEST_EXCHANGE_ID, 32); 

        Util::ParsedPacket result{};

        expect(parsePacket(packet, result), "Valid INIT packet was rejected");

        expect(result.type == Util::MessageType::INIT, "Incorrect message type");

        expect(result.exchange_id == TEST_EXCHANGE_ID, "Incorrect exchange_id");

        expect(result.payload.size() == 32, "Incorrect payload size");

        for (std::size_t i = 0; i < result.payload.size(); ++i)
            expect(result.payload[i] == static_cast<std::uint8_t>(i), "Incorrect payload data");
        
    }

    //Корректный разбор INIT_ACK
    void testParseValidInitAck() {

        const auto packet = makePacket(static_cast<std::uint8_t>(Util::MessageType::INIT_ACK), TEST_EXCHANGE_ID, 64);

        Util::ParsedPacket result{};

        expect(parsePacket(packet, result), "Valid INIT_ACK packet was rejected");

        expect(result.type == Util::MessageType::INIT_ACK, "Incorrect message type");

        expect(result.payload.size() == 64, "Incorrect INIT_ACK payload size");
    }

    //Обрезанный заголовок
    void testParseTruncatedHeader() {

        const std::vector<std::uint8_t> packet( TEST_HEADER_SIZE - 1, 0);

        Util::ParsedPacket result{};

        expect(!parsePacket(packet, result), "Packet with truncated header was accepted");
    }

    //Обрезанный payload
    void testParseTruncatedPayload() {

        const auto packet = makePacket(static_cast<std::uint8_t>(Util::MessageType::INIT), TEST_EXCHANGE_ID, 31);

        Util::ParsedPacket result{};

        expect(!parsePacket(packet, result), "Packet with truncated payload was accepted");
    }

    //Неверный magic
    void testParseInvalidMagic() {

        auto packet = makePacket(static_cast<std::uint8_t>(Util::MessageType::INIT), TEST_EXCHANGE_ID, 32);

        packet[0] ^= 0xFF;

        Util::ParsedPacket result{};

        expect(!parsePacket(packet, result), "Packet with invalid magic was accepted");
    }

    //Неизвестный тип сообщения
    void testParseUnknownType() {
       
        const auto packet = makePacket(0xFF, TEST_EXCHANGE_ID, 32);

        Util::ParsedPacket result{};

        expect(!parsePacket(packet, result), "Packet with unknown type was accepted");
    }

    //Неверная версия протокола
    void testParseInvalidVersion() {
        
        auto packet = makePacket(static_cast<std::uint8_t>(Util::MessageType::INIT), TEST_EXCHANGE_ID, 32);

        packet[4] = 2;

        Util::ParsedPacket result{};

        expect(!parsePacket(packet, result), "Packet with invalid version was accepted");
    }

    //Ненулевые flags
    void testParseInvalidFlags() {
       
        auto packet = makePacket(static_cast<std::uint8_t>(Util::MessageType::INIT), TEST_EXCHANGE_ID, 32);

        packet[6] = 1;

        Util::ParsedPacket result{};

        expect(!parsePacket(packet, result), "Packet with non-zero flags was accepted");
    }

    //Некорректный пакет не должен изменять результат разбора
    void testParseFailurePreservesResult() {
       
        Util::ParsedPacket result{};

        result.type = Util::MessageType::CONFIRM;
        result.exchange_id = 12345;
        result.payload = { 0xAA, 0xBB, 0xCC };

        const auto original_payload = result.payload;

        const std::vector<std::uint8_t> packet(TEST_HEADER_SIZE - 1, 0);

        expect(!parsePacket(packet, result), "Invalid packet was accepted");

        expect(result.type == Util::MessageType::CONFIRM, "Result type was unexpectedly modified");

        expect(result.exchange_id == 12345, "Result exchange_id was unexpectedly modified");

        expect(result.payload == original_payload, "Result payload was unexpectedly modified");
    }

    //Слишком большой пакет
    void testParseOversizedPacket() {
        
        const auto packet = makePacket(static_cast<std::uint8_t>(Util::MessageType::INIT), TEST_EXCHANGE_ID, Util::MAX_PAYLOAD_SIZE + 1);

        Util::ParsedPacket result{};

        expect(!parsePacket(packet, result), "Oversized packet was accepted");
    }

    //Проверка SHA-256 общего секрета
    void testCalculateSecretKnownVector() {
        
        const auto client_random = makeSequence<Util::RANDOM_SIZE>(0);
        const auto server_random = makeSequence<Util::RANDOM_SIZE>(32);
        const auto nonce = makeSequence<Util::RANDOM_SIZE>(64);

        const auto secret = Util::calculateSecret(TEST_EXCHANGE_ID, client_random, server_random, nonce);

        expectHex(secret, "c6996db273ef549460d095d4d1645e292235cdddbac49c5c5382ab33a9ea141d");
    }

    //Секрет зависит от exchange_id
    void testCalculateSecretDependsOnExchangeId() {
        
        const auto client_random = makeSequence<Util::RANDOM_SIZE>(0);
        const auto server_random = makeSequence<Util::RANDOM_SIZE>(32);
        const auto nonce = makeSequence<Util::RANDOM_SIZE>(64);

        const auto first_secret = Util::calculateSecret(TEST_EXCHANGE_ID, client_random, server_random, nonce);

        const auto second_secret = Util::calculateSecret(TEST_EXCHANGE_ID + 1, client_random, server_random, nonce);

        expect(first_secret != second_secret, "Secret did not change after exchange_id changed");
    }

    //Проверка HMAC для CONFIRM
    void testCalculateConfirmHmacKnownVector() {
        
        const auto client_random = makeSequence<Util::RANDOM_SIZE>(0);
        const auto server_random = makeSequence<Util::RANDOM_SIZE>(32);
        const auto nonce = makeSequence<Util::RANDOM_SIZE>(64);

        const auto secret = Util::calculateSecret(TEST_EXCHANGE_ID, client_random, server_random, nonce);

        const auto mac = calculateHmac(Util::MessageType::CONFIRM, TEST_EXCHANGE_ID, secret, client_random, server_random, nonce);

        expectHex(mac, "8c4c39a059b9d74bf5488afcf3790dbf96053c3efe6ad9d8a9ffa4de8eb94d55");
    }

    //Проверка HMAC для CONFIRM_ACK
    void testCalculateConfirmAckHmacKnownVector() {
        
        const auto client_random = makeSequence<Util::RANDOM_SIZE>(0);
        const auto server_random = makeSequence<Util::RANDOM_SIZE>(32);
        const auto nonce = makeSequence<Util::RANDOM_SIZE>(64);

        const auto secret = Util::calculateSecret(TEST_EXCHANGE_ID, client_random, server_random, nonce);

        const auto mac = Util::calculateHmac(Util::MessageType::CONFIRM_ACK, TEST_EXCHANGE_ID, secret, client_random, server_random, nonce);

        expectHex(mac, "d12d21b80e50cc04be7f7baebd6f67b0e5c2902e92e5db699a6b443e02ce8220");
    }

    //HMAC зависит от типа сообщения
    void testCalculateHmacDependsOnMessageType() {
        
        const auto client_random = makeSequence<Util::RANDOM_SIZE>(0);
        const auto server_random = makeSequence<Util::RANDOM_SIZE>(32);
        const auto nonce = makeSequence<Util::RANDOM_SIZE>(64);

        const auto secret = Util::calculateSecret(TEST_EXCHANGE_ID, client_random, server_random, nonce);

        const auto confirm_mac = Util::calculateHmac(Util::MessageType::CONFIRM, TEST_EXCHANGE_ID, secret, client_random, server_random, nonce);

        const auto ack_mac = Util::calculateHmac(Util::MessageType::CONFIRM_ACK, TEST_EXCHANGE_ID, secret, client_random, server_random, nonce);

        expect(confirm_mac != ack_mac, "HMAC did not change after message type changed");
    }

    //HMAC зависит от входных данных
    void testCalculateHmacDependsOnNonce() {
       
        const auto client_random = makeSequence<Util::RANDOM_SIZE>(0);
        const auto server_random = makeSequence<Util::RANDOM_SIZE>(32);
        const auto nonce = makeSequence<Util::RANDOM_SIZE>(64);

        auto modified_nonce = nonce;
        modified_nonce[0] ^= 0x01;

        const auto secret = Util::calculateSecret(TEST_EXCHANGE_ID, client_random, server_random, nonce);

        const auto original_mac = Util::calculateHmac(Util::MessageType::CONFIRM, TEST_EXCHANGE_ID, secret, client_random, server_random, nonce);

        const auto modified_mac = Util::calculateHmac(Util::MessageType::CONFIRM, TEST_EXCHANGE_ID, secret, client_random, server_random, modified_nonce);

        expect(original_mac != modified_mac, "HMAC did not change after nonce changed");
    }
}

int main()
{
    struct TestCase
    {
        const char* name;
        void (*function)();
    };

    const TestCase tests[] = {
        { "Parse valid INIT", testParseValidInit },
        { "Parse valid INIT_ACK", testParseValidInitAck },
        { "Parse truncated header", testParseTruncatedHeader },
        { "Parse truncated payload", testParseTruncatedPayload },
        { "Parse invalid magic", testParseInvalidMagic },
        { "Parse unknown type", testParseUnknownType },
        { "Parse invalid version", testParseInvalidVersion },
        { "Parse invalid flags", testParseInvalidFlags },
        { "Parse failure preserves result", testParseFailurePreservesResult },
        { "Parse oversized packet", testParseOversizedPacket },
        { "Calculate secret known vector", testCalculateSecretKnownVector },
        { "Secret depends on exchange_id", testCalculateSecretDependsOnExchangeId },
        { "Calculate CONFIRM HMAC known vector", testCalculateConfirmHmacKnownVector },
        { "Calculate CONFIRM_ACK HMAC known vector", testCalculateConfirmAckHmacKnownVector },
        { "HMAC depends on message type", testCalculateHmacDependsOnMessageType },
        { "HMAC depends on nonce", testCalculateHmacDependsOnNonce }
    };

    int failed = 0;

    for (const auto& test : tests) {

        try {
            test.function();
            std::cout << "[PASS] " << test.name << '\n';
        }
        catch (const std::exception& exception) {
            ++failed;
            std::cout << "[FAIL] " << test.name << ": " << exception.what() << '\n';
        }
    }

    const int passed = static_cast<int>(sizeof(tests) / sizeof(tests[0])) - failed;

    std::cout << "\nResults: " << passed << " passed, " << failed << " failed\n";

    return failed == 0 ? 0 : 1;
}
