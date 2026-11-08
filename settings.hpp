//Конфигурация общих объектов

#pragma once

//Импорты

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

// Пространство имён с функциями и структурами для формирования, обработки и проверки UDP-пакетов.
namespace Util
{
    //Значение для идентификации пакета протокола
    constexpr std::uint32_t MAGIC = 0x4B455931;

    //Версия протокола
    constexpr std::uint8_t VERSION = 1;

    //Размер заголовка пакета в байтах
    constexpr std::size_t HEADER_SIZE = 12;

    //Размер случайных данных в байтах
    constexpr std::size_t RANDOM_SIZE = 32;

    //Размер хеша в байтах
    constexpr std::size_t HASH_SIZE = 32;

    //Максимальный размер полезной нагрузки пакета в байтах
    constexpr std::size_t MAX_PAYLOAD_SIZE = 2048;

    /*
        Тип сообщения, передаваемого между клиентом и сервером.
    */
    enum class MessageType : std::uint8_t
    {
        INIT = 1,       //Начало обмена
        INIT_ACK = 2,   //Подтверждение начала обмена
        CONFIRM = 3,    //Подтверждение обмена
        CONFIRM_ACK = 4 //Подтверждение получения сообщения CONFIRM
    };

    /*
        Заполняет массив случайными байтами.

        Принимаемые аргументы:
            std::array<std::uint8_t, N>& buffer - буффер для случайных байтов.
    */
    template<std::size_t N>
    void generateRandomBytes(std::array<std::uint8_t, N>& buffer) {

        std::random_device rd;
        std::uniform_int_distribution<unsigned int> distribution(0, 255);

        for (auto& byte : buffer)
            byte = static_cast<std::uint8_t>(distribution(rd));
    }

    /*
        Записывает 32-битное число в буфер в формате Big Endian.

        Принимаемые аргументы:
            std::uint8_t* buffer - указатель на буфер для записи;
            std::uint32_t value - число, которое необходимо записать.
    */
    void writeUint32BE(std::uint8_t* buffer, std::uint32_t value);

    /*
        Формирует пакет сообщения с заголовком и полезной нагрузкой.

        Принимаемые аргументы:
            MessageType type - тип сообщения;
            std::uint32_t exchange_id - идентификатор обмена;
            const std::vector<std::uint8_t>& payload - полезная нагрузка пакета.

        Возвращаемое значение:
            std::vector<std::uint8_t> - Сформированный UDP-пакет в виде последовательности байтов.
    */
    std::vector<std::uint8_t> makePacket(MessageType type, std::uint32_t exchange_id, const std::vector<std::uint8_t>& payload);
    
    /*
        Вычисляет секретное значение на основе идентификатора обмена,
        случайных данных клиента и сервера, а также дополнительного случайного значения.

        Принимаемые аргументы:
            std::uint32_t exchange_id - идентификатор обмена;
            const std::array<std::uint8_t, RANDOM_SIZE>& client_random - случайные данные клиента;
            const std::array<std::uint8_t, RANDOM_SIZE>& server_random - случайные данные сервера;
            const std::array<std::uint8_t, RANDOM_SIZE>& nonce - дополнительное случайное значение.

        Возвращаемое значение:
            std::array<std::uint8_t, HASH_SIZE> - Массив байтов с вычисленным секретным значением.
    */
    std::array<std::uint8_t, HASH_SIZE> calculateSecret(std::uint32_t exchange_id,
        const std::array<std::uint8_t, RANDOM_SIZE>& client_random,
        const std::array<std::uint8_t, RANDOM_SIZE>& server_random, const std::array<std::uint8_t, RANDOM_SIZE>& nonce);

    /*
        Вычисляет HMAC для сообщения.

        Принимаемые аргументы:
            MessageType type - тип сообщения;
            std::uint32_t exchange_id - идентификатор обмена;
            const std::array<std::uint8_t, HASH_SIZE>& secret - секретное значение;
            const std::array<std::uint8_t, RANDOM_SIZE>& client_random - случайные данные клиента;
            const std::array<std::uint8_t, RANDOM_SIZE>& server_random - случайные данные сервера;
            const std::array<std::uint8_t, RANDOM_SIZE>& nonce - дополнительное случайное значение.

        Возвращаемое значение:
            std::array<std::uint8_t, HASH_SIZE> Массив байтов с вычисленным HMAC.
    */
    std::array<std::uint8_t, HASH_SIZE> calculateHmac(MessageType type, std::uint32_t exchange_id,
        const std::array<std::uint8_t, HASH_SIZE>& secret,
        const std::array<std::uint8_t, RANDOM_SIZE>& client_random,
        const std::array<std::uint8_t, RANDOM_SIZE>& server_random, const std::array<std::uint8_t, RANDOM_SIZE>& nonce);

    /*
        Структура для хранения данных, извлечённых из UDP-пакета.
    */
    struct ParsedPacket
    {
        MessageType type{};                 //Тип сообщения
        std::uint32_t exchange_id{};        //Идентификатор обмена
        std::vector<std::uint8_t> payload;  //Полезная нагрузка пакета
    };

    /*
        Читает 32-битное число из буфера в формате Big Endian.

        Принимаемые аргументы:
            const std::uint8_t* buffer - указатель на буфер с данными.

        Возвращаемое значение:
            std::uint32_t - Прочитанное 32-битное число.
    */
    std::uint32_t readUint32BE(const std::uint8_t* buffer);

    /*
        Разбирает UDP-пакет и извлекает из него данные.

        Принимаемые аргументы:
            const std::vector<std::uint8_t>& packet - пакет для разбора;
            ParsedPacket& result - структура для записи извлечённых данных.

        Возвращаемое значение:
            bool - true, если пакет успешно разобран, иначе false.
    */
    bool parsePacket(const std::vector<std::uint8_t>& packet, ParsedPacket& result);

    /*
        Сравнивает два участка памяти за постоянное время.

        Принимаемые аргументы:
            const std::uint8_t* first - указатель на первый участок памяти;
            const std::uint8_t* second - указатель на второй участок памяти;
            std::size_t size - количество байтов для сравнения.

        Возвращаемое значение:
            bool - true, если данные совпадают, иначе false.
    */
    bool constantTimeEqual(const std::uint8_t* first, const std::uint8_t* second, std::size_t size);
}