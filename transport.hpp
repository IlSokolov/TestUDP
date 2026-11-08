//Конфигурация обмена

#pragma once

//Импорты

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

//Пространство имен, содержащее функции и классы для UDP-транспорта
namespace UdpTransport
{
    /*
        Алиас для хранения UDP-пакета

        std::uint8_t - тип одного байта пакета
    */
    using Packet = std::vector<std::uint8_t>;

    /*
        Максимальный размер UDP-пакета с учетом заголовка и полезных данных
    */
    constexpr std::size_t MAX_PACKET_SIZE = Util::HEADER_SIZE + Util::MAX_PAYLOAD_SIZE;

    /*
        Перечисление, которое определяет результат получения UDP-пакета
    */
    enum class ReceiveStatus
    {
        Received,           //Пакет успешно получен
        Timeout,            //Время ожидания получения пакета истекло
        InvalidDatagram,    //Полученная дейтаграмма некорректна
        UnexpectedSender    //Пакет получен от неожиданного отправителя
    };

    /*
        Функция, которая сравнивает адреса двух сетевых узлов

        Принимаемые аргументы:
            const sockaddr_in& first - первый адрес
            const sockaddr_in& second - второй адрес

        Возвращаемое значение:
            bool - true, если адреса совпадают, иначе false
    */
    bool sameEndpoint(const sockaddr_in& first, const sockaddr_in& second);

    /*
        Функция, которая отправляет UDP-дейтаграмму указанному получателю

        Принимаемые аргументы:
            SOCKET socket - дескриптор сокета
            const Packet& packet - отправляемый UDP-пакет
            const sockaddr_in& destination - адрес транспорта и порт получателя
    */
    void sendDatagram(SOCKET socket, const Packet& packet, const sockaddr_in& destination);

    /*
        Функция, которая получает UDP-дейтаграмму и сохраняет адрес отправителя

        Принимаемые аргументы:
            SOCKET socket - дескриптор сокета
            Packet& packet - переменная для сохранения полученного пакета
            sockaddr_in& sender - адрес транспорта и порт отправителя
            const timeval* timeout - максимальное время ожидания получения пакета

        Возвращаемое значение:
            ReceiveStatus - результат получения UDP-пакета
    */
    ReceiveStatus receiveDatagram(SOCKET socket, Packet& packet, sockaddr_in& sender, const timeval* timeout = nullptr);

    /*
        Класс, который управляет временем жизни цикла обмена
        и позволяет отслеживать оставшееся время ожидания
    */
    class ExchangeTimer
    {
    public:
        /*
            Алиас для типа часов с монотонным временем,
            используемых для измерения продолжительности обмена
        */
        using Clock = std::chrono::steady_clock;

        /*
            Метод, который запускает таймер и устанавливает время окончания ожидания
        */
        void start();

        /*
            Метод, который сбрасывает таймер и удаляет установленный срок окончания ожидания
        */
        void reset() noexcept;

        /*
            Метод, который проверяет активность таймера

            Возвращаемое значение:
                bool - true, если таймер запущен, иначе false
        */
        bool active() const noexcept;

        /*
            Метод, который проверяет, истекло ли установленное время ожидания

            Возвращаемое значение:
                bool - true, если время ожидания истекло, иначе false
        */
        bool expired() const noexcept;

        /*
            Метод, который определяет оставшееся время до окончания ожидания

            Возвращаемое значение:
                std::optional<timeval> - оставшееся время ожидания
                или std::nullopt, если таймер не активен
        */
        std::optional<timeval> remaining() const;

    private:
        //Время окончания ожидания текущего цикла обмена
        std::optional<Clock::time_point> deadline;
    };

    /*
        Функция, которая очищает содержимое UDP-пакета

        Принимаемые аргументы:
            Packet& packet - пакет, содержимое которого необходимо очистить
    */
    void clearPacket(Packet& packet) noexcept;
}