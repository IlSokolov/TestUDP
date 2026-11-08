//Функция обнуления на C

#ifndef SECURE_ZERO_H
#define SECURE_ZERO_H

#include <stddef.h>

//Подключение функции на С к проекту С++
#ifdef __cplusplus
extern "C" {
#endif

    /*
        Обнуляет указанный участок памяти.

        Принимаемые аргументы:
            void* ptr - указатель на область памяти;
            size_t size - размер области памяти в байтах.
    */
    void secure_zero(void* ptr, size_t size);

#ifdef __cplusplus
}
#endif

#endif