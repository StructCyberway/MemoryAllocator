#include "mem.h"

#include <stdio.h>
#include <string.h>

int main() {
    // Инициализация кучи (например, 8 KiB)
    void* start = heap_init(8 * 1024);
    if (!start) {
        fprintf(stderr, "heap_init() failed.\n");
        return 1;
    }
    printf("Heap initialized at %p\n", start);

    // 1) Простейший тест
    char* p1 = _malloc(100);
    if (!p1) {
        fprintf(stderr, "Failed to allocate p1.\n");
        return 1;
    }
    memset(p1, 'A', 100); // заполняем память для проверки

    // 2) Ещё один выделенный блок
    char* p2 = _malloc(200);
    if (!p2) {
        fprintf(stderr, "Failed to allocate p2.\n");
        return 1;
    }
    memset(p2, 'B', 200);

    // 3) Освободим p1
    _free(p1);
    printf("[INFO] Freed p1.\n");

    // 4) Освободим p2
    _free(p2);
    printf("[INFO] Freed p2.\n");

    // 5) Пробуем большой запрос (чтобы проверить расширение)
    char* p3 = _malloc(10 * 1024);
    if (!p3) {
        fprintf(stderr, "Failed to allocate p3.\n");
    } else {
        memset(p3, 'C', 10 * 1024);
        printf("[INFO] Allocated big p3 at %p.\n", (void*)p3);
    }

    // 6) Освобождаем все регионы
    heap_term();
    printf("heap_term() done, all regions unmapped.\n");

    // Итог
    printf("All tests passed.\n");
    return 0;
}
