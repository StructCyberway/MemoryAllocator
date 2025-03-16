#define  _DEFAULT_SOURCE  

#include  <assert.h>       
#include  <stdio.h>        
#include  <stdlib.h>       
#include  <unistd.h>       

#include  "mem_internals.h" 
#include  "mem.h"           
#include  "util.h"          

// Объявления отладочных функций
void debug_block(struct block_header* b, const char* fmt, ...);
void debug(const char* fmt, ...);

// Инлайн-функции из mem_internals.h для получения размеров блоков
extern inline block_size     size_from_capacity(block_capacity cap);
extern inline block_capacity capacity_from_size(block_size sz);
extern inline bool           region_is_invalid(const struct region* r);

/*
 * Функция pages_count вычисляет, сколько страниц потребуется
 * для размещения mem байт, округляя вверх.
 */
static size_t pages_count(size_t mem) {
    return mem / getpagesize() + ((mem % getpagesize()) ? 1 : 0);
}

/*
 * Округляем mem до границы страницы, используя pages_count.
 */
static size_t round_pages(size_t mem) {
    return getpagesize() * pages_count(mem);
}

/*
 * Проверяем, достаточно ли блок >= query байт
 */
static bool block_is_big_enough(size_t query, struct block_header* block) {
    return block->capacity.bytes >= query;
}

/*
 * Инициализация заголовка блока по адресу addr.
 * block_sz указывает общий размер блока (заголовок + данные).
 * next_block — следующий блок в списке, если есть.
 */
static void block_init(void* addr, block_size block_sz, void* next_block) {
    struct block_header* hdr = (struct block_header*)addr;
    hdr->next = (struct block_header*)next_block;
    hdr->capacity = capacity_from_size(block_sz);
    hdr->is_free = true;
}

/*
 * Определяем реальный размер региона для mmap,
 * учитывая кратность страниц и минимальный размер REGION_MIN_SIZE.
 */
static size_t region_actual_size(size_t query) {
    return size_max(round_pages(query), REGION_MIN_SIZE);
}

/*
 * Обёртка над mmap для выделения памяти.
 * flags_extra добавляет дополнительные флаги (например, MAP_FIXED_NOREPLACE).
 */
static void* map_pages(const void* addr, size_t length, int flags_extra) {
    return mmap((void*)addr, length,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | flags_extra,
                -1, 0);
}

/*
 * Выделение региона памяти (mmap) с желаемым размером query.
 * Возвращает структуру region с addr, size и флагом extends.
 * Если не смогли привязать регион к addr, пробуем обычный mmap (0).
 */
static struct region alloc_region(const void* addr, size_t query) {
    block_capacity cap = { .bytes = query };
    // С учётом заголовка блока
    block_size sz = size_from_capacity(cap);
    size_t real_size = region_actual_size(sz.bytes);

    // Пытаемся выделить по addr
    void* region_addr = map_pages(addr, real_size, MAP_FIXED_NOREPLACE);
    struct region reg = {
        .addr = region_addr,
        .size = real_size,
        .extends = false
    };

    // Если не получилось, пробуем без фиксации
    if (region_addr == MAP_FAILED) {
        region_addr = map_pages(addr, real_size, 0);
        if (region_addr == MAP_FAILED) {
            return REGION_INVALID;
        }
        reg.addr = region_addr;
    }

    // Проверяем, удалось ли разместить именно по addr
    reg.extends = (reg.addr == addr);

    // Инициализируем первый блок во всём регионе
    block_init(reg.addr, (block_size){ .bytes = reg.size }, NULL);
    return reg;
}

#define BLOCK_MIN_CAPACITY 32  // Минимальная вместимость блока

/*
 * Можно ли поделить блок?
 * Нужно, чтобы он был свободен и
 * оставалось место после query >= BLOCK_MIN_CAPACITY.
 */
static bool block_splittable(struct block_header* restrict block, size_t query) {
    const size_t overhead = offsetof(struct block_header, contents);
    return block->is_free &&
           (query + overhead + BLOCK_MIN_CAPACITY <= block->capacity.bytes);
}

/*
 * Делим блок на два, если он слишком большой.
 * Возвращаем true, если действительно разделили.
 */
static bool split_if_too_big(struct block_header* block, size_t query) {
    if (!block || !block_splittable(block, query)) return false;

    // Адрес начала второго блока
    uint8_t* new_block_addr = block->contents + query;
    // Оставшаяся вместимость
    size_t remaining = block->capacity.bytes - query;

    // Инициализируем второй блок
    block_init(new_block_addr, (block_size){ .bytes = remaining }, block->next);

    // Уменьшаем текущий блок
    block->capacity.bytes = query;
    block->next = (struct block_header*)new_block_addr;
    block->is_free = true;

    return true;
}

/*
 * Возвращаем адрес (void*), где заканчивается блок (после данных).
 */
static void* block_after(const struct block_header* block) {
    return (void*)(block->contents + block->capacity.bytes);
}

/*
 * Находятся ли два блока подряд в памяти?
 */
static bool blocks_continuous(const struct block_header* fst,
                              const struct block_header* snd) {
    return (void*)snd == block_after(fst);
}

/*
 * Проверка, можно ли объединить два блока:
 * они должны быть свободны и идти подряд в памяти.
 */
static bool mergeable(const struct block_header* restrict fst,
                      const struct block_header* restrict snd) {
    return fst->is_free && snd->is_free && blocks_continuous(fst, snd);
}

/*
 * Пытаемся объединить block со следующим (block->next), если это возможно.
 */
static bool try_merge_with_next(struct block_header* block) {
    if (!block || !block->next) return false;
    struct block_header* next_block = block->next;
    if (mergeable(block, next_block)) {
        // Увеличиваем вместимость
        block->capacity.bytes += size_from_capacity(next_block->capacity).bytes;
        // Пропускаем следующий блок
        block->next = next_block->next;
        return true;
    }
    return false;
}

/*
 * Сливаем все возможные блоки после block, пока это можно сделать.
 */
static void merge_all_possible(struct block_header* block) {
    while (try_merge_with_next(block)) {
        // Продолжаем сливать
    }
}

/*
 * Результат поиска хорошего блока:
 * - BSR_FOUND_GOOD_BLOCK: нашли подходящий блок
 * - BSR_REACHED_END_NOT_FOUND: не нашли, дошли до конца
 * - BSR_CORRUPTED: некорректный список
 */
struct block_search_result {
    enum {
        BSR_FOUND_GOOD_BLOCK,
        BSR_REACHED_END_NOT_FOUND,
        BSR_CORRUPTED
    } type;
    struct block_header* block;
};

/*
 * find_good_or_last ищет свободный блок достаточного размера,
 * либо возвращает последний блок в цепочке, если подходящего не нашлось.
 * Если список "битый", возвращаем BSR_CORRUPTED.
 */
static struct block_search_result
find_good_or_last(struct block_header* restrict start, size_t sz)
{
    struct block_header* current = start;
    while (current) {
        // Попробуем объединить текущий блок со следующим
        merge_all_possible(current);

        // Если свободен и достаточно велик
        if (current->is_free && block_is_big_enough(sz, current)) {
            return (struct block_search_result){
                .type = BSR_FOUND_GOOD_BLOCK,
                .block = current
            };
        }
        // Если следующий блок отсутствует — дошли до конца
        if (!current->next) {
            return (struct block_search_result){
                .type = BSR_REACHED_END_NOT_FOUND,
                .block = current
            };
        }
        current = current->next;
    }
    // Если стартовый блок был NULL или список оборвался
    return (struct block_search_result){ BSR_CORRUPTED, NULL };
}

/*
 * В уже существующей куче пытаемся найти подходящий блок.
 * Если находим, возможно делим блок, помечаем как занятый.
 */
static struct block_search_result
try_memalloc_existing(size_t query, struct block_header* block)
{
    struct block_search_result res = find_good_or_last(block, query);
    if (res.type == BSR_FOUND_GOOD_BLOCK) {
        struct block_header* good_block = res.block;
        // Делим, если нужно
        split_if_too_big(good_block, query);
        // Занимаем блок
        good_block->is_free = false;
    }
    return res;
}

/*
 * Функция расширения кучи: создаёт новый регион после last.
 * Если регион удаётся разместить вплотную, пробуем объединить блоки.
 */
static struct block_header* grow_heap(struct block_header* restrict last, size_t query) {
    uint8_t* next_addr = block_after(last);
    struct region new_reg = alloc_region(next_addr, query);
    if (region_is_invalid(&new_reg)) { return NULL; }
    last->next = (struct block_header*)new_reg.addr;

    // Если не вплотную, просто возвращаем указатель на новый регион
    if (!new_reg.extends) { return last->next; }
    // Иначе пытаемся объединить
    if (try_merge_with_next(last)) { return last; }
    return last->next;
}

/*
 * memalloc — поиск в уже известной куче + grow_heap при необходимости.
 */
static struct block_header* memalloc(size_t query, struct block_header* heap_start) {
    if (!heap_start) return NULL;

    // Минимальный запрос
    if (query < BLOCK_MIN_CAPACITY) {
        query = BLOCK_MIN_CAPACITY;
    }

    // Сначала ищем в уже выделенных блоках
    struct block_search_result res = try_memalloc_existing(query, heap_start);
    if (res.type == BSR_FOUND_GOOD_BLOCK) {
        return res.block;
    }
    // Если не нашли, пробуем расширить кучу
    if (res.type == BSR_REACHED_END_NOT_FOUND) {
        struct block_header* grown_start = grow_heap(res.block, query);
        if (!grown_start) return NULL;
        // После расширения повторяем поиск
        return try_memalloc_existing(query, grown_start).block;
    }
    // BSR_CORRUPTED или иная ошибка
    return NULL;
}

/*
 * Публичная функция _malloc: возвращает указатель на содержимое,
 * или NULL, если не удалось выделить.
 */
void* _malloc(size_t query) {
    struct block_header* allocated = memalloc(query, (struct block_header*)HEAP_START);
    return allocated ? allocated->contents : NULL;
}

/*
 * Инициализация кучи: создаём mmap-регион по указанному адресу HEAP_START.
 */
void* heap_init(size_t initial) {
    struct region reg = alloc_region(HEAP_START, initial);
    if (region_is_invalid(&reg)) {
        return NULL;
    }
    return reg.addr;
}

/*
 * Завершение работы кучи: освобождаем все mmap-регионы одним за другим.
 * Для каждого непрерывного участка блоков вызываем один munmap.
 */
void heap_term() {
    struct block_header* current = (struct block_header*)HEAP_START;
    // Идём по списку блоков, пока не закончится
    while (current) {
        struct block_header* next_block = current->next;

        // Рассчитываем общий размер непрерывного участка
        block_size total_size = size_from_capacity(current->capacity);
        while (next_block && blocks_continuous(current, next_block)) {
            total_size.bytes += size_from_capacity(next_block->capacity).bytes;
            next_block = next_block->next;
        }

        // Вызываем munmap, освобождая память
        int rc = munmap(current, total_size.bytes);
        if (rc != 0) {
 
        }

        // Переходим к следующему блоку (после всех непрерывных)
        current = next_block;
    }
}

/*
 * Вспомогательная функция: получить адрес заголовка блока по указателю на данные.
 */
static struct block_header* block_get_header(void* contents) {
    return (struct block_header*)((uint8_t*)contents
                                  - offsetof(struct block_header, contents));
}

/*
 * Публичная функция _free: помечаем блок свободным и пытаемся объединять.
 */
void _free(void* mem) {
    if (!mem) return;
    struct block_header* hdr = block_get_header(mem);
    hdr->is_free = true;
    merge_all_possible(hdr);
}
