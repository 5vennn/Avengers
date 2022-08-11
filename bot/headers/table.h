#pragma once

#include <stdint.h>
#include "includes.h"

struct table_value
{
    char *val;
    uint16_t val_len;

    #ifdef DEBUG
        BOOL locked;
    #endif
};

#define TABLE_KILLER_PROC 1
#define TABLE_KILLER_EXE 2
#define TABLE_KILLER_DELETED 3
#define TABLE_KILLER_FD 4
#define TABLE_KILLER_MAPS 5
#define TABLE_KILLER_TCP 6
#define TABLE_KILLER_MASUTA 7
#define TABLE_MAPS_MIRAI 8
#define TABLE_MISC_WATCHDOG 9
#define TABLE_MISC_WATCHDOG2 10
#define TABLE_MISC_ROUTE 11
#define TABLE_MAX_KEYS 12

void table_init(void);
void table_unlock_val(uint8_t);
void table_lock_val(uint8_t); 
char *table_retrieve_val(int, int *);

static void add_entry(uint8_t, char *, int);
static void toggle_obf(uint8_t);
