#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "history.h"
#include "nosh.h"  // for MAX_HISTORY

static char *history_list[MAX_HISTORY];
static int history_count = 0;

void nosh_add_history(const char *command) {
    if (history_count < MAX_HISTORY) {
        history_list[history_count++] = strdup(command);
    }
}

void print_history(void) {
    for (int i = 0; i < history_count; i++) {
        printf("%d: %s\n", i + 1, history_list[i]);
    }
}

char *get_history(int index) {
    if (index < 0 || index >= history_count) {
        return NULL;
    }
    return history_list[index];
}

void nosh_clear_history(void) {  // Renamed to avoid conflict
    for (int i = 0; i < history_count; i++) {
        free(history_list[i]);
    }
    history_count = 0;
    printf("Command history cleared.\n");
}
