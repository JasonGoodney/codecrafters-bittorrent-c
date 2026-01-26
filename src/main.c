#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool
is_digit(char c)
{
    return c >= '0' && c <= '9';
}

enum bencode_type {
    BENCODE_BYTE_STRING,
    BENCODE_INTEGER,
    BENCODE_LIST,
    BENCODE_DICTIONARY
};

typedef union bencode Bencode;

struct bencode_integer {
    enum bencode_type type;
    uint32_t padding1;
    int64_t value;
    uint64_t padding2;
    uint64_t padding3;
};

struct bencode_byte_string {
    enum bencode_type type;
    uint32_t padding1;
    char *buffer;
    size_t length;
    uint64_t padding2;
};

struct bencode_list {
    enum bencode_type type;
    uint32_t padding1;
    Bencode *items;
    size_t length;
    uint64_t padding2;
};

struct bencode_kvpair {
    struct bencode_byte_string *key;
    Bencode *value;
    uint64_t padding;
};

struct bencode_dictionary {
    enum bencode_type type;
    uint32_t padding1;
    struct bencode_kvpair *kvpairs;
    size_t length;
    uint64_t padding2;
};

union bencode {
    enum bencode_type type;
    struct bencode_byte_string byte_string;
    struct bencode_integer integer;
    struct bencode_list list;
    struct bencode_dictionary dictionary;
};

struct arena {
    void *base;
    uint32_t capacity;
    uint32_t used;
};

void *
arena_push(struct arena *arena, size_t size, size_t nitems)
{
    assert((size * nitems) + arena->used <= arena->capacity);

    void *ptr = (uint8_t *)arena->base + arena->used;
    arena->used += (size * nitems);
    return ptr;
}

void
arena_clear(struct arena *arena)
{
    arena->used = 0;
}

struct arena
arena_init(uint32_t capacity)
{
    struct arena arena = {0};
    arena.capacity = capacity;
    arena.base = malloc(capacity);
    return arena;
}

void
arena_destroy(struct arena *arena)
{
    free(arena->base);
}

char *
decode_bencode(struct arena *arena, Bencode *bencode, char *bencoded_value);

char *
decode_byte_string(struct arena *arena,
                   struct bencode_byte_string *bencode,
                   char *bencoded_value)
{
    int length = atoi(bencoded_value);
    size_t lengthlength = snprintf(NULL, 0, "%d", length);
    const char *colon_index = strchr(bencoded_value, ':');
    if (colon_index != NULL) {
        const char *start = colon_index + 1;
        bencode->buffer = malloc(length + 1); // TODO: free string value
        memcpy(bencode->buffer, start, length);
        bencode->buffer[length] = '\0';
        bencode->length = length;
    }
    else {
        fprintf(stderr, "Invalid encoded value: %s\n", bencoded_value);
        exit(1);
    }
    char *next = bencoded_value + length + lengthlength + 1;
    return next;
}

char *
decode_integer(struct arena *arena,
               struct bencode_integer *bencode,
               char *bencoded_value)
{
    char *token = strtok(bencoded_value + 1, "e");
    int64_t result = strtoll(token, NULL, 10);
    bencode->value = result;

    char *next = bencoded_value + strlen(token) + 2;
    return next;
}

char *
decode_list(struct arena *arena,
            struct bencode_list *list,
            char *bencoded_value)
{
    list->length = 0;
    list->items = (Bencode *)arena_push(
        arena, sizeof(Bencode *), 8); // TODO: fix hardcoded size
    bencoded_value++;
    while (*bencoded_value != '\0' && *bencoded_value != 'e') {

        bencoded_value =
            decode_bencode(arena, &list->items[list->length], bencoded_value);
        list->length++;
    }

    return bencoded_value + 1;
}

char *
decode_dictionary(struct arena *arena,
                  struct bencode_dictionary *dict,
                  char *bencoded_value)
{
    dict->length = 0;
    dict->kvpairs = (struct bencode_kvpair *)arena_push(
        arena, sizeof(*dict->kvpairs), 8); // TODO: fix hardcoded size

    bencoded_value++;
    while (*bencoded_value != '\0' && *bencoded_value != 'e') {
        dict->kvpairs[dict->length].key =
            arena_push(arena, sizeof(struct bencode_byte_string), 1);
        bencoded_value = decode_bencode(
            arena, (Bencode *)dict->kvpairs[dict->length].key, bencoded_value);

        dict->kvpairs[dict->length].value =
            arena_push(arena, sizeof(Bencode), 1);
        bencoded_value = decode_bencode(
            arena, dict->kvpairs[dict->length].value, bencoded_value);

        dict->length++;
    }

    return bencoded_value + 1;
}

char *
decode_bencode(struct arena *arena, Bencode *bencode, char *bencoded_value)
{
    if (is_digit(bencoded_value[0])) {
        bencode->type = BENCODE_BYTE_STRING;
        bencoded_value = decode_byte_string(
            arena, (struct bencode_byte_string *)bencode, bencoded_value);
    }
    else if ('i' == bencoded_value[0]) {
        bencode->type = BENCODE_INTEGER;
        bencoded_value = decode_integer(
            arena, (struct bencode_integer *)bencode, bencoded_value);
    }
    else if ('l' == bencoded_value[0]) {
        bencode->type = BENCODE_LIST;
        bencoded_value =
            decode_list(arena, (struct bencode_list *)bencode, bencoded_value);
    }
    else if ('d' == bencoded_value[0]) {
        bencode->type = BENCODE_DICTIONARY;
        bencoded_value = decode_dictionary(
            arena, (struct bencode_dictionary *)bencode, bencoded_value);
    }
    else {
        fprintf(stderr, "Only strings are supported at the moment\n");
        exit(1);
    }

    return bencoded_value;
}

struct string_builder {
    char *buffer;
    size_t capacity;
    size_t length;
};

struct string_builder
string_builder_init(size_t capacity)
{
    struct string_builder sb = {0};
    sb.capacity = capacity;
    sb.buffer = malloc(capacity);
    return sb;
}

char *
string_builder_string(struct string_builder *sb)
{
    return sb->buffer;
}

void
string_builder_append_string(struct string_builder *sb,
                             char *string,
                             size_t length)
{
    memcpy(sb->buffer + sb->length, string, length);
    sb->length += length;
}

void
string_builder_append_int64(struct string_builder *sb, int64_t value)
{
    char tmp[1024];

    size_t length = snprintf(tmp, sizeof(tmp), "%lld", value);
    tmp[length] = '\0';
    string_builder_append_string(sb, tmp, length);
}

char *
string_builder_end(struct string_builder *sb)
{
    sb->buffer[sb->length] = '\0';
    return sb->buffer;
}

char *
bencode_stringify(struct string_builder *sb, Bencode *bencode)
{

    if (bencode->type == BENCODE_BYTE_STRING) {
        string_builder_append_string(sb, "\"", 1);
        string_builder_append_string(
            sb, bencode->byte_string.buffer, bencode->byte_string.length);
        string_builder_append_string(sb, "\"", 1);
    }
    else if (bencode->type == BENCODE_INTEGER) {
        string_builder_append_int64(sb, bencode->integer.value);
    }
    else if (bencode->type == BENCODE_LIST) {
        char *delim = "";
        string_builder_append_string(sb, "[", 1);
        for (int i = 0; i < bencode->list.length; i++) {
            string_builder_append_string(sb, delim, strlen(delim));
            delim = ",";
            Bencode *item = &bencode->list.items[i];
            bencode_stringify(sb, item);
        }
        string_builder_append_string(sb, "]", 1);
    }
    else if (bencode->type == BENCODE_DICTIONARY) {
        char *delim = "";
        string_builder_append_string(sb, "{", 1);
        for (int i = 0; i < bencode->dictionary.length; i++) {
            string_builder_append_string(sb, delim, strlen(delim));
            delim = ",";

            struct bencode_kvpair *kvpair = &bencode->dictionary.kvpairs[i];
            bencode_stringify(sb, (Bencode *)kvpair->key);
            string_builder_append_string(sb, ":", 1);
            bencode_stringify(sb, kvpair->value);
        }
        string_builder_append_string(sb, "}", 1);
    }

    return string_builder_string(sb);
}

int
main(int argc, char *argv[])
{
    // Disable output buffering
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    if (argc < 3) {
        fprintf(stderr, "Usage: your_program.sh <command> <args>\n");
        return 1;
    }

    const char *command = argv[1];

    uint32_t capacity = 1024 * 1024 * 64;
    struct arena arena = arena_init(capacity);

    if (strcmp(command, "decode") == 0) {
        // You can use print statements as follows for debugging, they'll be
        // visible when running tests.
        fprintf(stderr, "Logs from your program will appear here!\n");

        char *encoded_str = argv[2];
        Bencode *bencode = arena_push(&arena, sizeof(*bencode), 1);
        decode_bencode(&arena, bencode, encoded_str);
        struct string_builder sb = string_builder_init(1024 * 1024);
        char *string = bencode_stringify(&sb, bencode);
        string_builder_end(&sb);
        printf("%s\n", string);
    }
    else if (0 == strcmp(command, "info")) {
        char filename[4096];
        size_t len = snprintf(filename, sizeof(filename), "../%s", argv[2]);
        filename[len] = '\0';
        FILE *fh = fopen(filename, "rb");
        assert(fh != NULL);
        char buffer[4096];
        size_t read = fread(&buffer, sizeof(*buffer), sizeof(buffer), fh);
        assert(read > 0);
        int closed = fclose(fh);
        assert(closed >= 0);

        Bencode *bencode = arena_push(&arena, sizeof(*bencode), 1);
        decode_bencode(&arena, bencode, buffer);
        struct bencode_dictionary *dict = &bencode->dictionary;
        for (int i = 0; i < dict->length; i++) {
            char *key = dict->kvpairs[i].key->buffer;
            Bencode *value = dict->kvpairs[i].value;
            if (0 == strcmp(key, "announce") && value->type == BENCODE_BYTE_STRING) {
                printf("Tracker URL: %s\n", value->byte_string.buffer);
                break;
            }
        }
        for (int i = 0; i < dict->length; i++) {
            char *key = dict->kvpairs[i].key->buffer;
            Bencode *value = dict->kvpairs[i].value;
            if (0 == strcmp(key, "info") && value->type == BENCODE_DICTIONARY) {
                struct bencode_dictionary child = value->dictionary;
                for (int j = 0; j < child.length; j++) {
                    char *key = child.kvpairs[j].key->buffer;
                    Bencode *value = child.kvpairs[j].value;
                    if (0 == strcmp(key, "length") && value->type == BENCODE_INTEGER) {
                        printf("Length: %lld\n", value->integer.value);
                        break;
                    }
                }
                break;
            }
        }
    }
    else {
        fprintf(stderr, "Unknown command: %s\n", command);
        return 1;
    }

    arena_destroy(&arena);

    return 0;
}
