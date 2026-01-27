#include <assert.h>
#include <openssl/evp.h>
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

enum btype {
    BENCODE_BYTE_STRING,
    BENCODE_INTEGER,
    BENCODE_LIST,
    BENCODE_DICTIONARY
};

typedef union belement belement_t;

struct bint {
    enum btype type;
    uint32_t padding1;
    int64_t value;
    uint64_t padding2;
    uint64_t padding3;
};

struct bstr {
    enum btype type;
    uint32_t padding1;
    char *buffer;
    size_t length;
    uint64_t padding2;
};

struct blist {
    enum btype type;
    uint32_t padding1;
    belement_t *items;
    size_t length;
    uint64_t padding2;
};

struct kvpair {
    struct bstr *key;
    belement_t *element;
    uint64_t padding;
};

struct bdict {
    enum btype type;
    uint32_t padding1;
    struct kvpair *kvpairs;
    size_t length;
    uint64_t padding2;
};

union belement {
    enum btype type;
    struct bstr byte_string;
    struct bint integer;
    struct blist list;
    struct bdict dictionary;
};

char *
bdecode(struct arena *, belement_t *, char *);

char *
bdecode_byte_string(struct arena *arena,
                    struct bstr *bstr,
                    char *bencoded_value)
{
    int length = atoi(bencoded_value);
    size_t lengthlength = snprintf(NULL, 0, "%d", length);
    const char *colon_index = strchr(bencoded_value, ':');
    if (colon_index != NULL) {
        const char *start = colon_index + 1;
        bstr->buffer = malloc(length + 1); // TODO: free string value
        memcpy(bstr->buffer, start, length);
        bstr->buffer[length] = '\0';
        bstr->length = length;
    }
    else {
        fprintf(stderr, "Invalid encoded value: %s\n", bencoded_value);
        exit(1);
    }
    char *next = bencoded_value + length + lengthlength + 1;
    return next;
}

char *
bdecode_integer(struct arena *arena, struct bint *bint, char *bencoded_value)
{
    char *token = strtok(bencoded_value + 1, "e");
    int64_t result = strtoll(token, NULL, 10);
    bint->value = result;

    char *next = bencoded_value + strlen(token) + 2;
    return next;
}

char *
bdecode_list(struct arena *arena, struct blist *blist, char *bencoded_value)
{
    blist->length = 0;
    blist->items = (belement_t *)arena_push(
        arena, sizeof(belement_t *), 8); // TODO: fix hardcoded size
    bencoded_value++;
    while (*bencoded_value != '\0' && *bencoded_value != 'e') {

        bencoded_value =
            bdecode(arena, &blist->items[blist->length], bencoded_value);
        blist->length++;
    }

    return bencoded_value + 1;
}

char *
bdecode_dictionary(struct arena *arena,
                   struct bdict *bdict,
                   char *bencoded_value)
{
    bdict->length = 0;
    bdict->kvpairs = (struct kvpair *)arena_push(
        arena, sizeof(*bdict->kvpairs), 8); // TODO: fix hardcoded size

    bencoded_value++;
    while (*bencoded_value != '\0' && *bencoded_value != 'e') {
        bdict->kvpairs[bdict->length].key =
            arena_push(arena, sizeof(struct bstr), 1);
        bencoded_value =
            bdecode(arena,
                    (belement_t *)bdict->kvpairs[bdict->length].key,
                    bencoded_value);

        bdict->kvpairs[bdict->length].element =
            arena_push(arena, sizeof(belement_t), 1);
        bencoded_value = bdecode(
            arena, bdict->kvpairs[bdict->length].element, bencoded_value);

        bdict->length++;
    }

    return bencoded_value + 1;
}

char *
bdecode(struct arena *arena, belement_t *bencode, char *bencoded_value)
{
    if (is_digit(bencoded_value[0])) {
        bencode->type = BENCODE_BYTE_STRING;
        bencoded_value =
            bdecode_byte_string(arena, (struct bstr *)bencode, bencoded_value);
    }
    else if ('i' == bencoded_value[0]) {
        bencode->type = BENCODE_INTEGER;
        bencoded_value =
            bdecode_integer(arena, (struct bint *)bencode, bencoded_value);
    }
    else if ('l' == bencoded_value[0]) {
        bencode->type = BENCODE_LIST;
        bencoded_value =
            bdecode_list(arena, (struct blist *)bencode, bencoded_value);
    }
    else if ('d' == bencoded_value[0]) {
        bencode->type = BENCODE_DICTIONARY;
        bencoded_value =
            bdecode_dictionary(arena, (struct bdict *)bencode, bencoded_value);
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

char *
string_builder_append_string(struct string_builder *sb,
                             char *string,
                             size_t length)
{
    memcpy(sb->buffer + sb->length, string, length);
    sb->length += length;
    sb->buffer[sb->length] = '\0';
    return sb->buffer;
}

char *
string_builder_append_char(struct string_builder *sb, char c)
{
    char str[1] = {c};
    return string_builder_append_string(sb, str, 1);
}

char *
string_builder_append_int64(struct string_builder *sb, int64_t value)
{
    char tmp[1024];

    size_t length = snprintf(tmp, sizeof(tmp), "%lld", value);
    tmp[length] = '\0';
    return string_builder_append_string(sb, tmp, length);
}

void
string_builder_destroy(struct string_builder *sb)
{
    free(sb->buffer);
}

char *
bencode_stringify(struct string_builder *sb, belement_t *bencode)
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
            belement_t *item = &bencode->list.items[i];
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

            struct kvpair *kvpair = &bencode->dictionary.kvpairs[i];
            bencode_stringify(sb, (belement_t *)kvpair->key);
            string_builder_append_string(sb, ":", 1);
            bencode_stringify(sb, kvpair->element);
        }
        string_builder_append_string(sb, "}", 1);
    }

    return string_builder_string(sb);
}

void
bencode(struct string_builder *sb, belement_t *bencode);

void
bencode_string(struct string_builder *sb, struct bstr *s)
{
    string_builder_append_int64(sb, s->length);
    string_builder_append_char(sb, ':');
    string_builder_append_string(sb, s->buffer, s->length);
}

void
bencode_integer(struct string_builder *sb, struct bint *i)
{
    string_builder_append_char(sb, 'i');
    string_builder_append_int64(sb, i->value);
    string_builder_append_char(sb, 'e');
}

void
bencode_list(struct string_builder *sb, struct blist *list)
{
    string_builder_append_char(sb, 'l');
    for (int i = 0; i < list->length; i++) {
        bencode(sb, (belement_t *)&list->items[i]);
    }
    string_builder_append_char(sb, 'e');
}

void
bencode_dictionary(struct string_builder *sb, struct bdict *dict)
{
    string_builder_append_char(sb, 'd');
    for (int i = 0; i < dict->length; i++) {
        struct bstr *key = dict->kvpairs[i].key;
        belement_t *value = dict->kvpairs[i].element;
        bencode_string(sb, key);
        bencode(sb, value);
    }
    string_builder_append_char(sb, 'e');
}

void
bencode(struct string_builder *sb, belement_t *bencode)
{
    if (bencode->type == BENCODE_BYTE_STRING) {
        bencode_string(sb, (struct bstr *)bencode);
    }
    else if (bencode->type == BENCODE_INTEGER) {
        bencode_integer(sb, (struct bint *)bencode);
    }
    else if (bencode->type == BENCODE_LIST) {
        bencode_list(sb, (struct blist *)bencode);
    }
    else if (bencode->type == BENCODE_DICTIONARY) {
        bencode_dictionary(sb, (struct bdict *)bencode);
    }
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
        belement_t *bencode = arena_push(&arena, sizeof(*bencode), 1);
        bdecode(&arena, bencode, encoded_str);
        struct string_builder sb = string_builder_init(1024 * 1024);
        char *string = bencode_stringify(&sb, bencode);
        printf("%s\n", string);
        string_builder_destroy(&sb);
    }
    else if (0 == strcmp(command, "info")) {
        char *tracker_url = NULL;
        char *name = NULL;
        size_t length = 0;
        char *info_hash = NULL;
        size_t piece_length = 0;
        uint8_t **pieces = NULL;
        char **piece_hashes = NULL;
        size_t npieces = 0;

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

        belement_t *elem = arena_push(&arena, sizeof(*elem), 1);
        bdecode(&arena, elem, buffer);
        struct bdict *dict = &elem->dictionary;
        for (int i = 0; i < dict->length; i++) {
            char *key = dict->kvpairs[i].key->buffer;
            belement_t *value = dict->kvpairs[i].element;
            if (0 == strcmp(key, "announce") &&
                value->type == BENCODE_BYTE_STRING) {
                tracker_url = arena_push(
                    &arena, sizeof(*tracker_url), value->byte_string.length);
                memcpy(tracker_url,
                       value->byte_string.buffer,
                       value->byte_string.length + 1);
                tracker_url[value->byte_string.length] = '\0';
            }
            else if (0 == strcmp(key, "info") &&
                     value->type == BENCODE_DICTIONARY) {

                struct bdict info = value->dictionary;
                struct string_builder sb = string_builder_init(1024 * 64);

                bencode(&sb, (belement_t *)&info);

                OpenSSL_add_all_digests();
                const EVP_MD *md = EVP_get_digestbyname("SHA1");
                assert(md && "Failed to get SHA1 digest");

                unsigned char md_val[EVP_MAX_MD_SIZE];
                uint32_t md_len = 0;
                EVP_MD_CTX *md_ctx = EVP_MD_CTX_create();
                EVP_DigestInit_ex(md_ctx, md, NULL);
                EVP_DigestUpdate(md_ctx, sb.buffer, sb.length);
                EVP_DigestFinal_ex(md_ctx, md_val, &md_len);
                EVP_MD_CTX_destroy(md_ctx);

                info_hash = arena_push(&arena, sizeof(*info_hash), md_len * 2);
                for (int i = 0; i < md_len; i++) {
                    sprintf(&info_hash[i * 2], "%02x", md_val[i]);
                }

                for (int j = 0; j < info.length; j++) {
                    char *key = info.kvpairs[j].key->buffer;
                    belement_t *value = info.kvpairs[j].element;
                    if (0 == strcmp(key, "length") &&
                        value->type == BENCODE_INTEGER) {
                        length = value->integer.value;
                    }
                    else if (0 == strcmp(key, "piece length") &&
                             value->type == BENCODE_INTEGER) {
                        piece_length = value->integer.value;
                    }
                    else if (0 == strcmp(key, "name") &&
                             value->type == BENCODE_BYTE_STRING) {
                        name = arena_push(
                            &arena, sizeof(*name), value->byte_string.length);
                        memcpy(name,
                               value->byte_string.buffer,
                               value->byte_string.length + 1);
                        name[value->byte_string.length] = '\0';
                    }
                    else if (0 == strcmp(key, "pieces") &&
                             value->type == BENCODE_BYTE_STRING) {
                        npieces = value->byte_string.length / 20;
                        pieces = arena_push(
                            &arena, sizeof(*pieces), value->byte_string.length);
                        for (int i = 0; i < npieces; i++) {
                            pieces[i] =
                                arena_push(&arena, sizeof(**pieces), 21);
                            memcpy(pieces[i],
                                   value->byte_string.buffer + i * 20,
                                   20);
                            pieces[i][20] = '\0';
                        }
                    }
                }

                piece_hashes =
                    arena_push(&arena, sizeof(*piece_hashes), npieces);
                for (int i = 0; i < npieces; i++) {
                    piece_hashes[i] =
                        arena_push(&arena, sizeof(**piece_hashes), 41);
                    uint8_t *piece = pieces[i];
                    for (int j = 0; j < 20; j++) {
                        sprintf(
                            &piece_hashes[i][j * 2], "%02x", piece[j] & 0xFF);
                    }
                    piece_hashes[i][40] = '\0';
                }

                printf("Tracker URL: %s\n", tracker_url);
                printf("Length: %zu\n", length);
                printf("Info Hash: %s\n", info_hash);
                printf("Piece Length: %zu\n", piece_length);
                printf("Piece Hashes:\n");
                for (int i = 0; i < npieces; i++) {
                    printf("%s\n", piece_hashes[i]);
                }

                string_builder_destroy(&sb);
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
