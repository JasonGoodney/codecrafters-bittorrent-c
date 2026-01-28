#include <assert.h>
#include <ctype.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "arena.h"

bool
is_digit(char c)
{
    return c >= '0' && c <= '9';
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
    size_t length_char_count = snprintf(NULL, 0, "%d", length);
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
    char *next = bencoded_value + length + length_char_count + 1;
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
        fprintf(stderr, "Unknown identifier: [%c]\n", bencoded_value[0]);
        exit(1);
    }

    return bencoded_value;
}

struct strbuf {
    char *buffer;
    size_t capacity;
    size_t length;
};

struct strbuf
strbuf_init(size_t capacity)
{
    struct strbuf sb = {0};
    sb.capacity = capacity;
    sb.buffer = malloc(capacity);
    return sb;
}

char *
strbuf_string(struct strbuf *sb)
{
    return sb->buffer;
}

char *
strbuf_append_string(struct strbuf *sb, char *string, size_t length)
{
    memcpy(sb->buffer + sb->length, string, length);
    sb->length += length;
    sb->buffer[sb->length] = '\0';
    return sb->buffer;
}

char *
strbuf_append_char(struct strbuf *sb, char c)
{
    char str[1] = {c};
    return strbuf_append_string(sb, str, 1);
}

char *
strbuf_append_int64(struct strbuf *sb, int64_t value)
{
    char tmp[1024];

    size_t length = snprintf(tmp, sizeof(tmp), "%lld", value);
    tmp[length] = '\0';
    return strbuf_append_string(sb, tmp, length);
}

void
strbuf_destroy(struct strbuf *sb)
{
    free(sb->buffer);
}

char *
bencode_stringify(struct strbuf *sb, belement_t *bencode)
{

    if (bencode->type == BENCODE_BYTE_STRING) {
        strbuf_append_string(sb, "\"", 1);
        strbuf_append_string(
            sb, bencode->byte_string.buffer, bencode->byte_string.length);
        strbuf_append_string(sb, "\"", 1);
    }
    else if (bencode->type == BENCODE_INTEGER) {
        strbuf_append_int64(sb, bencode->integer.value);
    }
    else if (bencode->type == BENCODE_LIST) {
        char *delim = "";
        strbuf_append_string(sb, "[", 1);
        for (int i = 0; i < bencode->list.length; i++) {
            strbuf_append_string(sb, delim, strlen(delim));
            delim = ",";
            belement_t *item = &bencode->list.items[i];
            bencode_stringify(sb, item);
        }
        strbuf_append_string(sb, "]", 1);
    }
    else if (bencode->type == BENCODE_DICTIONARY) {
        char *delim = "";
        strbuf_append_string(sb, "{", 1);
        for (int i = 0; i < bencode->dictionary.length; i++) {
            strbuf_append_string(sb, delim, strlen(delim));
            delim = ",";

            struct kvpair *kvpair = &bencode->dictionary.kvpairs[i];
            bencode_stringify(sb, (belement_t *)kvpair->key);
            strbuf_append_string(sb, ":", 1);
            bencode_stringify(sb, kvpair->element);
        }
        strbuf_append_string(sb, "}", 1);
    }

    return strbuf_string(sb);
}

void
bencode(struct strbuf *sb, belement_t *bencode);

void
bencode_string(struct strbuf *sb, struct bstr *s)
{
    strbuf_append_int64(sb, s->length);
    strbuf_append_char(sb, ':');
    strbuf_append_string(sb, s->buffer, s->length);
}

void
bencode_integer(struct strbuf *sb, struct bint *i)
{
    strbuf_append_char(sb, 'i');
    strbuf_append_int64(sb, i->value);
    strbuf_append_char(sb, 'e');
}

void
bencode_list(struct strbuf *sb, struct blist *list)
{
    strbuf_append_char(sb, 'l');
    for (int i = 0; i < list->length; i++) {
        bencode(sb, (belement_t *)&list->items[i]);
    }
    strbuf_append_char(sb, 'e');
}

void
bencode_dictionary(struct strbuf *sb, struct bdict *dict)
{
    strbuf_append_char(sb, 'd');
    for (int i = 0; i < dict->length; i++) {
        struct bstr *key = dict->kvpairs[i].key;
        belement_t *value = dict->kvpairs[i].element;
        bencode_string(sb, key);
        bencode(sb, value);
    }
    strbuf_append_char(sb, 'e');
}

void
bencode(struct strbuf *sb, belement_t *bencode)
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

void
error(char *msg)
{
    perror(msg);
    exit(EXIT_SUCCESS);
}
char rfc3986[256] = {0};
char html5[256] = {0};

void
url_encoder_rfc_tables_init()
{

    int i;

    for (i = 0; i < 256; i++) {

        rfc3986[i] =
            isalnum(i) || i == '~' || i == '-' || i == '.' || i == '_' ? i : 0;
        html5[i] = isalnum(i) || i == '*' || i == '-' || i == '.' || i == '_'
                       ? i
                   : (i == ' ') ? '+'
                                : 0;
    }
}

char *
url_encode(char *table, unsigned char *s, char *enc)
{

    for (; *s; s++) {

        if (table[*s])
            *enc = table[*s];
        else
            sprintf(enc, "%%%02X", *s);
        while (*++enc)
            ;
    }

    return (enc);
}

void
tracker_request(char *url,
                size_t torrent_file_size,
                unsigned char *hash,
                size_t hash_len)
{
    struct arena arena = arena_init(1024 * 10);

    url_encoder_rfc_tables_init();
    char *hash_urlencoded =
        arena_push(&arena, sizeof(*hash_urlencoded), hash_len * 3 + 1);
    url_encode(rfc3986, hash, hash_urlencoded);
    hash_urlencoded[strlen(hash_urlencoded)] = '\0';

    char *tmpurl = strdup(url);

    char *scheme = NULL;
    char *host = NULL;
    char *path = NULL;
    char *port = NULL;
    char *qport = "6881";
    char *qpeer_id = "01234567890123456789";
    size_t schemelen = 0;
    size_t hostlen = 0;
    size_t pathlen = 0;

    char *pos = strstr(tmpurl, "://");
    if (pos) {
        schemelen = pos - tmpurl;
        scheme = arena_push(&arena, sizeof(*scheme), schemelen + 1);
        memcpy(scheme, url, schemelen);
        scheme[schemelen] = '\0';
    }
    tmpurl += (schemelen + 3);

    char *l = tmpurl;
    char *p = tmpurl;
    if (*p) {
        while (*p != '\0' && *p != ':' && *p != '/') {
            p++;
        }
        assert(*p != '\0');
        size_t hostlen = p - l;
        host = arena_push(&arena, sizeof(*host), hostlen + 1);
        memcpy(host, l, hostlen);
        host[hostlen] = '\0';
    }

    if (*p == ':') {
        p++;
        l = p;

        while (*p != '\0' && *p != '/') {
            p++;
        }
        assert(*p != '\0');
        size_t portlen = p - l;
        port = arena_push(&arena, sizeof(*port), portlen + 1);
        memcpy(port, l, portlen);
        port[portlen] = '\0';
    }

    if (*p == '/') {
        l = p;

        while (*p != '\0') {
            p++;
        }

        size_t pathlen = p - l;
        path = arena_push(&arena, sizeof(*path), pathlen + 1);
        memcpy(path, l, pathlen);
        path[pathlen] = '\0';
    }

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        error("socket failure");
    }

    struct addrinfo *ai_hints = arena_push(&arena, sizeof(*ai_hints), 1);
    struct addrinfo *ai_result;
    ai_hints->ai_family = AF_INET;
    ai_hints->ai_socktype = SOCK_STREAM;
    ai_hints->ai_protocol = IPPROTO_TCP;

    char *ai_service = (port != NULL) ? port : scheme;
    int ai_status = getaddrinfo(host, port, ai_hints, &ai_result);
    if (0 != ai_status) {
        close(sockfd);
        error((char *)gai_strerror(ai_status));
    }

    int connect_success = 0;
    for (struct addrinfo *ai = ai_result; ai != NULL; ai = ai->ai_next) {
        if (0 > connect(sockfd, ai->ai_addr, ai->ai_addrlen)) {
            perror("connect failed");
            continue;
        }
        connect_success = 1;
        break;
    }

    freeaddrinfo(ai_result);
    if (!connect_success) {
        close(sockfd);
        error("failed to connect");
    }

    char request[1024];
    snprintf(request,
             sizeof(request),
             "GET "
             "%s"
             "?info_hash=%s"
             "&peer_id=%s"
             "&port=%s"
             "&uploaded=0"
             "&downloaded=0"
             "&left=%zu"
             "&compact=1"
             " HTTP/1.1\r\n"
             "Host: %s\r\n"
             "User-Agent: codecrafters-bittorrent/1.0\r\n"
             "\r\n",
             path,
             hash_urlencoded,
             qpeer_id,
             qport,
             torrent_file_size,
             host);

    size_t total = 0;
    size_t request_len = strlen(request);
    while (total < request_len) {
        ssize_t bytes = send(sockfd, request + total, request_len - total, 0);
        if (bytes < 0) {
            close(sockfd);
            error("send failed");
        }
        total += bytes;
    }

    char buffer[4096];
    ssize_t bytes_read;
    while ((bytes_read = recv(sockfd, buffer, sizeof(buffer) - 1, 0)) < 0) {
        buffer[bytes_read] = '\0';
    }

    if (bytes_read < 0) {
        close(sockfd);
        error("recv failed");
    }

    char *header_end = "\r\n\r\n";
    char *response_body = strstr(buffer, header_end);
    response_body += 4;

    struct bdict tracker_dict = {0};
    bdecode(&arena, (belement_t *)&tracker_dict, response_body);
    if (0 == strcmp(tracker_dict.kvpairs[0].key->buffer, "failure reason")) {
        printf("tracker failure reason: %s\n",
               tracker_dict.kvpairs[0].element->byte_string.buffer);
    }
    else {
        struct bstr *bpeers = NULL;
        for (int i = 0; i < tracker_dict.length; i++) {
            if (0 == strcmp("peers", tracker_dict.kvpairs[i].key->buffer)) {
                bpeers = (struct bstr *)tracker_dict.kvpairs[i].element;
                break;
            }
        }

        if (bpeers == NULL) {
            return;
        }

        uint8_t *ptr = (uint8_t *)bpeers->buffer;
        while (*ptr != '\0') {
            char *delim = "";
            for (int b = 0; b < 4; b++) {
                printf("%s%u", delim, *ptr);
                delim = ".";
                ptr++;
            }
            printf(":%u",
                   (uint16_t)((*ptr) << 8) | (uint16_t)(*(ptr + 1) & 0xFF));
            printf("\n");
            ptr += 2;
        }
    }

    arena_destroy(&arena);
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
        struct strbuf sb = strbuf_init(1024 * 1024);
        char *string = bencode_stringify(&sb, bencode);
        printf("%s\n", string);
        strbuf_destroy(&sb);
    }
    else if (0 == strcmp(command, "peers")) {
        char *tracker_url = NULL;
        char *name = NULL;
        size_t length = 0;
        unsigned char info_hash[EVP_MAX_MD_SIZE];
        uint32_t info_hash_len = 0;
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

        printf("torrent file: %*s\n", (int)len, buffer);

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
                struct strbuf sb = strbuf_init(1024 * 64);

                bencode(&sb, (belement_t *)&info);

                OpenSSL_add_all_digests();
                const EVP_MD *md = EVP_get_digestbyname("SHA1");
                assert(md && "Failed to get SHA1 digest");
                EVP_MD_CTX *md_ctx = EVP_MD_CTX_create();
                EVP_DigestInit_ex(md_ctx, md, NULL);
                EVP_DigestUpdate(md_ctx, sb.buffer, sb.length);
                EVP_DigestFinal_ex(md_ctx, info_hash, &info_hash_len);
                info_hash[info_hash_len] = '\0';
                EVP_MD_CTX_destroy(md_ctx);
            }
        }

        tracker_request(tracker_url, read, info_hash, info_hash_len);
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
                struct strbuf sb = strbuf_init(1024 * 64);

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

                strbuf_destroy(&sb);
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
