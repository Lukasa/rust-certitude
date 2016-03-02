#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

extern uint32_t validate_cert_chain(uint8_t **encoded_certs,
                                    size_t *cert_sizes,
                                    size_t cert_count,
                                    const char *hostname);

#define CERT_COUNT 3
#define BUFFER_SIZE 4096

static char *leaf_cert = "../rust-certitude/fixtures/certifi/leaf.crt";
static char *first_intermediate = "../rust-certitude/fixtures/certifi/first-intermediate.crt";
static char *second_intermediate = "../rust-certitude/fixtures/certifi/second-intermediate.crt";
static char *correct_hostname = "certifi.io";
static char *incorrect_hostname = "certitude.io";



int main(int argc, char **argv) {
    char *filenames[CERT_COUNT] = {leaf_cert, first_intermediate, second_intermediate};
    uint8_t *certs[CERT_COUNT];
    size_t sizes[CERT_COUNT];
    uint32_t validation_result;

    // Read the certs.
    for (int i = 0; i < CERT_COUNT; i++) {
        FILE *file = NULL;
        uint8_t *cert_data = malloc(BUFFER_SIZE);
        size_t read_count;

        assert(cert_data != NULL);

        file = fopen(filenames[i], "rb");
        if (file == NULL) {
            fprintf(stderr, "Cannot open file %d!\n", i);
            exit(1);
        }

        read_count = fread(cert_data, 1, BUFFER_SIZE, file);
        if (read_count == BUFFER_SIZE) {
            fprintf(stderr, "File too long!\n");
            exit(1);
        }

        fclose(file);

        // Resize the buffer, we don't need the extra data.
        cert_data = realloc(cert_data, read_count);
        assert(cert_data != NULL);

        certs[i] = cert_data;
        sizes[i] = read_count;
    }

    // Just test two basic cases: one with the correct hostname, one without.
    validation_result = validate_cert_chain(certs, sizes, CERT_COUNT, correct_hostname);
    if (validation_result == 1) {
        printf("Correct validated chain.\n");
    } else {
        printf("Unexpected result, code %d\n", validation_result);
        exit((int)validation_result);
    }

    validation_result = validate_cert_chain(certs, sizes, CERT_COUNT, incorrect_hostname);
    if (validation_result == 2) {
        printf("Correctly rejected hostname.\n");
    } else {
        printf("Unexpected result, code %d\n", validation_result);
        exit((int)validation_result);
    }

    // Do some cleanup.
    for (int j = 0; j < CERT_COUNT; j++) {
        free(certs[j]);
    }

    return 0;
}
