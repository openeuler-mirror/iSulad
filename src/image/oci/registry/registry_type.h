#ifndef _IMAGE_REGISTRY_TYPE_H
#define _IMAGE_REGISTRY_TYPE_H

#include <stdint.h>
#include <time.h>

// 8 is enough for challenge, usually only one challenge is provided.
#define CHALLENGE_MAX 8

typedef struct {
    char *schema;
    char *realm;
    char *service;
    char *cached_token;
    time_t expires_time;
} challenge;

typedef struct {
    char *media_type;
    size_t size;
    char *digest;
    // Downloaded file path
    char *file;
} manifest_blob;

typedef struct {
    char *media_type;
    size_t size;
    char *digest;
    // Downloaded file path
    char *file;
} config_blob;

typedef struct {
    char *media_type;
    // blob size
    size_t size;
    // compressed digest
    char *digest;
    // uncompressed digest
    char *diff_id;
    // use chainID as layerID
    char *chain_id;
    // Downloaded file path
    char *file;
    // already exist on local store
    char *already_exist;
} layer_blob;

typedef struct {
    char *full_name;
    char *host;
    char *name;
    char *tag;

    char *auth_file_path;
    bool auth_loaded;
    char *username;
    char *password;

    char *use_decrypted_key;
    char *cert_path;
    bool cert_loaded;
    char *ca_file;
    char *cert_file;
    char *key_file;

    char *blobpath;
    char *protocol;
    bool skip_tls_verify;
    bool already_ping;
    char *scope;
    challenge challenges[CHALLENGE_MAX];
    // This is temporary field. Once http request is performed, it is cleared
    char **headers;

    // Image blobs downloaded
    manifest_blob manifest;
    config_blob config;
    layer_blob *layers;
    size_t layers_len;
} pull_descriptor;

void free_pull_desc(pull_descriptor *desc);

#endif
