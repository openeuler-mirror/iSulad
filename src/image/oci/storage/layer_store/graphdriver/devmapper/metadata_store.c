
#include <pthread.h>
#include "metadata_store.h"
#include "utils.h"
#include "log.h"

typedef struct {
    map_t *map;  // map string image_devmapper_device_info*   key string will be strdup  value ptr will not
    pthread_rwlock_t rwlock;
} metadata_store_t;

static metadata_store_t *g_metadata_store = NULL;

/* metadata store map kvfree */
static void metadata_store_map_kvfree(void *key, void *value)
{
    free(key);

    free_image_devmapper_device_info((image_devmapper_device_info *)value);
}

/* metadata store free */
static void metadata_store_free(metadata_store_t *store)
{
    if (store == NULL) {
        return;
    }
    map_free(store->map);
    store->map = NULL;
    pthread_rwlock_destroy(&(store->rwlock));
    free(store);
}

/* metadata store new */
static metadata_store_t *metadata_store_new(void)
{
    int ret;
    metadata_store_t *store = NULL;

    store = util_common_calloc_s(sizeof(metadata_store_t));
    if (store == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    ret = pthread_rwlock_init(&(store->rwlock), NULL);
    if (ret != 0) {
        ERROR("Failed to init memory store rwlock");
        free(store);
        return NULL;
    }
    store->map = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, metadata_store_map_kvfree);
    if (store->map == NULL) {
        ERROR("Out of memory");
        goto error_out;
    }
    return store;
error_out:
    metadata_store_free(store);
    return NULL;
}

int metadata_store_init(void)
{
    g_metadata_store = metadata_store_new();
    if (g_metadata_store == NULL) {
        return -1;
    }
    return 0;
}

// 需要malloc，然后存入map，顶层调用已被释放
bool metadata_store_add(const char *hash, image_devmapper_device_info *device)
{
    bool ret = false;

    if (pthread_rwlock_wrlock(&g_metadata_store->rwlock)) {
        ERROR("devmapper: lock metadata store failed");
        return false;
    }

    // 如果key不存在则insert
    ret = map_replace(g_metadata_store->map, (void *)hash, (void *)device);
    if (pthread_rwlock_unlock(&g_metadata_store->rwlock)) {
        ERROR("devmapper: unlock metadata store failed");
        return false;
    }
    return ret;
}

image_devmapper_device_info *metadata_store_get(const char *hash)
{
    return NULL;
}

bool metadata_store_remove(const char *hash)
{
    return true;
}