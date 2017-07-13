#include <stdio.h>
#include <stdlib.h>
#include <float.h>
#include <error.h>
#include <string.h>

#include "hashmap.h"

#define HASHMAP_INIT_BUCKET_COUNT 20
#define HASHMAP_MAX_LOAD_FACTOR 0.75
#define HASHMAP_MIN_LOAD_FACTOR 0.25
#define HASHMAP_GROWTH_RATE 2.0

#define HASHMAP_COMPUTE_BUCKET(hasher, key, size) hasher(key) % size


/*! @struct hashmap_entry_t
 *
 * @brief Internal struct for maintaining the key/value pairs contained within the hashmap.
 */

typedef struct hashmap_entry {
    void *key;
    void *value;
} *hashmap_entry_t;


/*! @struct hashmap_entry_free_functions
 *
 * @brief Internal struct for passing a pair of free functions for freeing the key and value in a hashmap_entry_t
 */
struct hashmap_entry_free_functions {
    void (*free_key)(void *);

    void (*free_value)(void *);
};

/* Prototypes for private functions defined at the bottom */
hashmap_entry_t hashmap_get_entry(hashmap_t map, void *key, int *position);

int hashmap_resize(hashmap_t map, unsigned int size);

void hashmap_entry_free(hashmap_entry_t entry, struct hashmap_entry_free_functions *funcs);


hashmap_t hashmap_create(unsigned int (*hasher)(void *), int (*equals)(void *, void *)) {
    hashmap_t map = (hashmap_t) malloc(sizeof(struct hashmap));
    if (map == NULL) {
        perror("malloc");
        return NULL;
    }

    map->bucket_count = HASHMAP_INIT_BUCKET_COUNT;
    map->equals = equals;
    map->hasher = hasher;
    map->size = 0;
    map->buckets = (linked_list_t *) calloc(map->bucket_count, sizeof(linked_list_t));
    if (map->buckets == NULL) {
        perror("malloc");
        free(map);
        return NULL;
    }

    return map;
}


void hashmap_free(hashmap_t map, void (*free_key)(void *), void (*free_value)(void *)) {
    struct hashmap_entry_free_functions funcs;
    funcs.free_key = free_key;
    funcs.free_value = free_value;

    for (int bucket = 0; bucket < map->bucket_count; bucket++) {
        if (map->buckets[bucket] != NULL) {
            linked_list_free_with_args(map->buckets[bucket], (void (*)(void *, void *)) hashmap_entry_free, &funcs);
        }
    }

    free(map->buckets);
    free(map);
}


void *hashmap_get(hashmap_t map, void *key) {
	return hashmap_find(map, key, NULL);
}


void *hashmap_find(hashmap_t map, void *key, int *found) {
    hashmap_entry_t entry = hashmap_get_entry(map, key, NULL);
	 if (found != NULL)
		 *found = entry != NULL;
    if (entry != NULL) {
        return entry->value;
    } else {
        return NULL;
    }
}



const void **hashmap_get_keys(hashmap_t map) {
    const void **keys = (const void **) calloc(sizeof(void *), map->size);
    if (keys == NULL) {
        perror("malloc keys");
        return NULL;
    }

    long key_idx = 0;
    for (int i = 0; i < map->bucket_count && key_idx < map->size; i++) {
        if (map->buckets[i] != NULL && linked_list_length(map->buckets[i]) > 0) {
            linked_list_iter_t iter = linked_list_get_iter(map->buckets[i]);
            while (linked_list_iter_has_next(iter)) {
                hashmap_entry_t entry = linked_list_iter_next(iter);
                keys[key_idx++] = entry->key;
            }
            linked_list_iter_free(iter);
        }
    }

    if (key_idx != map->size) {
        fprintf(stderr, "Critical error: hashmap_get_keys returned a different number of keys than the map's size\n");
    }

    return keys;
}


int hashmap_is_empty(hashmap_t map) {
    return map->size == 0;
}


void *hashmap_put(hashmap_t map, void *key, void *value) {
    // Resize if adding item would push the capacity beyond the load factor (might not actually add a new entry though)
    if ((map->size + 1) / (float) map->bucket_count >= HASHMAP_MAX_LOAD_FACTOR - FLT_EPSILON) {
        int success = hashmap_resize(map, (unsigned int) (map->bucket_count * HASHMAP_GROWTH_RATE));
        if (!success) {
            perror("hashmap_resize");
            return NULL;
        }
    }

    // If bucket list exists, search and replace value if it exists, otherwise create a new bucket list
    unsigned int bucket = HASHMAP_COMPUTE_BUCKET(map->hasher, key, map->bucket_count);
    if (map->buckets[bucket] != NULL) {
        hashmap_entry_t entry = hashmap_get_entry(map, key, NULL);
        if (entry != NULL) {
            void *old_value = entry->value;
            entry->value = value;
            return old_value;
        } // Doesn't exist, fall through to add entry
    } else {
        map->buckets[bucket] = linked_list_create();
        if (map->buckets[bucket] == NULL) {
            return NULL;
        }
    }

    // Key did not exist, create and add a new entry and return NULL
    hashmap_entry_t entry = (hashmap_entry_t) malloc(sizeof(struct hashmap_entry));
    if (entry == NULL) {
        perror("malloc");
        return NULL;
    }
    entry->key = key;
    entry->value = value;
    linked_list_append(map->buckets[bucket], entry);
    map->size++;

    return NULL;
}


void *hashmap_remove(hashmap_t map, void *key, void (*free_key)(void *)) {
    int position;
    hashmap_entry_t entry = hashmap_get_entry(map, key, &position);
    if (entry == NULL) {
        return NULL;
    }

    void *value = entry->value;
    unsigned int bucket = HASHMAP_COMPUTE_BUCKET(map->hasher, key, map->bucket_count);
    linked_list_remove(map->buckets[bucket], position);
    if (free_key != NULL) {
        free_key(entry->key);
    }
    free(entry);

    map->size--;
    if (map->bucket_count > HASHMAP_INIT_BUCKET_COUNT &&
        map->size / (float) map->bucket_count <= HASHMAP_MIN_LOAD_FACTOR + FLT_EPSILON) {
        // Can still progress if unsuccessful
        hashmap_resize(map, (unsigned int) (map->bucket_count / HASHMAP_GROWTH_RATE));
    }

    return value;
}


unsigned int hashmap_size(hashmap_t map) {
    return map->size;
}


/* DEFAULT HASHER AND EQUALS FUNCTIONS */

unsigned int hashmap_default_int_hasher(int *value) {
    return (unsigned int) *value;
}


unsigned int hashmap_default_string_hasher(char *string) {
    unsigned int hash = 0;
    int length = strlen(string);
    for (int i = 0; i < length; i++) {
		 hash = 31 * hash + string[i];
    }

    return hash;
}


int hashmap_default_int_equals(int *v1, int *v2) {
    return *v1 == *v2;
}


int hashmap_default_string_equals(char *str1, char *str2) {
    return strcmp(str1, str2) == 0;
}


/* PRIVATE FUNCTIONS */

// Return entry matching the given key, or NULL if key doesn't exist
hashmap_entry_t hashmap_get_entry(hashmap_t map, void *key, int *position) {
    unsigned int bucket = HASHMAP_COMPUTE_BUCKET(map->hasher, key, map->bucket_count);
    if (map->buckets[bucket] == NULL) {
        return NULL;
    }

    int i = 0;
    linked_list_iter_t iter = linked_list_get_iter(map->buckets[bucket]);
    hashmap_entry_t match = NULL;
    while (linked_list_iter_has_next(iter)) {
        hashmap_entry_t entry = linked_list_iter_next(iter);
        if (map->equals(entry->key, key)) {
            match = entry;
            break;
        }
        i++;
    }
    linked_list_iter_free(iter);

    if (position != NULL) {
        *position = i;
    }

    return match;
}


// Return 0 if malloc fails, otherwise resize, rehash and return 1
int hashmap_resize(hashmap_t map, unsigned int size) {
    linked_list_t *tmp = (linked_list_t *) calloc(size, sizeof(linked_list_t));
    if (tmp == NULL) {
        perror("malloc");
        return 0;
    }

    // Attempt to rehash the keys of every entry and add them to the new buckets, allocating the buckets when needed
    int aborted = 0;
    for (int bucket = 0; bucket < map->bucket_count; bucket++) {
        if (map->buckets[bucket] != NULL) {
            linked_list_iter_t iter = linked_list_get_iter(map->buckets[bucket]);
            while (linked_list_iter_has_next(iter)) {
                hashmap_entry_t entry = linked_list_iter_next(iter);
                unsigned int new_bucket = HASHMAP_COMPUTE_BUCKET(map->hasher, entry->key, size);

                // If new bucket doesn't exist, create it
                if (tmp[new_bucket] == NULL) {
                    tmp[new_bucket] = linked_list_create();
                    if (tmp[new_bucket] == NULL) {
                        perror("malloc");
                        aborted = 1;
                        break;
                    }
                }

                linked_list_append(tmp[new_bucket], entry);
            }
            if (aborted) {
                break;
            }
			
			linked_list_iter_free(iter);
        }
    }

    // We cannot move forward if allocating a single new bucket failed, thus we must be sure to free up any
    // new buckets we might have successfully allocated before the failure, before freeing the tmp bucket list.
    if (aborted) {
        for (int bucket = 0; bucket < size; bucket++) {
            if (tmp[bucket] != NULL) {
                linked_list_free(tmp[bucket], NULL);
            }
        }
        free(tmp);
        return 0;
    }

    // Succeeded in resizing, so remove the old buckets and move tmp into the struct
    for (int bucket = 0; bucket < map->bucket_count; bucket++) {
        if (map->buckets[bucket] != NULL) {
            linked_list_free(map->buckets[bucket], NULL); // We don't want to actually free the entries, just the list
        }
    }
    free(map->buckets);
    map->buckets = tmp;
    map->bucket_count = size;

    return 1;
}


void hashmap_entry_free(hashmap_entry_t entry, struct hashmap_entry_free_functions *funcs) {
    if (funcs->free_key != NULL) {
        funcs->free_key(entry->key);
    }
    if (funcs->free_value != NULL && entry->value != NULL) {
        funcs->free_value(entry->value);
    }
    free(entry);
}
