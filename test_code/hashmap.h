#ifndef PENNOS_HASHMAP_H
#define PENNOS_HASHMAP_H

#include "linked_list.h"

/*! @struct hashmap
 *
 * @brief A hashmap struct maintains a mapping of any key object to any other object, such
 * that the hasher (and equals) functions given during construction can properly hash (or compare)
 * the given key object. If equals returns true for any given pair of keys, the hasher function
 * must also return the same hash value for the same pair of keys.
 */

typedef struct hashmap {
    unsigned int (*hasher)(void *); /*!< Pointer to a function that accepts the key and returns a hash */
    int (*equals)(void *, void *); /*!< Pointer to a function that returns 1 iff key1 == key2 */
    unsigned int size; /*!< The number of elements in the hashmap */
    unsigned int bucket_count; /*!< The number of buckets in the hashmap */
    linked_list_t *buckets; /*!< buckets[i] = linked list of hashmap_entry_t with keys that hash to i */
} * hashmap_t;


/*! @fn hashmap_create
 *
 * @brief Creates the hashmap struct and initializes its values.
 *
 * @param hasher pointer to a function that takes a void pointer to a key object and returns an unsigned long
 * @param equals pointer to a function that takes void pointers to two key objects and returns true if they are equal
 *
 * @return pointer to the hashmap struct, or NULL if malloc fails
 */

hashmap_t hashmap_create(unsigned int (*hasher)(void *), int (*equals)(void *, void *));


/*! @fn hashmap_free
 *
 * @brief Frees the given hashmap struct and all of its entries given non-NULL function pointers for freeing the keys
 * and freeing their values.
 *
 * @param map the hashmap_t to free
 * @param free_key pointer to a function that frees the memory allocated for a key object
 * @param free_value pointer to a function that frees the memory allocated for a value object
 */

void hashmap_free(hashmap_t map, void (*free_key)(void *), void (*free_value)(void *));


/*! @fn hashmap_get
 *
 * @brief Returns the value that is mapped to the given key object, or NULL if the hashmap does not contain the key.
 *
 * @return the object mapped to the given key, or NULL if the hashmap does not contain the key.
 */

void *hashmap_get(hashmap_t map, void *key);


/*! @fn hashmap_find
 *
 * @brief Returns the value that is mapped to the given key object, or NULL if the hashmap does not contain the key.
 *        If given found pointer is not null, found will be set to 1 if an object was mapped to the key. This can
 *        be used to check if the key exists but is mapped to a NULL object.
 *
 * @return the object mapped to the given key, or NULL if the hashmap does not contain the key.
 */

void *hashmap_find(hashmap_t map, void *key, int *found);


/*! @fn hashmap_get_keys
 *
 * @brief Returns an array of pointers to the keys in the hashmap. The number of keys in the array is equal to the
 * size of the hashmap.
 *
 * @return the object mapped to the given key, or NULL if the hashmap does not contain the key.
 */

const void **hashmap_get_keys(hashmap_t map);


/*! @fn hashmap_is_empty
 *
 * @brief Returns 1 if the map is empty, 0 otherwise.
 *
 * @return 1 if the map is empty, 0 otherwise.
 */

int hashmap_is_empty(hashmap_t map);


/*! @fn hashmap_put
 *
 * @brief Associates the given key with the given value in the map.
 *
 * @return the value originally associated with the given key
 */

void *hashmap_put(hashmap_t map, void *key, void *value);


/*! @fn hashmap_remove
 *
 * @brief Removes the mapping for the given key if it exists. If given key does not point to the same instance of the
 * key given when this key was first inserted, then a non-NULL function pointer may be given to free the key with.
 *
 * @return the value originally associated with the given key
 */

void *hashmap_remove(hashmap_t map, void *key, void (*free_key)(void *));


/*! @fn hashmap_size
 *
 * @brief Returns the number of key-value mappings in the map.
 *
 * @return the number of key-value mappings in the map
 */

unsigned int hashmap_size(hashmap_t map);


/*! @fn hashmap_default_int_hasher
 *
 * @brief Default hasher for an integer
 *
 * @param value pointer to the integer value to hash
 *
 * @return a hash value generated from the given integer
 */

unsigned int hashmap_default_int_hasher(int *value);


/*! @fn hashmap_default_string_hasher
 *
 * @brief Default hasher for a string
 *
 * @param string pointer to the string to hash
 *
 * @return a hash value generated from the given string
 */

unsigned int hashmap_default_string_hasher(char *string);


/*! @fn hashmap_default_int_equals
 *
 * @brief Default int comparator
 *
 * @param v1 pointer to the first integer value
 * @param v2 pointer to the second integer value
 *
 * @return 1 if v1 and v2 have equal values, 0 otherwise
 */

int hashmap_default_int_equals(int *v1, int *v2);


/*! @fn hashmap_default_string_equals
 *
 * @brief Default comparator for a string
 *
 * @param str1 pointer the first string
 * @param str2 pointer the second string
 *
 * @return 1 if str1 has the same sequence of characters as str2
 */

int hashmap_default_string_equals(char *str1, char *str2);


#endif //PENNOS_HASHMAP_H
