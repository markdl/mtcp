/*! @file linked_list.h 
 * @brief Includes functions to create, manipulate and destroy linked lists
 *
 * The linked list is a generic list and can accepts any type of data. However the user must use appropriate type casting to prevent undefined behaviour
 */

#ifndef SHELL_LINKED_LIST_H_
#define SHELL_LINKED_LIST_H_

/*! @typedef linked_list_t
 * @brief A linked_list_t object maintains a linked list of items that can be appended to.
 */

typedef struct linked_list *linked_list_t;

/*! @typedef linked_list_iter_t
 *
 * @brief A linked_list_iter_t object maintains a reference to a given linked_list_t and
 * next position of the iterator in the list, which can be used to traverse the
 * list of items inside the linked list.
 */

typedef struct linked_list_iter *linked_list_iter_t;

/*! @fn linked_list_t linked_list_create()
 *
 * @brief Create and return new linked_list_t object. NULL is returned if malloc fails.
 * @warning New struct MUST BE FREED USING linked_list_free(). 
 *
 * @return A linked_list_t pointer to a linked_list struct, or NULL if malloc fails.
 */

linked_list_t linked_list_create();

/*! @fn void linked_list_free(linked_list_t linked_list, void (*free_item)(void *item))
 *
 * @brief Frees the linked_list struct and any items inside it using any non-NULL
 * function pointer to a free function for the type of items in it.
 *
 * @memberof linked_list
 *
 * @param linked_list The linked_list_t to be freed
 * @param free_item Optional (non-NULL) function pointer to use to free the items
 *
 * @return void
 */

void linked_list_free(linked_list_t linked_list, void (*free_item)(void *));

/*! @fn void linked_list_free_with_args(linked_list_t linked_list, void (*free_item)(void *, void *), void *args)
 *
 * @brief Frees the linked_list struct and any items inside it using any non-NULL function pointer to a free function
 * for the type of items in it. This function extends linked_list_free by allowing an additional pointer to args to be
 * passed into the given to the free_item function as the second parameter.
 *
 * @memberof linked_list
 *
 * @param linked_list The linked_list_t to be freed
 * @param free_item Optional (non-NULL) function pointer to use to free the items
 *
 * @return void
 */

void linked_list_free_with_args(linked_list_t linked_list, void (*free_item)(void *, void *), void *args);

/*! @fn int linked_list_append(linked_list_t linked_list, void *item)
 *
 * @brief Adds the given item to the end of the given linked list.
 *
 * @memberof linked_list
 *
 * @param linked_list The linked_list_t to add the item to
 * @param item The item to add
 *
 * @return 0 if success, -1 if malloc fails to create item_node struct
 */

int linked_list_append(linked_list_t linked_list, void *item);

/*! @fn int linked_list_prepend(linked_list_t linked_list, void *item)
 *
 * @brief Adds the given item to the beginning of the given linked list.
 *
 * @memberof linked_list
 *
 * @param linked_list The linked_list_t to add the item to
 * @param item The item to add
 *
 * @return 0 if success, -1 if malloc fails to create item_node struct
 */

int linked_list_prepend(linked_list_t linked_list, void *item);

/*! @fn void *linked_list_remove(linked_list_t linked_list, int index)
 *
 * @brief Removes the item at the given index from the linked list and returns it.
 *
 * @memberof linked_list
 * 
 * @param linked_list The linked_list_t to remove the item from the linked_list
 * @param index The index of the item to be removed
 *
 * @return the void pointer to the item. Returns NULL if the given index is out of bounds. Note: NULL items can be
 * inserted into the list, so a NULL return here might not be indicative of an index out of bounds.
 */

void *linked_list_remove(linked_list_t linked_list, int index);

/*! @fn void linked_list_free_items(linked_list_t linked_list, int *indices, int num_indices, void (*free_item)(void *))
 * 
 * @brief Removes and frees the items that exist at each index given as a sorted array of ints.
 * 
 * Note : Any index less than or equal to the previous index or greater than or equal to the
 * length of the given linked list will be ignored.
 *
 * @memberof linked_list
 *
 * @param linked_list The linked_list_t to remove the items from
 * @param indices The sorted array of indices to remove and free from the given list
 * @param num_indices the number of indices in the given array
 * @param free_item optional (non-NULL) function pointer to use to free the items
 *
 * @return void
 */

void linked_list_free_items(linked_list_t linked_list, int *indices, int num_indices, void (*free_item)(void *));

/*! @fn int linked_list_length(linked_list_t linked_list)
 *
 * @brief Returns the number of items inside the given linked_list.
 *
 * @memberof linked_list
 *
 * @param linked_list The linked_list_t
 *
 * @return The number of items within the linked_list
 */

int linked_list_length(linked_list_t linked_list);

/*! @fn void *linked_list_get(linked_list_t linked_list, int index)
 *
 * @brief Returns the item at the given index within the linked_list, or -1 if the
 * index is out of bounds.
 *
 * @memberof linked_list
 *
 * @param linked_list The linked_list_t to retrieve the item from, and
 * @param index       The index of the item to retrieve
 *
 * @return The item at the given index
 */

void *linked_list_get(linked_list_t linked_list, int index);

/*! @fn void *linked_list_get_last(linked_list_t linked_list)
 *
 * @brief Returns the last item within the linked_list, or -1 if list is empty.
 *
 * @memberof linked_list
 *
 * @param linked_list The linked_list_t to retrieve the item from
 *
 * @return The last item in the list
 */

void *linked_list_get_last(linked_list_t linked_list);

/*! @fn linked_list_iter_t linked_list_get_iter(linked_list_t linked_list)
 *
 * @brief Returns a linked_list_iter_t set at the beginning of the given linked_list_t.
 * @warning The linked_list_iter_t MUST BE FREED USING linked_list_iter_free.
 *
 * @memberof linked_list
 *
 * @param linked_list The linked_list_t to iterate over
 *
 * @return The new linked_list_iter_t
 */

linked_list_iter_t linked_list_get_iter(linked_list_t linked_list);

/*! @fn void linked_list_iter_free(linked_list_iter_t iter)
 *
 * @brief Frees the given linked_list_iter_t.
 *
 * @memberof linked_list
 *
 * @param iter The linked_list_iter_t to be freed
 *
 * @return void
 */

void linked_list_iter_free(linked_list_iter_t iter);

/*! @fn int linked_list_iter_has_next(linked_list_iter_t iter)
 *
 * @brief Checks if the given iter has anymore items it can return if
 * linked_list_iter_next was called.
 *
 * @memberof linked_list_iter
 *
 * @param iter The linked_list_iter_t to check
 * @return TRUE if the linked_list_iter_t has more items to return, or
 *           FALSE if the linked_list_iter_t has reached the end of the list
 */

int linked_list_iter_has_next(linked_list_iter_t iter);

/*! @fn void *linked_list_iter_next(linked_list_iter_t iter)
 *
 * @brief Returns the next item in the linked list at the index maintained by the given
 * iterator.
 *
 * @memberof linked_list_iter
 *
 * @param iter The linked_list_iter_t to maintain the index
 *
 * @return A void pointer to the item inside the linked list
 */

void *linked_list_iter_next(linked_list_iter_t iter);

#endif // SHELL_LINKED_LIST_H_
