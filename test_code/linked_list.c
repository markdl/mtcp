
/*! @file linked_list.c 
 *
 * @brief Implements functions to create, destroy and manipulate linked lists
 */

#include <malloc.h>

#include "linked_list.h"

/*! @struct item_node
 *
 * @brief An item_node struct holds a value and a pointer to the next item in the list.
 */

struct item_node {
  void *item; //!< pointer to the data to be stored in the linked list
  struct item_node *next; //!< pointer to the next node in the linked list
};

/*! @struct linked_list
 *
 * @brief A linked_list struct maintains a linked list of command structs that can be
 * prepended and appended to.
 */

struct linked_list {
  int length; //!< length of the linked list
  struct item_node *first; //!< the head of the linked list
  struct item_node *last;//!< the tail of the linked list
};

/*! @struct linked_list_iter
 *
 * @brief A linked_list_iter struct maintains a pointer to the next item_node from a
 * linked_list to return the next item from.
 */

struct linked_list_iter {
  struct item_node *next;//!< pointer to the next item in the linked list
};

/*!
 * Create and return new linked_list_t object. New struct MUST BE FREED USING
 * linked_list_free(). NULL is returned if malloc fails.
 *
 */

linked_list_t linked_list_create() {
    linked_list_t list = (linked_list_t) malloc(sizeof(struct linked_list));
    if (list != NULL) {
        list->length = 0;
        list->first = NULL;
        list->last = NULL;
    } else {
        perror("linked_list struct malloc");
    }
    return list;
}

/*!
 * Frees the linked_list struct and optionally any items inside it using any non-NULL
 * function pointer to a free function for the type of items in it.
 *
 */

void linked_list_free(linked_list_t linked_list, void (*free_item)(void *)) {
    for (struct item_node *curr = linked_list->first;
         curr != NULL;) {
        if (free_item != NULL) {
            (*free_item)(curr->item);
        }
        struct item_node *next = curr->next;
        free(curr);
        curr = next;
    }

    free(linked_list);
}

/*!
 * Frees the linked_list struct and optionally any items inside it using any non-NULL
 * function pointer to a free function for the type of items in it and an optional pointer to
 * any data to pass into the free function as the second parameter.
 *
 */

void linked_list_free_with_args(linked_list_t linked_list, void (*free_item)(void *, void *), void *args) {
    for (struct item_node *curr = linked_list->first;
         curr != NULL;) {
        if (free_item != NULL) {
            (*free_item)(curr->item, args);
        }
        struct item_node *next = curr->next;
        free(curr);
        curr = next;
    }

    free(linked_list);
}

/*!
 * Adds the given item to the end of the given linked list.
 */

int linked_list_append(linked_list_t linked_list, void *item) {
    // Create and populate node for linked list
    struct item_node *node = (struct item_node *) malloc(sizeof(*node));
    if (node == NULL) {
        return -1;
    }
    node->item = item;
    node->next = NULL;

    // Add the node to the linked list
    if (linked_list->length == 0) {
        linked_list->first = node;
        linked_list->last = node;
    } else {
        linked_list->last->next = node;
        linked_list->last = node;
    }
    linked_list->length++;

    return 0;
}

/*!
 * Adds the given item to the beginning of the given linked list.
 */

int linked_list_prepend(linked_list_t linked_list, void *item) {
    // Create and populate node for linked list
    struct item_node *node = (struct item_node *) malloc(sizeof(*node));
    if (node == NULL) {
        return -1;
    }
    node->item = item;
    node->next = linked_list->first;

    linked_list->first = node;

    if (linked_list->length == 0) {
        linked_list->last = node;
    }
    linked_list->length++;

    return 0;
}

/*!
 * Removes the item at the given index from the linked list and returns it.
 * Returns NULL if the given index is out of bounds. Note: NULL items can be
 * inserted into the list, so a NULL return here might not be indicative of an
 * index out of bounds.
 *
 */

void *linked_list_remove(linked_list_t linked_list, int index) {
    if (index < 0 || index >= linked_list->length) {
        return NULL;
    }

    // Get the item_node at the given index, and the item_node before it
    struct item_node *prev = linked_list->first;
    struct item_node *curr = linked_list->first->next;
    for (int i = 1; i < index; prev = curr, curr = curr->next, i++);

    // Now retrieve the item from the item_node, free the item_node, and
    // update length as well as the first and last pointers if necessary
    void *item = prev->item;
    if (index == 0) { // removing first item
        linked_list->first = curr;
        free(prev);
    } else {
        item = curr->item;
        prev->next = curr->next;
        free(curr);
        if (linked_list->last == curr) { // removing last item
            linked_list->last = prev;
        }
    }

    linked_list->length--;

    return item;
}

/*!
 * Removes and frees the items that exist at each index given as a sorted array of ints.
 * Any index less than or equal to the previous index or greater than or equal to the
 * length of the given linked list will be ignored.
 */

void linked_list_free_items(linked_list_t linked_list, int *indices, int num_indices, void (*free_item)(void *)) {
    int length = linked_list->length;
    if (num_indices == 0 || length == 0) return;

    // Start from the second item, and begin removing items
    struct item_node *prev = linked_list->first;
    struct item_node *curr = linked_list->first->next;
    int last = 0; // If first index is 0, skip it and handle it later
    int curr_idx = 1;
    for (int i = 0; i < num_indices && curr != NULL; i++) {
        int index = indices[i];
        if (index <= last || index >= length) {
            continue;
        }
        last = index;

        if (curr_idx == index) {
            // Remove the current node
            prev->next = curr->next;
            linked_list->length--;
            if (curr == linked_list->last) {
                linked_list->last = prev;
            }
            struct item_node *next = curr->next;
            if (free_item != NULL) {
                free_item(curr->item);
            }
            free(curr);
            curr = next;
        } else {
            // Get the next node
            prev = curr;
            curr = curr->next;
        }

        curr_idx++;
    }

    // Now if the first index was 0, remove the first node
    if (indices[0] == 0) {
        linked_list_remove(linked_list, 0);
    }
}

/*!
 * Returns the number of items inside the given linked_list.
 *
 */

int linked_list_length(linked_list_t linked_list) {
    return linked_list->length;
}

/*!
 * Returns the item at the given index within the linked_list, or -1 if the
 * index is out of bounds.
 */

void *linked_list_get(linked_list_t linked_list, int index) {
    struct item_node *curr = linked_list->first;
    if (index != linked_list->length - 1) {
        for (int i = 0; i < index; curr = curr->next, i++);
    } else {
        curr = linked_list->last;
    }
    return curr->item;
}

/*!
 * Returns the last item within the linked_list, or -1 if list is empty.
 */

void *linked_list_get_last(linked_list_t linked_list) {
    return linked_list->last->item;
}

/*!
 * Returns a linked_list_iter_t set at the beginning of the given linked_list_t.
 * Note: The linked_list_iter_t MUST BE FREED USING linked_list_iter_free.
 */

linked_list_iter_t linked_list_get_iter(linked_list_t linked_list) {
    linked_list_iter_t iter = (linked_list_iter_t) malloc(sizeof(*iter));
    if (iter != NULL) {
        iter->next = linked_list->first;
    }
    return iter;
}

/*!
 * Frees the given linked_list_iter_t. Does not free the underlying linked list.
 *
 */

void linked_list_iter_free(linked_list_iter_t iter) {
    free(iter);
}

/*!
 * Checks if the given iter has anymore items it can return if
 * linked_list_iter_next was called.
 *
 */

int linked_list_iter_has_next(linked_list_iter_t iter) {
    return iter->next != NULL;
}

/*!
 * Returns the next item in the linked list at the index maintained by the given
 * iterator.
 *
 */

void *linked_list_iter_next(linked_list_iter_t iter) {
    void *item = iter->next->item;
    iter->next = iter->next->next;
    return item;
}
