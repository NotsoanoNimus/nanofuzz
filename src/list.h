/*
 * list.h
 *
 * Simple linked-list implementation.
 *
 */

#ifndef _FUZZ_LIST_H
#define _FUZZ_LIST_H

#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

// Macro definition to simplify the process of fetching an item from a linked list.
#define GET_FROM_LIST_AS_TYPE( list, type, name, propertyoffset, wherevalue, valuesize ) \
    type* name = (type*)((List__get_node(list, propertyoffset, wherevalue, valuesize))->node);



// Define a linked list's node definitions.
typedef struct _linked_list_node_t {
    void* node;
    struct _linked_list_node_t* next;
} __attribute__((__packed__)) ListNode_t;

typedef struct _linked_list_t List_t;

// List manipulation: Create, Destroy, Clear (Empty), & Reverse.
List_t* List__new( size_t max_size );
void List__delete( List_t* list );
void List__clear( List_t* list );
List_t* List__reverse( List_t* list );

// Get the amount of nodes in the list.
size_t List__get_count( List_t* list );
// Get the maximum amount of nodes allowed for a given list.
size_t List__get_max_count( List_t* list );

// Get the position of a certain node with the set ptr.
int List__index_of( List_t* list, void* node );

// List node manipulation, adding and removal.
bool List__add_node( List_t* list, void* node );
ListNode_t* List__drop_node( List_t* list, ListNode_t* node );

// Get a list node using the specified property at the given offset of the given size and with the given value.
ListNode_t* List__get_node( List_t* list, int node_property_offset, void* property_value, size_t property_size );
// Get the node at the listed index from the head of the list.
ListNode_t* List__get_index_from_head( List_t* p_list, size_t index );

// Get placemarkers from the list from the heap.
ListNode_t* List__get_head( List_t* list );
ListNode_t* List__get_tail( List_t* list );



#endif   /* _FUZZ_LIST_H */
