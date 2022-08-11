/*
 * list.c
 *
 * Generic linked-list implementations.
 *
 */

#include "list.h"



// Define a generic linked list structure.
struct _linked_list_t {
    struct _linked_list_node_t* head;
    size_t max_size;
} __attribute__((__packed__));



// "Private" method to set the list's head node.
void __List__set_head( List_t* list, ListNode_t* val ) {
    if ( list == NULL )  return;
    list->head = val;
}


// Create a new linked-list object.
List_t* List__new( size_t max_size ) {
    List_t* x = (List_t*)calloc( 1, sizeof(List_t) );
    x->head = NULL;
    x->max_size = max_size;
    return x;
}

// Delete and destroy a linked-list object from the heap.
void List__delete( List_t* list ) {
    List__clear( list );
    if ( list != NULL )  free( list );
}

// Clear all items from a linked-list object.
void List__clear( List_t* list ) {
    if ( list == NULL )  return;

    ListNode_t* x = List__get_head( list );
    while ( x != NULL ) {
        ListNode_t* x_shadow = x->next;
        free( x );
        x = x_shadow;
    }

    __List__set_head( list, NULL );
}


// Get the amount of nodes in the linked-list object.
size_t List__get_count( List_t* list ) {
    size_t count = 0;
    for ( ListNode_t* x = List__get_head( list ); x != NULL; x = x->next )  count++;
    return count;
}


// Add an entry onto the end of a linked-list.
bool List__add_node( List_t* list, void* node ) {
    if ( list == NULL || node == NULL )  return false;

    if ( List__get_count( list ) >= list->max_size )  return false;

    ListNode_t* x = (ListNode_t*)calloc( 1, sizeof(ListNode_t) );
    x->node = node;
    x->next = List__get_head( list );
    __List__set_head( list, x );

    return true;
}

// Delete an entry from within a linked list.
ListNode_t* List__drop_node( List_t* list, ListNode_t* node ) {
    if ( list == NULL || node == NULL )  return NULL;

    ListNode_t* x = List__get_head( list );
    if ( x == NULL ) {
        // Empty list; nothing to remove.
        return NULL;
    } else if ( x == node && x->next == NULL ) {
        // When the node to remove is the only list item, free it and set the head to null.
        free( node );
        __List__set_head( list, NULL );
        return NULL;
    }

    // Automatically move to the next node after pointing a 'shadow' to the head node.
    ListNode_t* prev_node = List__get_head( list );
    x = x->next;
    while ( x != NULL ) {
        if ( x == node ) {
            // Point the previous node to the next node, thereby bridging OVER this list item and removing it.
            prev_node->next = x->next;
            free( x );
            return prev_node;
        }
        // When the node isn't found, keep going forward in the list.
        prev_node = x;
        x = x->next;
    }

    // If nothing was found matching the list node address provided, exit failure.
    return NULL;
}


// Get a list node using the specified property at the given offset of the given size and with the given value.
ListNode_t* List__get_node( List_t* list, int node_property_offset, void* property_value, size_t property_size ) {
    if ( property_value == NULL || property_size <= 0 )  return NULL;

    // For each node in the list, check the property value at the given offset against the provided comparator.
    for ( ListNode_t* x = List__get_head( list ); x != NULL; x = x->next ) {
        if ( memcmp( ((x->node)+node_property_offset), property_value, property_size ) == 0 )  return x;
    }

    // If no matching nodes were found, simply return a NULL.
    return NULL;
}


// Fetch the head of a linked-list object.
ListNode_t* List__get_head( List_t* list ) {
    if ( list == NULL )  return NULL;
    return list->head;
}

// Fetch the tail of a linked-list object.
ListNode_t* List__get_tail( List_t* list ) {
    ListNode_t* x = List__get_head( list );
    size_t loop_stop = 0;

    // Iterate the list to its end, but also add in a loop prevention mechanism, just in case.
    while ( x != NULL && loop_stop < (SIZE_MAX-1) ) {
        if ( x->next == NULL )  return x;
        x = x->next;
        loop_stop++;
    }

    // When nothing is found, return a NULL.
    return NULL;
}
