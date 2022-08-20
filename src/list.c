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
static void __List__set_head( List_t* list, ListNode_t* val ) {
    if ( NULL == list )  return;
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
    // First, delete all node data containers.
    ListNode_t* x = List__get_head( list );
    while ( NULL != x ) {
        if ( x->node )  free( x->node );
        x = x->next;
    }

    // Then, delete the ListNode items.
    List__clear( list );

    // Finally, free the entire list.
    if ( NULL != list )  free( list );
}

// Clear all items from a linked-list object. This simply clears all nodes from
//   the list, but does NOT delete the node data containers (items actually ref'd
//   by list nodes).
void List__clear( List_t* list ) {
    if ( NULL == list )  return;

    ListNode_t* x = List__get_head( list );
    while ( NULL != x ) {
        ListNode_t* x_shadow = x->next;
        free( x );
        x = x_shadow;
    }

    __List__set_head( list, NULL );
}

// Reverse the order of a list.
// TODO: Set the parm to List_t** and ret-type to void
List_t* List__reverse( List_t* list ) {
    if ( NULL == list || List__get_count( list ) < 1 )  return NULL;

    List_t* p_new = List__new( list->max_size );

    ListNode_t* x = List__get_head( list );
    while ( NULL != x ) {
        List__add_node( p_new, x->node );
        x = x->next;
    }

    // Clear the old list (but don't free ptrs) and delete.
    List__clear( list );
    free( list );

    return p_new;
}


// Get the amount of nodes in the linked-list object.
size_t List__get_count( List_t* list ) {
    size_t count = 0;
    for ( ListNode_t* x = List__get_head( list ); NULL != x; x = x->next )  count++;
    return count;
}


// Get the maximum amount of nodes allowed for the given linked list.
size_t List__get_max_count( List_t* list ) {
    return (NULL == list) ? 0 : list->max_size;
}


// Get the position of a certain node with the set ptr.
int List__index_of( List_t* list, void* node ) {
    if ( NULL == list || NULL == node )  return -1;

    ListNode_t* p_lhead = List__get_head( list );
    int idx = 0;

    while ( NULL != p_lhead ) {
        if ( node == p_lhead->node )  return idx;

        p_lhead = p_lhead->next;
        idx++;
    }

    return -1;
}


// Get the node at the listed index.
ListNode_t* List__get_index_from_head( List_t* p_list, size_t index ) {
    if ( NULL == p_list )  return NULL;

    ListNode_t* p_lhead = List__get_head( p_list );
    for ( size_t i = 0; i < index; i++ ) {
        if ( NULL == p_lhead )  return NULL;

        p_lhead = p_lhead->next;
    }

    return p_lhead;
}


// Add an entry onto the end of a linked-list.
bool List__add_node( List_t* list, void* node ) {
    if ( NULL == list || NULL == node )  return false;

    if ( List__get_count( list ) >= list->max_size )  return false;

    ListNode_t* x = (ListNode_t*)calloc( 1, sizeof(ListNode_t) );
    x->node = node;
    x->next = List__get_head( list );
    __List__set_head( list, x );

    return true;
}

// Delete an entry from within a linked list.
ListNode_t* List__drop_node( List_t* list, ListNode_t* node ) {
    if ( NULL == list || NULL == node )  return NULL;

    ListNode_t* x = List__get_head( list );
    if ( NULL == x ) {
        // Empty list; nothing to remove.
        return NULL;
    } else if ( x == node ) {
        if ( NULL == x->next ) {
            // When the node to remove is the only list item, free it and set the head to null.
            free( node );
            __List__set_head( list, NULL );
        } else {
            // When removing the head but with following items, set HEAD to the next list item.
            __List__set_head( list, x->next );
            free( node );
        }
        return NULL;
    }

    // Automatically move to the next node after pointing a 'shadow' to the head node.
    ListNode_t* prev_node = List__get_head( list );
    x = x->next;
    while ( NULL != x ) {
        if ( x == node ) {
            // Point the previous node to the next node, thereby bridging OVER this list item and removing it.
            prev_node->next = x->next;

            if ( x->node )  free( x->node );
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
    if (
           NULL == property_value || property_size <= 0
        || node_property_offset > 65535 || node_property_offset < 0
    ) return NULL;

    // For each node in the list, check the property value at the given offset against the provided comparator.
    for ( ListNode_t* x = List__get_head( list ); NULL != x; x = x->next ) {
        if ( !x || !(x->node) )  continue;
        if (
            0 == memcmp(
                ((x->node)+node_property_offset),
                property_value,
                property_size
            )
        )  return x;
    }

    // If no matching nodes were found, simply return a NULL.
    return NULL;
}


// Fetch the head of a linked-list object.
ListNode_t* List__get_head( List_t* list ) {
    if ( NULL == list )  return NULL;
    return list->head;
}

// Fetch the tail of a linked-list object.
ListNode_t* List__get_tail( List_t* list ) {
    ListNode_t* x = List__get_head( list );
    size_t loop_stop = 0;

    // Iterate the list to its end, but also add in a loop prevention mechanism, just in case.
    while ( NULL != x && loop_stop < (SIZE_MAX-1) ) {
        if ( NULL == x->next )  return x;
        x = x->next;
        loop_stop++;
    }

    // When nothing is found, return a NULL.
    return NULL;
}
