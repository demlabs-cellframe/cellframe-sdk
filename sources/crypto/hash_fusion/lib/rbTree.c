/*******************************************************************************
  rbTree.c

  Red-Black Trees

  - Implements ordered keys mapping to value (i.e. ordered treemap).
    + Provides set and/or map abstractions.

  - Significant input from:
    +  Chapter 12, Binary Search Trees
    +  Chapter 13, Red-Black Trees

    from Cormen et al, Introduction to Algorithms, 3rd Ed. MIT Press

  Keys are encoded as an "opaque" type (see utils.h)

  Red-Black properties:
  =====================
  - Each internal node has colour either RED or BLACK.

  - The root of the tree is BLACK.

  - If a node is RED, then both of its decendants must be BLACK.

  - All terminal nodes (i.e. NULLs) are BLACK.

  - All new nodes start out being coloured RED.

  - For every node, the total number of BLACK nodes is the same for each
    decendant path from the node to the leaves.
    
   Author: brian.monahan@hpe.com
      
   (c) Copyright 2017 Hewlett Packard Enterprise Development LP 

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are
   met: 

   1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer. 

   2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution. 

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
   IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
   TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
   PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
   HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
   TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 
*******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "utils.h"
#include "stringbuffer.h"
#include "alloc.h"
#include "rbTree.h"


// Colour data type
typedef enum { BLACK, RED } Colour_t;

// This encodes the internal red-black tree node.
// The tree components left and right may be LEAF (i.e. terminal leaf nodes).
// The only tree having LEAF parent is a root ...

typedef struct rbTreeNode Node_t;

struct rbTreeNode {
   Node_t *left;
   Node_t *right;
   Node_t *parent;           // This pointer could always be computed ... it is convenient to compute it

   unsigned int  id;         // unique id for the node - this is never recycled.

   Colour_t      colour;     // This could be encoded into the last bit of a pointer.

   Key_t         key;        // NULL_KEY represents "default" key
   void         *data;       // data pointer ...

   // synthetic attributes - these are convenient (but unnecessary)
   Boolean_t     needUpd;     // TRUE when synthetic attributes need updating

   int           size;       // number of nodes in this subtree (inclusive)
   Byte_t        height;     // height of subtree (inclusive)
   Byte_t        bHeight;    // black height for subtree (not incl. this node).
};


// Red-Black Tree structure
// - This encodes the root of the tree itself.
struct rbTree {
   VoidFn_t      finalObjFn;
   CompareFn_t   keyCompFn;

   Boolean_t     cacheOn;
   Key_t         cachedKey;     // Could be either NULL or non-NULL
   void         *cachedData;

   Boolean_t     allowUpd;      // TRUE when insert may update existing entries.
   Boolean_t     allowNullKey;  // TRUE when NULL_KEY is allowed as a valid key.

   Node_t       *root;
};


// Default flag value for allowing updates within the tree.
#define DEFAULT_ALLOW_UPDATES   TRUE


// Default flag value for allowing NULL_KEY as a valid key.
#define DEFAULT_ALLOW_NULL_KEY  TRUE
;


/*******************************************************************************
   Memory Management
*******************************************************************************/
static MemMgr_t *rbTree_MemMgr = NULL;
static MemMgr_t *rbNode_MemMgr = NULL;


/*******************************************************************************
   Node IDs
*******************************************************************************/
static unsigned int nextNodeID  =  1;


/*******************************************************************************
   LEAF node object
   - This is the unique terminating node object.
*******************************************************************************/
static Node_t *LEAF = NULL;

static void setupLeafObject() {
   if (LEAF != NULL) return;

   // Allocate memory for this object
   LEAF = ALLOC_OBJ(Node_t);

   // Set attributes
   LEAF->left     = LEAF;
   LEAF->right    = LEAF;
   LEAF->parent   = LEAF;

   LEAF->id       = 0;

   LEAF->key      = NULL_KEY;
   LEAF->data     = NULL;

   // Synthetic attributes
   LEAF->needUpd  = FALSE;
   LEAF->size     = 0;
   LEAF->height   = 0;
   LEAF->bHeight  = 0;
}


/*******************************************************************************
   Static method prototypes
*******************************************************************************/

// Insertion helpers
static void *insertNode(RBTree_t *tree, Key_t key, void *val);
static void fixupInsert(RBTree_t *tree, Node_t *newNode);

// Deletion helpers
static void removeInfo(RBTree_t *tree, Node_t * targetNode);
static void fixupDelete(RBTree_t *tree, Node_t *fixupNode);

// Memory management helpers
static void ensureMemMgmt();

static Node_t *allocate_Node(Key_t key, void *data);
static void deallocate_Node(RBTree_t *tree, Node_t *node);
static void deallocate_All(RBTree_t *tree, Node_t *node, VoidFn_t finalObjFn);

// Node ID
static int nodeID(Node_t *node);
static char *showNodeID(Node_t *node);

// Comparing opaque keys
static Comparison_t cmpKey(RBTree_t *tree, Key_t keyA, Key_t keyB);

static Boolean_t keyLT(RBTree_t *tree, Key_t keyA, Key_t keyB);
static Boolean_t keyEQ(RBTree_t *tree, Key_t keyA, Key_t keyB);
static Boolean_t keyGT(RBTree_t *tree, Key_t keyA, Key_t keyB);

// Showing keys
static char *showKey(Key_t key);

// Accessing extended attributes (e.g. height)
static int nodeNumNodes(Node_t *node);
static int nodeHeight(Node_t *node);
static int nodeBHeight(Node_t *node);

// Total bHeight = bHeight + colour weighting ...
static int totalBHeight(Node_t *node);

// Getting colours
static Colour_t nodeColour(Node_t *node);

static Boolean_t nodeIsBlack(Node_t *node);
static Boolean_t nodeIsRed(Node_t *node);

// Showing colours
static char *showColour(Colour_t colour);
static char *showNodeColour(Node_t *node);

// Checking for leaf/null nodes
static Boolean_t nodeIsLeaf(Node_t *node);
static Boolean_t nodeIsProper(Node_t *node);

// checking blackHeight balance
static Boolean_t nodeIsBalanced(Node_t *node);

// extracting nodes
static Node_t *nodeLeft(Node_t *node);
static Node_t *nodeRight(Node_t *node);
static Node_t *nodeParent(Node_t *node);

// finding nodes
static Node_t *findNode(RBTree_t *tree, Key_t key);

static Node_t *matchFirstNode(Node_t *curNode, PredFn_t predFn);
static Node_t *matchLastNode(Node_t *curNode, PredFn_t predFn);

static Node_t *findNextNode(RBTree_t *tree, Key_t key, Boolean_t allowEQ);
static Node_t *findPrevNode(RBTree_t *tree, Key_t key, Boolean_t allowEQ);

static Node_t *findMinForTree(RBTree_t *tree);
static Node_t *findMaxForTree(RBTree_t *tree);

static Node_t *getPreviousNode(Node_t *node);
static Node_t *getSuccessorNode(Node_t *node);

static Node_t *getLeftmostNode(Node_t *node);
static Node_t *getRightmostNode(Node_t *node);

// caching info ...
static Key_t setCacheInfo_Key(RBTree_t *tree, Node_t *result);
static void *setCacheInfo_Data(RBTree_t *tree, Node_t *node);

// checking tree
static Boolean_t check_treenode(Node_t *node);
static Boolean_t check_subnode_parents(Node_t *node);
static Boolean_t check_RB_properties(Node_t *node);

// showing tree
static void initShowTree(StringBuf_t *sbuf);
static void showTree(RBTree_t *mTree);

// showing pointers
static Ptr_t convPtr(void *addr);

// updating extended attributes (height etc.)
static void updateAttrs_Tree(RBTree_t *tree);
static void updateAttrs_All(Node_t *node);        // This checks the update status
static void forcedUpdateAttrs(Node_t *node);  // This updates always
static Boolean_t updateAttrs_Node(Node_t *node);
//static void updateAttrs_Parent(Node_t *node);

static void markUpdateNeeded(Node_t *node);

// Rotation of nodes
static void leftRotate(RBTree_t *tree, Node_t *node);
static void rightRotate(RBTree_t *tree, Node_t *node);


/*******************************************************************************
  Parameters
  - These parameters are typically varied for testing purposes.
  - As they affect all instances, they should not be relied upon in production.
*******************************************************************************/
// Enable/disable internal checking of RB tree
Boolean_t doInternalChecks = FALSE;

// Enable/disable output of reports from checking:
Boolean_t outputCheckReports = TRUE;

// Enable balancing
Boolean_t doBalancing = TRUE;

// Abort when checking the tree fails
Boolean_t abortOnCheckFailure = TRUE;


/*******************************************************************************
  Methods
*******************************************************************************/
// Allocate an RBTree_t object ...
// - finalObjFn    - Used to deallocate data objects when disposing
//                 - If function is NULL, then nothing is done.
//
// - keyCompFn     - Used to compare non-NULL keys - as a linear (less-than) ordering.
//                 - This function does not need to consider NULL_KEYs as input.
//                 - If function is NULL, then the standard < ordering on unsigned long values is used.
RBTree_t *new_RBT(CompareFn_t keyCompFn) {
   // ensure that the allocation structures exist ...
   ensureMemMgmt();

   // determine default functions ...
   keyCompFn = (keyCompFn == NULL ? cmp_key : keyCompFn);

   // allocate new Tree
   RBTree_t *newTree = allocateObject_MM(rbTree_MemMgr);

   // set attributes
   newTree->finalObjFn   = nullVoidFn;
   newTree->keyCompFn    = keyCompFn;

   newTree->cacheOn      = FALSE;
   newTree->cachedKey    = NULL_KEY;
   newTree->cachedData   = NULL;
   newTree->allowUpd     = DEFAULT_ALLOW_UPDATES;
   newTree->allowNullKey = DEFAULT_ALLOW_NULL_KEY;
   newTree->root         = LEAF;

   return newTree;
}

// Deallocate an RBTree object ...
void deallocate_RBT(void *item) {
   if (item == NULL) return;

   RBTree_t *tree = (RBTree_t *)item;

   // ensure that the allocation structures exist ...
   ensureMemMgmt();

   // Deallocate all from root
   deallocate_All(tree, tree->root, tree->finalObjFn);

   // nullify the attributes of tree
   NULLIFY_OBJ(tree, RBTree_t)

   // recycle the current tree object
   deallocateObject_MM(rbTree_MemMgr, sizeof(RBTree_t), tree);
}


// Deallocate an RBTree object ... with specific object finaliser
void deallocateWithFinaliser_RBT(void *item, VoidFn_t finalObjFn) {
   if (item == NULL) return;

   RBTree_t *tree = (RBTree_t *)item;

   // ensure that the allocation structures exist ...
   ensureMemMgmt();

   // Deallocate all from root
   deallocate_All(tree, tree->root, finalObjFn);

   // nullify the attributes of tree
   NULLIFY_OBJ(tree, RBTree_t)

   // recycle the current tree object
   deallocateObject_MM(rbTree_MemMgr, sizeof(RBTree_t), tree);
}


// Set object finaliser function ...
// - No finalisation happens for data items unless this is set.
void setFinaliser_RBT(RBTree_t *tree, VoidFn_t finalObjFn) {
   req_NonNull(tree);

   // normalising function to be non-null
   finalObjFn = (finalObjFn == NULL ? nullVoidFn : finalObjFn);

   tree->finalObjFn = finalObjFn;
}


// Inserts data under given key into given tree ...
// - If key already exists in tree:
//   + replaces previous data with dataItem.
//   + return previous data.
// - Otherwise, insert new dataItem and return NULL.
void *insert_RBT(RBTree_t *tree, Key_t key, void *dataItem) {
   req_NonNull(tree);

	// Check if NULL_KEY is permitted
	if (!tree->allowNullKey && key == NULL_KEY) {
	   return NULL;
	}

   // update the cache, if necessary
   if (tree->cacheOn && keyEQ(tree, key, tree->cachedKey)) {
      tree->cachedData = dataItem;
   }

   // Add to key/data to tree
   // - Capture any previously held data
   void *prevData = insertNode(tree, key, dataItem);

   // Perform the finaliser on prevData
   // - This function may do nothing on prevData ...
   // - Thus, the data pointer prevData is returned in any case.
   tree->finalObjFn(prevData);

   // Perform update of attributes from root (as necessary)
   updateAttrs_Tree(tree);

   // Perform checks when balancing
   if (doInternalChecks && doBalancing) {
      checkTree_RBT(tree);
   }

   // Return old data pointer ...
   return prevData;
}

// Deletes data under given key from given tree.
// - If found, returns the data pointer found.
// - Otherwise return NULL
void *delete_RBT(RBTree_t *tree, Key_t key) {
   req_NonNull(tree);

	// Check if NULL_KEY is permitted
	if (!tree->allowNullKey && key == NULL_KEY) {
	   return NULL;
	}

   // Clear the cache, if necessary
   if (tree->cacheOn && keyEQ(tree, key, tree->cachedKey)) {
      tree->cachedKey = NULL_KEY;
      tree->cachedData = NULL;
      tree->cacheOn = FALSE;
   }

   // Find the node to be deleted
   Node_t *delNode  = findNode(tree, key);

   // check if deleted node was found
   if (nodeIsLeaf(delNode)) {

      return NULL;
   }

   // Capture data pointer from the node to be deleted
   void *prevData = delNode->data;

   // Now remove the information ...
   // - In fact, the tree is rearranged so that the information is removed.
   // - Node id's at which information is found may change.
   // - The number of nodes is decreased by 1 ...
   removeInfo(tree, delNode);

   // Perform the finaliser on prevData
   // - This function may do nothing on prevData ...
   // - Thus, the data pointer prevData is returned in any case.
   tree->finalObjFn(prevData);

   // perform update of attributes from root (as necessary)
   updateAttrs_Tree(tree);

   // Perform checks when balancing
   if (doInternalChecks && doBalancing) {
      checkTree_RBT(tree);
   }

   // Return old data pointer ...
   return prevData;
}


// Checks that key belongs to given tree - as a domain element.
// - Successful lookups are cached.
Boolean_t member_RBT(RBTree_t *tree, Key_t key) {
   req_NonNull(tree);

	// When NULL_KEY is not permitted, return FALSE for key == NULL_KEY
	if (!tree->allowNullKey && key == NULL_KEY) {
	   return FALSE;
	}

   // check if key was cached ...
   // if yes, then key is present in the tree ...
   if (tree->cacheOn && keyEQ(tree, key, tree->cachedKey)) return TRUE;

   Node_t *curNode = findNode(tree, key);

   // cache result of search
   setCacheInfo_Data(tree, curNode);

   // returns TRUE if proper node was found ...
   return (nodeIsProper(curNode));
}

// Lookup data in tree for the given key
// - If found, returns the corresponding data pointer for the given key.
// - Otherwise return NULL
// - Successful lookups are cached.
//   (Unsuccessful lookups clear the cache)
void *lookup_RBT(RBTree_t *tree, Key_t key) {
   req_NonNull(tree);

	// When NULL_KEY is not permitted, return NULL for key == NULL_KEY
	if (!tree->allowNullKey && key == NULL_KEY) {
	   return NULL;
	}

   // check if key was cached ...
   if (tree->cacheOn && keyEQ(tree, key, tree->cachedKey)) return tree->cachedData;

   Node_t *curNode = findNode(tree, key);

   // cache result of search
   return setCacheInfo_Data(tree, curNode);
}


// find key of first element matching the predicate ...
// - finds the key of the first/least element in the tree satisfying the predicate
Key_t findFirstMatch_RBT(RBTree_t *tree, PredFn_t predFn) {
   req_NonNull(tree);

   Node_t *curNode = matchFirstNode(tree->root, predFn);

   // cache result of search
   return setCacheInfo_Key(tree, curNode);
}


// find key of last element matching the predicate ...
// - finds the key of the last/greatest element in the tree satisfying the predicate
Key_t findLastMatch_RBT(RBTree_t *tree, PredFn_t predFn) {
   req_NonNull(tree);

   Node_t *curNode = matchLastNode(tree->root, predFn);

   // cache result of search
   return setCacheInfo_Key(tree, curNode);
}


// Returns minimum key in given tree, if it exists
// - Updates the lookup cache - this means that the corresponding min-value
//   can be efficiently accessed.
Key_t minKey_RBT(RBTree_t *tree) {
   req_NonNull(tree);

   Node_t *curNode = findMinForTree(tree);

   // cache result of search
   return setCacheInfo_Key(tree, curNode);
}

// Returns maximum key in given tree
// - Updates the lookup cache - this means that the corresponding max-value
//   can be efficiently accessed.
Key_t maxKey_RBT(RBTree_t *tree) {
   req_NonNull(tree);

   Node_t *curNode = findMaxForTree(tree);

   // cache result of search
   return setCacheInfo_Key(tree, curNode);
}


// Get first data element
// - Returns NULL if empty
void *getFirstElement_RBT(RBTree_t *tree) {
   req_NonNull(tree);

   Node_t *curNode = findMinForTree(tree);

   // cache result of search
   return setCacheInfo_Data(tree, curNode);
}

// Get last data element
// - Returns NULL if empty
void *getLastElement_RBT(RBTree_t *tree) {
   req_NonNull(tree);

   Node_t *curNode = findMaxForTree(tree);

   // cache result of search
   return setCacheInfo_Data(tree, curNode);
}

// Returns next successor key in given tree, if it exists
// - Otherwise, return NULL_KEY.
// - If allowEQ is TRUE, then can return the given key if present.
// - Given key may not itself exist in the tree.
Key_t nextKey_RBT(RBTree_t *tree, Key_t key, Boolean_t allowEQ) {
   req_NonNull(tree);

	// When NULL_KEY is not permitted, return NULL_KEY for key == NULL_KEY
	if (!tree->allowNullKey && key == NULL_KEY) {
	   return NULL_KEY;
	}

   Node_t *curNode = findNextNode(tree, key, allowEQ);

   // cache result of search
   return setCacheInfo_Key(tree, curNode);
}


// Returns predecessor key in given tree, if it exists
// - Otherwise, return NULL_KEY.
// - If allowEQ is TRUE, then can return the given key if present.
// - Given key may not itself exist in the tree.
Key_t priorKey_RBT(RBTree_t *tree, Key_t key, Boolean_t allowEQ) {
   req_NonNull(tree);

	// When NULL_KEY is not permitted, return NULL_KEY for key == NULL_KEY
	if (!tree->allowNullKey && key == NULL_KEY) {
	   return NULL_KEY;
	}

   Node_t *curNode = findPrevNode(tree, key, allowEQ);

   // cache result of search
   return setCacheInfo_Key(tree, curNode);
}


// Height of tree
int getHeight_RBT(RBTree_t *tree) {
   req_NonNull(tree);

   return (nodeIsLeaf(tree->root) ? 0 : tree->root->height);
}

// Total number of nodes in tree
int getSize_RBT(RBTree_t *tree) {
   req_NonNull(tree);

   return (nodeIsLeaf(tree->root) ? 0 : tree->root->size);
}


// Get/Set allow updates
void setAllowUpdates_RBT(RBTree_t *tree, Boolean_t status) {
   req_NonNull(tree);

   tree->allowUpd = status;
}

Boolean_t getAllowUpdates_RBT(RBTree_t *tree) {
   req_NonNull(tree);

   return tree->allowUpd;
}


// Set/Get allow NULL_KEY as a valid key
void setAllowNullKey_RBT(RBTree_t *tree, Boolean_t status){
   req_NonNull(tree);

   tree->allowNullKey = status;
}

Boolean_t getAllowNullKey_RBT(RBTree_t *tree) {
   req_NonNull(tree);

   return tree->allowNullKey;
}


// Show tree by appending to stringbuffer
// - set indent string
// - set incrment indent string
// - set compact display
// - set max depth (if positive)
// - set show details of nodes (default: TRUE)
// - set show tree tightly
// - set show tree in in-order (default)
// - set show tree in pre-order
// - set show ids (default: TRUE)
// - set show addresses (default: FALSE)
// - set show simplified addresses (e.g. addr mod 0x10000) (default: FALSE)

// show attributes
static char *show_indent = "   ";                // indent string
static char *show_incrIndent = "   ";;           // incremental indent
static Boolean_t show_compact_display = FALSE;
static int show_max_depth = -1;
static Boolean_t show_details = FALSE;           // show all node details
static Boolean_t show_tightly = FALSE;           // show the tree tightly
static Boolean_t show_inorder = TRUE;            // show the tree in order
static Boolean_t show_ids = TRUE;                // show IDs
static Boolean_t show_addrs = FALSE;             // show addresses
static Boolean_t show_simplified_addr = FALSE;   // show simplified addresses (e.g. addr mod 0x10000)

void show_RBT(RBTree_t *tree, StringBuf_t *sbuf) {
   req_NonNull(tree);
   req_NonNull(sbuf);

   initShowTree(sbuf);

   // updates the extended attributes of tree
   if (show_details) {
      updateAttrs_Tree(tree);
   }

   showTree(tree);
}

void setShow_Indent_RBT(char * indent) {
   int indentLen = strlen(indent);

   if (2 <= indentLen && indentLen < MAX_INDENT_LENGTH) {
		show_indent = indent;
   }
   else {
      diagnostic("rbTree.setShow_Indent : Bad indent length: %i", indentLen);
      codeError_exit();
   }
}

void setShow_IncrIndent_RBT(char * indent) {
   int indentLen = strlen(indent);

   if (2 <= indentLen && indentLen < MAX_INDENT_LENGTH) {
		show_incrIndent = indent;
   }
   else {
      diagnostic("rbTree.setShow_IncrIndent : Bad indent length: %i", indentLen);
      codeError_exit();
   }
}

void setShow_Compact_RBT(Boolean_t isCompact) {
	show_compact_display = asBoolean(isCompact);
}

// sets max depth
// - giving non-positive value removes constraint
void setShow_MaxDepth_RBT(int maxDepth) {
	show_max_depth = minmax(0, maxDepth, MAX_TREE_HEIGHT);
}

// set show details
void setShow_Details_RBT(Boolean_t details) {
   show_details = details;
}

void setShow_Tightly_RBT(Boolean_t tightly) {
   show_tightly = tightly;
}

void setShow_Inorder_RBT() {
   show_inorder = TRUE;
}

void setShow_Preorder_RBT() {
   show_inorder = FALSE;
}

void setShow_IDs_RBT(Boolean_t ids) {
   show_ids = ids;
}

void setShow_Addrs_RBT(Boolean_t addrs) {
   show_addrs = addrs;
}

void setShow_SimplifiedAddrs_RBT(Boolean_t simplified) {
   show_simplified_addr = simplified;
}


/*******************************************************************************
   Static methods
*******************************************************************************/
static void ensureMemMgmt() {
   if (rbTree_MemMgr == NULL) {
      rbTree_MemMgr      = new_MM(sizeof(RBTree_t));
      rbNode_MemMgr  = new_MM(sizeof(Node_t));

      // Ensure that LEAF object is initialised ...
      setupLeafObject();
   }
}


/*******************************************************************************
   Accessor methods
*******************************************************************************/
static int nodeNumNodes(Node_t *node) {
   return (nodeIsLeaf(node) ? 0 : node->size);
}

static int nodeHeight(Node_t *node) {
   return (nodeIsLeaf(node) ? 0 : node->height);
}

// Basic version of black height
// - does not depend upon node colour.
static int nodeBHeight(Node_t *node) {
   return (nodeIsLeaf(node) ? 0 : node->bHeight);
}

// Total black-height - bHeight + colour weighting
// - This is useful for calculating node balance as it includes a value for the
//   colour.
static int totalBHeight(Node_t *node) {
   return (nodeBHeight(node) + (nodeIsBlack(node) ? 1 : 0));
}

static Boolean_t nodeIsBalanced(Node_t *node) {
   if (nodeIsLeaf(node)) return TRUE;

   int leftBH  = totalBHeight(node->left);
   int rightBH = totalBHeight(node->right);

   return asBoolean(leftBH == rightBH);
}

static int nodeID(Node_t *node) {
   return (nodeIsLeaf(node) ? 0 : node->id);
}

// Manage temp strings
#define MAX_TEMP_STRINGS  5
#define TEMP_STRING_SIZE  64
static char *tempString[MAX_TEMP_STRINGS];
static int nextString = 0;

static char *showNodeID(Node_t *node) {
   if (tempString[nextString] == NULL) {
      // allocate string
      tempString[nextString] = ALLOC_STR(TEMP_STRING_SIZE);
   }

   // get next string
   char *output = tempString[nextString];

   // increment index of next string
   nextString += 1;
   if (nextString >= MAX_TEMP_STRINGS) nextString = 0;

   sprintf(output, "id-%i (0x%lu)", nodeID(node), (Ptr_t)node);

   return output;
}

static Colour_t nodeColour(Node_t *node) {
   return (nodeIsBlack(node) ? BLACK : RED);
}

static Boolean_t nodeIsBlack(Node_t *node) {
   return (nodeIsLeaf(node) ? TRUE : node->colour == BLACK);
}

static Boolean_t nodeIsRed(Node_t *node) {
   return (nodeIsLeaf(node) ? FALSE : node->colour == RED);
}

// This checks if node is the actual root node of given tree ...
static Boolean_t nodeIsRoot(RBTree_t *tree, Node_t *node) {
   return (  tree != NULL
          && nodeIsLeaf(nodeParent(node))
          && tree->root == node
          && nodeIsBlack(node)
          );
}


static Boolean_t nodeIsLeaf(Node_t *node) {
   return (node == NULL || node == LEAF);
}

// This is the negation of the nodeIsLeaf predicate
static Boolean_t nodeIsProper(Node_t *node) {
   return (node != NULL && node != LEAF);
}

// This checks if node is the left node of its parent ...
static Boolean_t nodeIsLeft(Node_t *node) {
   return (nodeIsProper(node) && node->parent->left == node);
}

// This checks if node is the right node of its parent ...
static Boolean_t nodeIsRight(Node_t *node) {
   return (nodeIsProper(node) && node->parent->right == node);
}

static Node_t *nodeLeft(Node_t *node) {
   return (nodeIsLeaf(node) ? LEAF : node->left);
}

static Node_t *nodeRight(Node_t *node) {
   return (nodeIsLeaf(node) ? LEAF : node->right);
}

static Node_t *nodeParent(Node_t *node) {
   return (nodeIsLeaf(node) ? LEAF : node->parent);
}


/*******************************************************************************
   Comparison methods

   This uses the compare protocol for cmpKey(x, y):
     LT   if (x less than y)
     EQ   if (x equals y)
     GT   if (x greater than y)

*******************************************************************************/
static Comparison_t cmpKey(RBTree_t *tree, Key_t keyA, Key_t keyB) {
   return tree->keyCompFn(keyA, keyB);
}

static Boolean_t keyLT(RBTree_t *tree, Key_t keyA, Key_t keyB) {
   return tree->keyCompFn(keyA, keyB) < 0;
}

static Boolean_t keyEQ(RBTree_t *tree, Key_t keyA, Key_t keyB) {
   return tree->keyCompFn(keyA, keyB) == 0;
}

static Boolean_t keyGT(RBTree_t *tree, Key_t keyA, Key_t keyB) {
   return tree->keyCompFn(keyA, keyB) > 0;
}


/*******************************************************************************
   Showing colours
*******************************************************************************/
static char *showColour(Colour_t colour) {
   return (colour == BLACK ? "BLACK" : "RED");
}

static char *showNodeColour(Node_t *node) {
   return showColour(nodeColour(node));
}


/*******************************************************************************
   Caching Info
   - ensures consistent updates and retrievals ...
*******************************************************************************/
static void updateCacheInfo(RBTree_t *tree, Node_t *result) {
   if (nodeIsProper(result)) {
      tree->cacheOn    = TRUE;
      tree->cachedKey  = result->key;
      tree->cachedData = result->data;
   }
   else {
      tree->cacheOn    = FALSE;
      tree->cachedKey  = NULL_KEY;
      tree->cachedData = NULL;
   }
}

static Key_t setCacheInfo_Key(RBTree_t *tree, Node_t *result) {
   updateCacheInfo(tree, result);
   return tree->cachedKey;
}

static void *setCacheInfo_Data(RBTree_t *tree, Node_t *result) {
   updateCacheInfo(tree, result);
   return tree->cachedData;
}


/*******************************************************************************
   Finding and matching nodes
*******************************************************************************/
static Node_t *findNode(RBTree_t *tree, Key_t key) {
   Node_t *curNode = tree->root;

   // if possible find node with matching key
   int indicator = 0;
   while(curNode != LEAF) {
      indicator = cmpKey(tree, key, curNode->key);

      if (indicator == 0) return curNode;
      curNode = (indicator < 0 ? curNode->left : curNode->right);
   }

   return LEAF;
}


static Node_t *matchFirstNode(Node_t *curNode, PredFn_t predFn) {
   if (nodeIsLeaf(curNode)) return LEAF;

   Node_t *result = matchFirstNode(curNode->left, predFn);
   if (nodeIsProper(result)) return result;

   if (predFn(curNode->data)) return curNode;

   return matchFirstNode(curNode->right, predFn);
}


static Node_t *matchLastNode(Node_t *curNode, PredFn_t predFn) {
   if (nodeIsLeaf(curNode)) return LEAF;

   Node_t *result = matchLastNode(curNode->right, predFn);
   if (nodeIsProper(result)) return result;

   if (predFn(curNode->data)) return curNode;

   return matchLastNode(curNode->left, predFn);
}


// finds the next node for a given key ...
// - the given key need not exist in the tree
// - If allowEQ is TRUE, then return node if it exists.
// - If no node exists, then return NULL
static Node_t *findNextNode(RBTree_t *tree, Key_t key, Boolean_t allowEQ) {
   Node_t *parentNode = NULL;
   Node_t *curNode = tree->root;

   // if possible find node with matching key
   int indicator = 0;
   while(nodeIsProper(curNode)) {
      parentNode = curNode;
      indicator = cmpKey(tree, key, curNode->key);

      // if node found then
      // - if allowEQ return node
      // - otherwise break
      if (indicator == 0) {
         if (allowEQ) return curNode;

         break;
      }

      // move curNode nearer to node with target key should be
      curNode = (indicator < 0 ? curNode->left : curNode->right);
   }

   if (nodeIsProper(curNode))  {
      // curNode->key == key
	   Node_t *succNode = getSuccessorNode(curNode);
	   if (nodeIsProper(succNode)) {

		   return succNode;
	   }
	   else {
	      return NULL;
	   }
   }
   // curNode == LEAF
   if (nodeIsProper(parentNode)) {
      // get the least element greater than node
      // - The parentNode is either the previous or next node for key
      if (keyLT(tree, parentNode->key, key)) {
          // - if parentNode's key is less than key,
          //   then the successor node will be immediately greater than key.
          return getSuccessorNode(parentNode);
      } else {
          // - if parentNode's key is less than key,
          //   then the successor node will be immediately less than key.
          //   This means that parentNode's is least greater than key in the tree.
          return parentNode;
      }
   }
   else {
      // This means both parentNode == curNode == LEAF i.e. undefined root
      return NULL;
   }
}


// finds the previous node for a given key ...
// - the given key need not exist in the tree
// - If allowEQ is TRUE, then return node if it exists.
// - If no node exists, then return NULL
static Node_t *findPrevNode(RBTree_t *tree, Key_t key, Boolean_t allowEQ) {
   Node_t *parentNode = LEAF;
   Node_t *curNode = tree->root;

   // if possible find node with matching key
   int indicator = 0;
   while(nodeIsProper(curNode)) {
      parentNode = curNode;
      indicator = cmpKey(tree, key, curNode->key);

      // if node found then
      // - if allowEQ return node
      // - otherwise break
      if (indicator == 0) {
         if (allowEQ) return curNode;

         break;
      }

      // move curNode nearer to where node with target key should be
      curNode = (indicator < 0 ? curNode->left : curNode->right);
   }

   if (nodeIsProper(curNode))  {
      // KEY FOUND!!!  curNode->key == key
	   Node_t *prevNode = getPreviousNode(curNode);
	   if (nodeIsProper(prevNode)) {
 		   return prevNode;
	   }
	   else {
	      return NULL;
	   }
   }
   // curNode == LEAF - i.e. key is not in the tree
   if (nodeIsProper(parentNode)) {
      // get the greatest element less than node
      // - The parentNode is either the previous or next node for key
      if (keyGT(tree, parentNode->key, key)) {
          // - if parentNode's key is greater than key,
          //   then the previous node will be immediately less than key.
          return getPreviousNode(parentNode);
      } else {
          // - if parentNode's key is less than key,
          //   then the successor node will be immediately greater than key.
          //   This means that parentNode's is greatest less than key in the tree.
          return parentNode;
      }
   }
   else {
      // This means both parentNode == curNode == LEAF
      return NULL;
   }
}

static Node_t *findMinForTree(RBTree_t *tree) {
   return getLeftmostNode(tree->root);
}

static Node_t *findMaxForTree(RBTree_t *tree) {
   return getRightmostNode(tree->root);
}


static Node_t *getSuccessorNode(Node_t *node) {
   if (nodeIsLeaf(node)) {
      return LEAF;
   }

   if (nodeIsLeaf(node->right)) {

      // crawl back up the tree to find successor (if possible)
      Node_t *curNode = node;
      Node_t *parentNode = curNode->parent;

      while (nodeIsProper(parentNode)) {
         if (curNode == parentNode->left) {
		      return parentNode;
         }

         // Ascending the tree ...
         curNode = parentNode;
         parentNode = curNode->parent;
      }

      return LEAF;

   } else {

     return getLeftmostNode(node->right);
   }
}


static Node_t *getPreviousNode(Node_t *node) {
   if (nodeIsLeaf(node)) {
      return LEAF;
   }

   if (nodeIsLeaf(node->left)) {

      // crawl back up the tree to find predecessor (if possible)
      Node_t *curNode = node;
      Node_t *parentNode = curNode->parent;

      while (nodeIsProper(parentNode)) {
         if (curNode == parentNode->right) {
		      return parentNode;
         }

         // Ascending the tree ...
         curNode = parentNode;
         parentNode = curNode->parent;
      }

      return LEAF;

   } else {

     return getRightmostNode(node->left);
   }
}

static Node_t *getLeftmostNode(Node_t *node) {
   if (nodeIsLeaf(node)) return node;

   Node_t *parentNode = nodeParent(node);
   Node_t *curNode = node;

   while (nodeIsProper(curNode)) {
       parentNode = curNode;
       curNode = curNode->left;
   }

   return parentNode;
}

static Node_t *getRightmostNode(Node_t *node) {
   if (nodeIsLeaf(node)) return LEAF;

   Node_t *parentNode = nodeParent(node);
   Node_t *curNode = node;

   while (nodeIsProper(curNode)) {
       parentNode = curNode;
       curNode = curNode->right;
   }

   return parentNode;
}


/*******************************************************************************
   Allocation/deallocation
*******************************************************************************/
// Allocate a fresh tree node.
// - All nodes are added as tips of the tree (i.e. with null descendents).
// - They all start out as coloured RED ...
static Node_t *allocate_Node(Key_t key, void *dataItem) {
   // ensure that the allocation structures exist ...
   ensureMemMgmt();

   Node_t *newNode = allocateObject_MM(rbNode_MemMgr);

   // initialise attributes
   newNode->left         = LEAF;
   newNode->right        = LEAF;
   newNode->parent       = LEAF;

   newNode->id           = nextNodeID;   // unique node id - these should never be repeated.
   newNode->colour       = RED;          // All allocated tree nodes start out as RED

   // extended attributes
   newNode->size         = 1;            // total number of nodes (including this one) - NULL
   newNode->height       = 1;            // current height of nodes (including this one)
   newNode->bHeight      = 1;            // blackHeight of this node is 1 (bHeight of LEAF's is 0)

   // keys and data
   newNode->key          = key;
   newNode->data         = dataItem;

   // increment node id ..
   nextNodeID += 1;

   return newNode;
}

static void deallocate_Node(RBTree_t *tree, Node_t *node) {
   if (tree == NULL) return;
   if (nodeIsLeaf(node)) return;

   // nullify node
   NULLIFY_OBJ(node, Node_t);

   // recycle the current tree object
   deallocateObject_MM(rbNode_MemMgr, sizeof(Node_t), node);
}


static void deallocate_All(RBTree_t *tree, Node_t *node, VoidFn_t finalObjFn) {
   if (tree == NULL) return;
   if (nodeIsLeaf(node)) return;

   // finalise all data below
   finalObjFn(node->data);
   deallocate_All(tree, node->left, finalObjFn);
   deallocate_All(tree, node->right, finalObjFn);

   // nullify node
   NULLIFY_OBJ(node, Node_t)

   // recycle the current tree object
   deallocateObject_MM(rbNode_MemMgr, sizeof(Node_t), node);
}


/*******************************************************************************
   Fixing the RB invariants

   On insert and delete actions, the tree will have its RB invaraants broken.

   These are fixed below (by suitable recolouring and rotations) which change topology
   without affecting the overall ordering of elements.
*******************************************************************************/

// This updates the tree, starting with the new node (coloured RED).  This works by
// rearranging nodes to eliminate RED nodes with RED parents.
static void *insertNode(RBTree_t *tree, Key_t key, void *val) {
	Node_t *curNode, *parentNode, *newNode;

	// find future parent
	curNode = tree->root;
	parentNode = NULL;

	while (curNode != LEAF) {
	   if (keyEQ(tree, key, curNode->key)) {
		   if (tree->allowUpd) {

			   // update existing data
			   void * prevData = curNode->data;
				curNode->data = val;

				return prevData;
	      }

		   //printf("insertNode - found DUPLICATED node with key = %s\n", showKey(key));
		   return NULL;
	   }

	   parentNode = curNode;
	   curNode = (keyLT(tree, key, curNode->key) ? curNode->left : curNode->right);
	}

	// setup new node
	newNode = allocate_Node(key, val);
	newNode->parent = parentNode;

	// insert node in tree
	if (nodeIsProper(parentNode)) {
	   if (keyLT(tree, key, parentNode->key))
		   parentNode->left = newNode;
	   else
		   parentNode->right = newNode;

	} else {

	   tree->root = newNode;

	}

   // Mark the newNode and its ancestors as needing update.
   markUpdateNeeded(newNode);

	fixupInsert(tree, newNode);

	return NULL;
}

static void fixupInsert(RBTree_t *tree, Node_t *newNode) {
    req_NonNull(tree);
    req_NonNull(newNode);

    // maintain red-black tree balance
    // after inserting node newNode

    Node_t *fixupNode = newNode;

    // check red-black properties
    while (fixupNode != tree->root && fixupNode->parent->colour == RED) {
        // we have a violation
        if (fixupNode->parent == fixupNode->parent->parent->left) {
            Node_t *uncleNode = fixupNode->parent->parent->right;

            // Mark the uncleNode and its ancestors as needing update.
            //markUpdateNeeded(uncleNode);

            if (uncleNode->colour == RED) {

                // uncle is RED
                fixupNode->parent->colour = BLACK;
                uncleNode->colour = BLACK;
                fixupNode->parent->parent->colour = RED;
                fixupNode = fixupNode->parent->parent;
            } else {

                // uncle is BLACK
                if (fixupNode == fixupNode->parent->right) {
                    // make fixupNode a left child
                    fixupNode = fixupNode->parent;

                    leftRotate(tree, fixupNode);
                }

                // recolor and rotate
                fixupNode->parent->colour = BLACK;
                fixupNode->parent->parent->colour = RED;

                rightRotate(tree, fixupNode->parent->parent);
            }
        } else {

            // mirror image of above code
            Node_t *uncleNode = fixupNode->parent->parent->left;

            // Mark the uncleNode and its ancestors as needing update.
            //markUpdateNeeded(uncleNode);

            if (uncleNode->colour == RED) {

                // uncle is RED
                fixupNode->parent->colour = BLACK;
                uncleNode->colour = BLACK;
                fixupNode->parent->parent->colour = RED;
                fixupNode = fixupNode->parent->parent;
            } else {

                // uncle is BLACK
                if (fixupNode == fixupNode->parent->left) {
                    fixupNode = fixupNode->parent;

                    rightRotate(tree, fixupNode);
                }
                fixupNode->parent->colour = BLACK;
                fixupNode->parent->parent->colour = RED;

                leftRotate(tree, fixupNode->parent->parent);
            }
        }
    }

    tree->root->colour = BLACK;
}


/*******************************************************************************
   Deleting nodes
   - Nodes are deleted by rearranging information and deleting a convenient node.
   - The subtlety is that the target node may not actually be deleted - instead
     a more convenient node is found and information rearranged so as to preserve
     content.
*******************************************************************************/
static void removeInfo(RBTree_t *tree, Node_t *targetNode) {
    req_NonNull(targetNode);

    if (targetNode == LEAF) {
       diagnostic("removeInfo : Attempting to delete LEAF node.");
       codeError_exit();
    }

    Node_t *movedNode, *delNode = LEAF;

    // Define this node to be the replacement
    Node_t *replaceNode = LEAF;

    if (targetNode->left == LEAF || targetNode->right == LEAF) {
        // delNode has a LEAF node as a child
        delNode = targetNode;

    } else {
        // targetNode->left != LEAF && targetNode->right != LEAF
        // - both descendents of targetNode are proper nodes.

        // Find tree successor with a LEAF node as a child
        Node_t *succNode = targetNode->right;
        while (succNode->left != LEAF) {
           succNode = succNode->left;
        }

        // delNode != LEAF && delNode->left == LEAF
        delNode = succNode;
        replaceNode = targetNode;

        // NOTE: delNode = succNode != targetNode = replaceNode
        // In this case, the node to be deleted is the successor node, not the targetNode.
    }

    // delNode now has at most one non-LEAF child ...
    // - This non-LEAF child has to be moved.
    // - it could still have two LEAF children (i.e. be a "tip" node)

    // set movedNode to be delNode's non-LEAF child (if possible)
    if (nodeIsProper(delNode->left))
        // movedNode cannot be a LEAF
        movedNode = delNode->left;
    else
        // movedNode could be a LEAF here ...
        movedNode = delNode->right;

    // Remove delNode from the parent chain
    // - Although the movedNode could be LEAF, the parent pointer may be updated ...
    movedNode->parent = delNode->parent;
    if (nodeIsProper(delNode->parent))
        if (delNode == delNode->parent->left)
            delNode->parent->left = movedNode;
        else
            delNode->parent->right = movedNode;
    else
        // delNode->parent == NULL, thus delNode is currently root
        tree->root = movedNode;

    if (delNode != targetNode) {
        // replaceNode must not be equal to LEAF
        req_Distinct(replaceNode, LEAF);

        // delNode and replaceNode must be distinct.
        req_Distinct(delNode, replaceNode);

        // relocating information to be retained

        replaceNode->key  = delNode->key;
        replaceNode->data = delNode->data;

        // Nullify old info ...
        delNode->key  = NULL_KEY;
        delNode->data = NULL;
    }

    // Mark the movedNode and its ancestors as needing update.
    markUpdateNeeded(movedNode);

    // Mark the delNode and its ancestors as needing update.
    markUpdateNeeded(delNode);

    // Check if fixup is needed ...
    if (delNode->colour == BLACK) {
        // Node to be deleted is BLACK, thus changing the number of BLACK nodes
        // - hence fixup is needed to restore red-black properties
        fixupDelete (tree, movedNode);
    }
    // Recycle delNode
    deallocate_Node(tree, delNode);
}


static void fixupDelete(RBTree_t *tree, Node_t *fixupNode) {

    // maintain red-black tree balance

    while (fixupNode != tree->root && fixupNode->colour == BLACK) {

        if (fixupNode == fixupNode->parent->left) {

            Node_t *siblingNode = fixupNode->parent->right;

            // Mark the siblingNode and its ancestors as needing update.
            markUpdateNeeded(siblingNode);

            if (siblingNode->colour == RED) {

                siblingNode->colour = BLACK;
                fixupNode->parent->colour = RED;

                leftRotate (tree, fixupNode->parent);

                siblingNode = fixupNode->parent->right;

                // Mark the siblingNode and its ancestors as needing update.
                markUpdateNeeded(siblingNode);
            }

            if (siblingNode->left->colour == BLACK && siblingNode->right->colour == BLACK) {
                siblingNode->colour = RED;

                fixupNode = fixupNode->parent;

            } else {
                if (siblingNode->right->colour == BLACK) {
                    siblingNode->left->colour = BLACK;
                    siblingNode->colour = RED;

                    rightRotate(tree, siblingNode);

                    siblingNode = fixupNode->parent->right;

                    // Mark the siblingNode and its ancestors as needing update.
                    markUpdateNeeded(siblingNode);
                }

                siblingNode->colour = fixupNode->parent->colour;
                fixupNode->parent->colour = BLACK;
                siblingNode->right->colour = BLACK;

                leftRotate(tree, fixupNode->parent);

                fixupNode = tree->root;
            }

        } else {

            Node_t *siblingNode = fixupNode->parent->left;

            // Mark the siblingNode and its ancestors as needing update.
            markUpdateNeeded(siblingNode);

            if (siblingNode->colour == RED) {
                siblingNode->colour = BLACK;
                fixupNode->parent->colour = RED;

                rightRotate(tree, fixupNode->parent);

                siblingNode = fixupNode->parent->left;

                // Mark the siblingNode and its ancestors as needing update.
                markUpdateNeeded(siblingNode);
            }

            if (siblingNode->right->colour == BLACK && siblingNode->left->colour == BLACK) {
                siblingNode->colour = RED;

                fixupNode = fixupNode->parent;

            } else {
                if (siblingNode->left->colour == BLACK) {
                    siblingNode->right->colour = BLACK;
                    siblingNode->colour = RED;

                    leftRotate(tree, siblingNode);

                    siblingNode = fixupNode->parent->left;

                    // Mark the siblingNode and its ancestors as needing update.
                    markUpdateNeeded(siblingNode);
                }

                siblingNode->colour = fixupNode->parent->colour;
                fixupNode->parent->colour = BLACK;
                siblingNode->left->colour = BLACK;

                rightRotate (tree, fixupNode->parent);

                fixupNode = tree->root;
            }
        }
    }

    fixupNode->colour = BLACK;
}


/*******************************************************************************
   Tree Rotations
*******************************************************************************/
// Left rotate moves a pivot node P left-wards down the tree (away from the root)
// and moves its right tree R to become its parent.
//
// - Right rotate is the inverse.
//
// - Requires node R to be _right_ node of pivot P.
//
// - Transforms:  P(TA, R(TB, TC))  To:  R(P(TA, TB), TC)
//   where P = pivot, R = right
//
// - Preserves ordering: TA < P < TB < R < TC
//
// - This transform does not change position of:
//   - TA, left node of P
//   - TC, right node of R
static void leftRotate(RBTree_t *tree, Node_t *pivotNode) {
    req_NonNull(tree);
    req_NonNull(pivotNode);

    if (nodeIsLeaf(pivotNode)) {
       diagnostic("rightRotate : pivot node is LEAF");
       codeError_exit();
    }

    Node_t *newPivotNode = pivotNode->right;

    // set pivotNode->right
    pivotNode->right = newPivotNode->left;
    if (nodeIsProper(newPivotNode->left)) newPivotNode->left->parent = pivotNode;

    // set newPivotNode->parent
    if (nodeIsProper(newPivotNode)) newPivotNode->parent = pivotNode->parent;
    if (nodeIsProper(pivotNode->parent)) {
        if (pivotNode == pivotNode->parent->left)
            pivotNode->parent->left = newPivotNode;
        else
            pivotNode->parent->right = newPivotNode;
    } else {
        // new root ...
        tree->root = newPivotNode;
    }

    // link pivotNode and newPivotNode
    newPivotNode->left = pivotNode;
    if (pivotNode != LEAF) pivotNode->parent = newPivotNode;

    // mark nodes that need updating ...
    markUpdateNeeded(pivotNode);
}


// Right rotate moves a pivot node P right-wards down the tree (away from the root)
// and moves its left tree L to become its parent.
//
// - Left rotate is the inverse.
//
// - Requires node L to be _left_ node of pivot P.
//
// - Transforms:  P(L(TA, TB), TC))  To:  L(TA, P(TB, TC))
//   where P = pivot, L = left
//
// - Preserves ordering: TA < L < TB < P < TC
//
// - This transform does not change position of:
//   - TA, left node of L
//   - TC, right node of P
static void rightRotate(RBTree_t *tree, Node_t *pivotNode) {
    req_NonNull(tree);
    req_NonNull(pivotNode);

    if (nodeIsLeaf(pivotNode)) {
       diagnostic("rightRotate : pivot node is LEAF");
       codeError_exit();
    }

    Node_t *newPivotNode = pivotNode->left;

    // setup pivotNode->left
    pivotNode->left = newPivotNode->right;
    if (nodeIsProper(newPivotNode->right)) newPivotNode->right->parent = pivotNode;

    // setup newPivotNode->parent
    if (nodeIsProper(newPivotNode)) newPivotNode->parent = pivotNode->parent;

    if (nodeIsProper(pivotNode->parent)) {
        if (pivotNode == pivotNode->parent->right)
            pivotNode->parent->right = newPivotNode;
        else
            pivotNode->parent->left = newPivotNode;
    } else {
        // new root ...
        tree->root = newPivotNode;
    }

    // link pivotNode and newPivotNode
    newPivotNode->right = pivotNode;
    if (pivotNode != LEAF) pivotNode->parent = newPivotNode;

    // mark nodes that need updating ...
    markUpdateNeeded(pivotNode);
}


/*******************************************************************************
   Attribute maintenance
*******************************************************************************/
static void updateAttrs_Tree(RBTree_t *tree) {
   req_NonNull(tree);

   // check for update
   if (!tree->root->needUpd) return;

   updateAttrs_All(tree->root);
}

static void markUpdateNeeded(Node_t *node) {

   while(nodeIsProper(node)) {
      // Check if node already marked
      if (node->needUpd) return;

		// Mark this node as needing needUpd
		node->needUpd = TRUE;

		// Now mark the _parent_ (if any) ...
		// Eventually this reaches the root or
		// some node already marked as needing update.
		node = node->parent;
	}
}

static void updateAttrs_All(Node_t *node) {
   if (nodeIsLeaf(node)) return;

   if (!node->needUpd) return;

   updateAttrs_All(node->left);
   updateAttrs_All(node->right);

   // Update current node using up-to-date info. from sub-trees.
   updateAttrs_Node(node);
}

static void forcedUpdateAttrs(Node_t *node) {
   if (nodeIsLeaf(node)) return;

   forcedUpdateAttrs(node->left);
   forcedUpdateAttrs(node->right);

   // Update current node using up-to-date info. from sub-trees.
   updateAttrs_Node(node);
}

// Just updates extended attributes for this node assuming data from sub-nodes is up-to-date
// - Returns TRUE if updates were made.
static Boolean_t updateAttrs_Node(Node_t *node) {
   if (nodeIsLeaf(node)) return FALSE;

   Boolean_t updateMade = FALSE;

   // Update height
   int leftHeight = nodeHeight(node->left);
   int rightHeight = nodeHeight(node->right);

   int newHeight = 1 + max(leftHeight, rightHeight);

   if (newHeight != node->height) {
      node->height = newHeight;
      updateMade = TRUE;
   }

   // Update bHeight
   int leftBH   =  totalBHeight(node->left);   // Calc. bHeight, incl. colour weighting ...
   int rightBH  =  totalBHeight(node->right);

   int newBH = max(leftBH, rightBH);  // This does NOT include colour weighting for the current node.

   if (newBH != node->bHeight) {
      node->bHeight = newBH;
      updateMade = TRUE;
   }

   // Update size
   int leftNumNodes   =  nodeNumNodes(node->left);
   int rightNumNodes  =  nodeNumNodes(node->right);

   int newNumNodes = 1 + leftNumNodes + rightNumNodes;

   if (newNumNodes != node->size) {
      node->size = newNumNodes;
      updateMade = TRUE;
   }

   // Clear the update flag ...
   node->needUpd = FALSE;

   return updateMade;
}


/*******************************************************************************
   Check tree and Red-Black Invariants

   - This checks structure of given tree and reports any issues found.
*******************************************************************************/
// Utility to check tree for integrity (useful for testing)
Boolean_t checkTree_RBT(RBTree_t *tree) {
   if (tree == NULL) return TRUE;
   if (nodeIsLeaf(tree->root)) return TRUE;

   Boolean_t treeStatus = TRUE;
   Boolean_t rootStatus = TRUE;

   Boolean_t outputStatus = outputCheckReports;

   outputCheckReports = (abortOnCheckFailure | outputStatus);

   if (!nodeIsBlack(tree->root)) {
      if (outputCheckReports) {
         printf("checkTree_RBT: Tree root 0x%lu is not BLACK.", convPtr(tree->root));
      }
      rootStatus = FALSE;
   }

   // check the tree ....
   treeStatus = check_treenode(tree->root);

   if (!treeStatus && abortOnCheckFailure) {
      printf("\n\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
      printf("FAILED TREE:\n\n");

      StringBuf_t *sBuf = new_SB();
      show_RBT(tree, sBuf);
      print_SB(sBuf);

      diagnostic("Aborting - checkTree_RBT failed");
      error_exit();
   }

   // resetting outputCheckReports
   outputCheckReports = outputStatus;

   return (rootStatus && treeStatus);
}


static void showReport(Node_t *node, char *msg) {
   if (outputCheckReports) {
      Key_t key = (nodeIsLeaf(node) ? NULL_KEY : node->key);

      if (show_ids) {
         printf("  Node %s (key: %s): %s\n", showNodeID(node), showKey(key), msg);
      } else {
         printf("  Node 0x%lu (key: %s): %s\n", convPtr(node), showKey(key), msg);
      }
   }
}


// Checks and updates nodes
static Boolean_t check_treenode(Node_t *node) {
   if (nodeIsLeaf(node)) return TRUE;

   // check and update sub-trees
   Boolean_t leftStatus  = check_treenode(node->left);
   Boolean_t rightStatus = check_treenode(node->right);

   // Update node attributes
   Boolean_t updateMade = updateAttrs_Node(node);
   if (updateMade) {
      //showReport(node, "Updates to attributes were made for node.");
      diagnostic("Updates to attributes were made for node = %s", showNodeID(node));
      error_exit();
   }

   // Check subnode parents ...
   Boolean_t parentStatus = check_subnode_parents(node);

   // Check RB properties ...
   Boolean_t nodeStatus = check_RB_properties(node);

   return (nodeStatus && parentStatus && leftStatus && rightStatus);
}

static Boolean_t check_subnode_parents(Node_t *node) {
   if (nodeIsLeaf(node)) return TRUE;

   Boolean_t status = TRUE;

   // check left parent
   if (nodeIsProper(node->left)) {
      if (node->left->parent != node) {
         showReport(node, "Parent of (node->left) is not equal to node");
         status = FALSE;
      }
   }

   // check right parent
   if (nodeIsProper(node->right)) {
      if (node->right->parent != node) {
         showReport(node, "Parent of (node->right) is not equal to node");
         status = FALSE;
      }
   }

   return status;
}

static char __checkMsgBuffer[1024];
static Boolean_t check_RB_properties(Node_t *node) {
   if (nodeIsLeaf(node)) return TRUE;

   Key_t key = node->key;

   Boolean_t status = TRUE;

   // Check node colour property
   if (nodeIsRed(node)) {
      if (nodeIsRed(node->left)) {
         showReport(node, "Colour property violated (both node and node-left are RED)");
         status = FALSE;
      }

      if (nodeIsRed(node->right)) {
         showReport(node, "Colour property violated (both node and node-right are RED)");
         status = FALSE;
      }
   }

   // Check black-height balance property
   if (!nodeIsBalanced(node)) {
      // construct tmp message ...
      sprintf(__checkMsgBuffer, "Black height property broken: left BH = %i =/= right BH = %i",
              totalBHeight(node->left),
              totalBHeight(node->right));

      showReport(node, __checkMsgBuffer);

      status = FALSE;
   }

   return status;
}


/*******************************************************************************
   Showing Keys and Pointers
*******************************************************************************/
#define INT_KEY_LIMIT  100001
static char keyBuffer[LINE_BUFSIZE+1];

static char *showKey(Key_t key) {
   if (key == NULL_KEY) return "NULL_KEY";

   long keyVal = (long)key;

   if (keyVal < -INT_KEY_LIMIT || keyVal > INT_KEY_LIMIT) {
      sprintf(keyBuffer, "0x%lu", convPtr((void *)key));
   } else {
      sprintf(keyBuffer, "%i", (int)keyVal);
   }

   return keyBuffer;
}

// This will convert pointers for display just to show the last two bytes
static Ptr_t convPtr(void *addr) {
   Ptr_t ptr = (Ptr_t)addr;
   return (show_simplified_addr ? ptr % 0x10000 : ptr);
}

/*******************************************************************************
   Showing RB Trees
*******************************************************************************/
static void initShowTree(StringBuf_t *sbuf);
static void showTree(RBTree_t *mTree);

static void setCurIndent(int indentLevel);
static void showTreeNode(Node_t *node, int indentLevel);
static void showNodeCore(Node_t *node, int indentLevel);

static StringBuf_t *curSBuf = NULL;
static int maxLevel = 15;
static char *curIndent = NULL;

static int indentLen     = 0;
static int incrIndentLen = 0;
static int totalIndentLength = 0;

static void setCurIndent(int indentLevel) {

   // ensure initialisation
   if (curIndent == NULL) {
      totalIndentLength = LINE_BUFSIZE+1;
      curIndent = ALLOC_ARR(totalIndentLength, char);

      // initialising lengths etc. ...
      indentLen  = strlen(show_indent);
      incrIndentLen = strlen(show_incrIndent);

      if (incrIndentLen <= 0) {
         diagnostic("setCurIndent: Bad incrIndentLen = %i", incrIndentLen);
         codeError_exit();
      }
   }

   // initialise by copying indent into curIndent
   strcpy(curIndent, show_indent);

   // set starting point
   char *nextIndent = curIndent+indentLen;

   for (int i = 0; i < indentLevel; i++) {
      // copy incremental
      strcpy(nextIndent, show_incrIndent);
      nextIndent += incrIndentLen;
   }
}

static void showNodeCore(Node_t *node, int indentLevel) {
   if (nodeIsLeaf(node)) return;

   if (!show_tightly) {
      addItems_SB(curSBuf, "    :\n");
   }
   addItems_SB(curSBuf, "%4i:%sNode key:   %s\n",    indentLevel, curIndent, showKey(node->key));

   if (show_ids) {
		addItems_SB(curSBuf, " ...:%sNode ID:    %s\n",    curIndent, showNodeID(node));
		addItems_SB(curSBuf, " ...:%sParent ID:  %s\n",    curIndent, showNodeID(nodeParent(node)));
   }

   if (show_addrs) {
		addItems_SB(curSBuf, " ...:%sNode obj:   0x%lu\n", curIndent, convPtr(node));
		addItems_SB(curSBuf, " ...:%sParent obj: 0x%lu\n", curIndent, convPtr(nodeParent(node)));
   }

   char *balanced = (nodeIsBalanced(node) ? "" : "   *** UNBALANCED ***");

   if (show_details) {
 		addItems_SB(curSBuf, " ...:%sColour:     %s%s\n",  curIndent, showNodeColour(node), balanced);
		addItems_SB(curSBuf, " ...:%sBHeight:    %i\n",    curIndent, nodeBHeight(node));
		addItems_SB(curSBuf, " ...:%sHeight:     %i\n",    curIndent, node->height);
		addItems_SB(curSBuf, " ...:%s# Nodes:    %i\n",    curIndent, nodeNumNodes(node));
   }
}

static void showSpacerLine() {
   if (!show_tightly) {
      addItems_SB(curSBuf, "    :\n");
   }
}

static char *showLeaf(Node_t *node) {
   return (node == NULL ?  "NULL" : node == LEAF ? "LEAF" : "???");
}

static void showTreeNode(Node_t *node, int indentLevel) {

   // set current indent level
   setCurIndent(indentLevel);

   if (nodeIsLeaf(node)) {
      addItems_SB(curSBuf, "%4i:%s%s\n", indentLevel, curIndent, showLeaf(node));
      return;
   }

   // check if indentLevel exceeds maxLevel
   if (indentLevel > maxLevel) {
      addItems_SB(curSBuf, "%4i:%s...\n", indentLevel, curIndent);
      return;
   }

   // Display the node pre-order
   if (!show_inorder) {
      showNodeCore(node, indentLevel);

      showSpacerLine();
   }

   if (nodeIsLeaf(node->left)) {
		if (show_ids) {
         addItems_SB(curSBuf, "%4i:%sLEFT  (for node %s): %s\n", indentLevel, curIndent, showNodeID(node), showLeaf(node->left));
		} else {
         addItems_SB(curSBuf, "%4i:%sLEFT  (for node 0x%lu): %s\n", indentLevel, curIndent, convPtr(node), showLeaf(node->left));
		}

   } else {
		if (show_ids) {
         addItems_SB(curSBuf, "%4i:%sLEFT  (for node %s):\n", indentLevel, curIndent, showNodeID(node));
		} else {
         addItems_SB(curSBuf, "%4i:%sLEFT  (for node 0x%lu):\n", indentLevel, curIndent, convPtr(node));
		}
		showTreeNode(node->left, indentLevel+1);

		setCurIndent(indentLevel);
	}

   showSpacerLine();

   // Display the node in-order
   if (show_inorder) {
      showNodeCore(node, indentLevel);

      showSpacerLine();
   }

   if (nodeIsLeaf(node->right)) {
		if (show_ids) {
         addItems_SB(curSBuf, "%4i:%sRIGHT (for node %s): %s\n", indentLevel, curIndent, showNodeID(node), showLeaf(node->right));
		} else {
         addItems_SB(curSBuf, "%4i:%sRIGHT (for node 0x%lu): %s\n", indentLevel, curIndent, showNodeID(node), showLeaf(node->right));
		}

   } else {
		if (show_ids) {
         addItems_SB(curSBuf, "%4i:%sRIGHT (for node %s):\n", indentLevel, curIndent, showNodeID(node));
		} else {
         addItems_SB(curSBuf, "%4i:%sRIGHT (for node 0x%lu):\n", indentLevel, curIndent, convPtr(node));
		}
      showTreeNode(node->right, indentLevel+1);
   }

   //addItems_SB(curSBuf, "    :\n");

}


static void initShowTree(StringBuf_t *sbuf) {
   // set the string buffer
   curSBuf = sbuf;
}

static void showTree(RBTree_t *tree) {
   req_NonNull(tree);

   setCurIndent(0);
   addItems_SB(curSBuf, "%sRBTree <size:%i>\n", curIndent, getSize_RBT(tree));

   // show the full tree if not compact ...
   if (!show_compact_display) {
      showTreeNode(tree->root, 0);
   }
}
