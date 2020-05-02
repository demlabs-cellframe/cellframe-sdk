/* merkleTree.c

   An Implementation of Merkle Trees

   Merkle Tree
   - Standard Peer-2-Peer hashing of a sequence of blocks
   - Handles building of data sequence in random order ...
   - Merkle, R. C. (1988). "A Digital Signature Based on a Conventional Encryption Function".
     Advances in Cryptology — CRYPTO '87. Lecture Notes in Computer Science 293. p. 369

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
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "alloc.h"
#include "hashlib.h"
#include "merkleTree.h"


// Merkle Tree Structures
// - Two kinds of node - internal nodes and leaf nodes.
typedef void MTreeNode_t;        // generic tree node type - covers (internal) node and leaf structs.

typedef struct mLeaf MLeaf_t;    // Leaf node type
typedef struct mNode MNode_t;    // (internal) node type


// Root Merkle Tree object
struct merkleTree {
   HashSpec_t         hashSpec;      // Type of HashSpec
   Digest_t          *topHash;       // Final digest value -- weak reference (NO allocation)
   int                blockCount;    // Current total of data blocks
   int                maxPosition;   // Max position
   int                height;        // Total height of tree
   int                totalNodes;    // Total number of tree nodes (i.e. both internal nodes and leaves)
   Boolean_t          autoClean;     // if TRUE, deallocates nodes as soon as possible.
   MTreeState_t       state;         // Current state
   MTreeNode_t       *treeRoot;      // Tree nodes ...
};

// Define tag values for the two different kinds of tree node.
// - tag values are always the first byte of object ... (see utils.h)
#define TAG_MLeaf_t   (Tag_t)'L'
#define TAG_MNode_t   (Tag_t)'N'

// Tag checks
#define isLeaf(obj)   (checkTag((obj), TAG_MLeaf_t))
#define isNode(obj)   (checkTag((obj), TAG_MNode_t))

// Internal nodes
// - have pivots + base
// - these have two sub-trees
struct mNode {
   Tag_t           tag;         // Tag for tree node
   int             height;      // Height of tree
   int             pivot;       // Pivot
   int             base;        // Base
   Digest_t       *digest;      // Digest
   MTreeNode_t    *left;        // Left  sub tree
   MTreeNode_t    *right;       // Right sub tree
};


// - Leaf nodes
//     + have positions
//     + has non-NULL digest
struct mLeaf {
   Tag_t           tag;         // Tag for tree leaf
   int             position;    // Position
   Digest_t       *digest;      // Digest
};


/*******************************************************************************
   Memory Management
*******************************************************************************/
MemMgr_t *merkleTree_MemMgr = NULL;
MemMgr_t *leaf_MemMgr       = NULL;
MemMgr_t *node_MemMgr       = NULL;


/*******************************************************************************
   Static method prototypes
*******************************************************************************/
static void ensureMemMgmt();

static MTreeNode_t *allocate_Leaf(MTree_t *mTree, int position, Digest_t *digest);
static MTreeNode_t *allocate_Node(MTree_t *mTree, int height, int base, MTreeNode_t *left, MTreeNode_t *right);

static void deallocate_TreeNode(MTree_t *mTree, void *obj);
static void deallocate_Node(MTree_t *mTree, MNode_t *obj);
static void deallocate_Leaf(MTree_t *mTree, MLeaf_t *obj);

static int calcPivot(int height, int base);
static int calcHeight(int position);

static void setLeft(MTree_t *mTree, MNode_t *node, MTreeNode_t *left);
static void setRight(MTree_t *mTree, MNode_t *node, MTreeNode_t *right);

static Digest_t *getDigest(MTreeNode_t *item);
static void calcDigest(MTree_t *mTree, MTreeNode_t *item);
static void calcTreeDigest(MTree_t *mTree, MTreeNode_t *item, Boolean_t isComplete);
static void rightmostPromotion(MTree_t *mTree, MNode_t *node);

static void inflateTree(MTree_t *mTree, int nodeHeight);
static void insertNode(MTree_t *mTree, MTreeNode_t *curNode, MTreeNode_t *newTreeNode);

// showing tree state
static void initShowTree(StringBuf_t *sbuf);
static void showTree(MTree_t *mTree);
static void resetShowTree();

// display node
static char *displayNode(MTreeNode_t *item);


/*******************************************************************************
   Methods
*******************************************************************************/

// The default auto clean
Boolean_t autoCleanDefault = FALSE;

// New Merkle Tree
MTree_t *new_MT(HashSpec_t hSpec) {
   return allocate_MT(hSpec, autoCleanDefault);
}

MTree_t *allocate_MT(HashSpec_t hSpec, Boolean_t autoClean) {
   // ensure that the allocation structures exist ...
   ensureMemMgmt();

   MTree_t *newTree = allocateObject_MM(merkleTree_MemMgr);

   // reset attributes
   newTree->hashSpec     = hSpec;
   newTree->topHash      = NULL;   // weak reference to top digest (NO allocation!)
   newTree->blockCount   = 0;
   newTree->maxPosition  = -1;
   newTree->height       = 0;
   newTree->totalNodes   = 0;
   newTree->autoClean    = FALSE; //autoClean;
   newTree->state        = MTree_Initial;
   newTree->treeRoot     = NULL;

   return newTree;
}


// Deallocate/recycle Merkle Tree
void deallocate_MT(MTree_t *mTree) {
   if (mTree == NULL) return;

   // ensure that the allocation structures exist ...
   ensureMemMgmt();

   // deallocate tree nodes
   deallocate_TreeNode(mTree, mTree->treeRoot);

   // nullify elements
   mTree->hashSpec    = HSP_NULL;
   mTree->topHash     = NULL;
   mTree->blockCount  = 0;
   mTree->maxPosition = 0;
   mTree->height      = 0;
   mTree->totalNodes  = 0;
   mTree->autoClean   = FALSE;
   mTree->state       = MTree_NULL;
   mTree->treeRoot    = NULL;

   deallocateObject_MM(merkleTree_MemMgr, sizeof(MTree_t), mTree);
}


// Resets the given hash tree
void reset_MT(MTree_t *mTree, HashSpec_t hSpec) {
   req_NonNull(mTree);

   // ensure that the allocation structures exist ...
   ensureMemMgmt();

   // capture autoClean state
   Boolean_t autoClean = mTree->autoClean;

   //deallocate tree nodes
   deallocate_TreeNode(mTree, mTree->treeRoot);

   // reset attributes
   mTree->hashSpec    = hSpec;
   mTree->topHash     = NULL; // weak ref.
   mTree->blockCount  = 0;
   mTree->maxPosition = -1;
   mTree->height      = 0;
   mTree->totalNodes  = 0;
   mTree->autoClean   = autoClean;
   mTree->state       = MTree_Initial;
   mTree->treeRoot    = NULL;
}


// Gets current Hash Spec
HashSpec_t getHashSpec_MT(MTree_t *mTree) {
   req_NonNull(mTree);

   return mTree->hashSpec;
}

// Gets Top Hash - if defined
// - This clones the mTree's digest object into given digest, dgst.
// - Returns TRUE only if digest was cloned.
Boolean_t getTopHash_MT(Digest_t *dgst, MTree_t *mTree) {
   req_NonNull(dgst);
   req_NonNull(mTree);

   if (mTree->topHash == NULL || mTree->state != MTree_Final) {
      return FALSE;
   }
   else {
      clone_DG(dgst, mTree->topHash);

      return TRUE;
   }
}


// Get the total number of data blocks so far.
int getNumBlocks_MT(MTree_t *mTree) {
   req_NonNull(mTree);

   return mTree->blockCount;
}

// Get the maximum position used so far
int getMaxPosition_MT(MTree_t *mTree) {
   req_NonNull(mTree);

   return mTree->maxPosition;
}

// Gets the height of the hash tree ...
int getHeight_MT(MTree_t *mTree)  {
   req_NonNull(mTree);

   return mTree->height;
}

// Gets the total number of tree nodes (i.e. internal nodes and leaves).
int getTotalNodes_MT(MTree_t *mTree) {
   req_NonNull(mTree);

   return mTree->totalNodes;
}

// Gets the auto clean flag.
// - if TRUE, deallocate tree nodes as soon as possible.
Boolean_t getAutoClean_MT(MTree_t *mTree) {
   req_NonNull(mTree);

   return mTree->autoClean;
}

// Inspect current state ...
MTreeState_t getState_MT(MTree_t *mTree) {
   req_NonNull(mTree);

   return mTree->state;
}

// Show current state ...
char *showState_MT(MTree_t *mTree) {
   req_NonNull(mTree);

   // process current state
   switch (mTree->state) {
      case MTree_NULL:     return "NULL state";

      case MTree_Initial:  return "Initialised";
      case MTree_Partial:  return "Partial";
      case MTree_Complete: return "Complete";
      case MTree_Final:    return "Final";

      default:
         diagnostic("merkleTree.showState_MT : Unknown state: %i\n", mTree->state);
         codeError_exit();
   }
}


// Show hash tree by appending to stringbuffer
// - set indent string
// - set incrment indent string
// - set compact display
// - set max depth
void show_MT(MTree_t *mTree, StringBuf_t *sbuf) {
   req_NonNull(mTree);
   req_NonNull(sbuf);

   initShowTree(sbuf);
   showTree(mTree);
}

// show attributes
static char *show_indent = "   ";                // indent string
static char *show_incrIndent = "   ";;           // incremental indent
static Boolean_t show_compact_display = FALSE;
static int show_max_depth = -1;

void setShowIndent_MT(char * indent) {
   int indentLen = strlen(indent);

   if (2 <= indentLen && indentLen < MAX_INDENT_LENGTH) {
		show_indent = indent;
		resetShowTree();
   }
   else {
      diagnostic("merkleTree.setShowIndent : Bad indent length: %i", indentLen);
      codeError_exit();
   }
}

void setShowIncrIndent_MT(char * indent) {
   int indentLen = strlen(indent);

   if (2 <= indentLen && indentLen < MAX_INDENT_LENGTH) {
		show_incrIndent = indent;
		resetShowTree();
   }
   else {
      diagnostic("merkleTree.setShowIncrIndent : Bad indent length: %i", indentLen);
      codeError_exit();
   }
}

void setShowCompact_MT(Boolean_t isCompact) {
	show_compact_display = asBoolean(isCompact);
}

// sets max depth
// - giving non-positive value removes constraint
void setShowMaxDepth_MT(int maxDepth) {
	show_max_depth = minmax(0, maxDepth, MAX_TREE_HEIGHT);
}


/*******************************************************************************
   Adding Data Blocks
*******************************************************************************/
// Add data blocks into tree
// - Requires that the tree has been initialised and has not yet been finalised.
// - position is 1-based and runs from 1 to K
void addDataBlock_MT(MTree_t *mTree, int position, ByteVec_t *dataVec) {
   req_NonNull(mTree);
   req_Pos(position);

   // Make position 0-based ...
   position = position - 1;

   // sanity check
   if (mTree->state == MTree_Final) {
      diagnostic("merkleTree.addDataBlock_MT : Can't add more data to an already finalised tree");
      codeError_exit();
   }

   // process current state
   switch (mTree->state) {
      case MTree_NULL:
		   diagnostic("merkleTree.addDataBlock_MT : Undefined NULL state");
		   codeError_exit();

      case MTree_Initial:  break;
      case MTree_Partial:  break;
      case MTree_Complete: break;
      case MTree_Final:
		   diagnostic("merkleTree.addDataBlock_MT : Can't add more data to an already finalised tree");
		   codeError_exit();

      default:
         diagnostic("merkleTree.addDataBlock_MT : Unknown state: %i\n", mTree->state);
         codeError_exit();
   }

   // Prepare the new block
   HashSpec_t hSpec     = mTree->hashSpec;
   Digest_t *dataDigest = new_DG(hSpec);

   // Calculate dataDigest ...
   Boolean_t stat = hashBV_DG(dataDigest, dataVec);
   if (!stat) {
      diagnostic("merkleTree.addDataBlock_MT : Data hashing failed!");
      codeError_exit();
   }

   // Build new leaf node
   MTreeNode_t *newLeaf = allocate_Leaf(mTree, position, dataDigest);

   // Inflate tree to correct height
   // - if the tree is already of sufficient height, then no change.
   // - else extends tree from the root
   inflateTree(mTree, calcHeight(position));

   // Insert new node into tree of correct height ...
   insertNode(mTree, mTree->treeRoot, newLeaf);

   // Update the number of blocks
   mTree->blockCount += 1;

   // Update the max position
   mTree->maxPosition = max(mTree->maxPosition, position);

   // update state
   Boolean_t isComplete = (mTree->maxPosition + 1 == mTree->blockCount);
   mTree->state = (isComplete ? MTree_Complete : MTree_Partial);
}


// Finalise the tree (if possible)
// - When complete, determines the full tree digest ...
// - Returns true if successfully finalised, otherwise false.
Boolean_t finalise_MT(MTree_t *mTree) {
   req_NonNull(mTree);

   // process current state
   switch (mTree->state) {
      case MTree_NULL:
		   diagnostic("merkleTree.finalise_MT : Undefined NULL state");
		   codeError_exit();
      case MTree_Initial:  return FALSE;
      case MTree_Partial:  break;
      case MTree_Complete: break;
      case MTree_Final:    return TRUE;
      default:
         diagnostic("merkleTree.finalise_MT : Unknown state: %i\n", mTree->state);
         codeError_exit();
   }

   Boolean_t isComplete = (mTree->maxPosition+1 == mTree->blockCount);

   if (isComplete) {
      calcTreeDigest(mTree, mTree->treeRoot, TRUE);

      Digest_t *rootDigest = getDigest(mTree->treeRoot);

      if (rootDigest == NULL) {
         return FALSE;
      }
      else {
         mTree->topHash = rootDigest;  // getTopHash_MT clones this value.
         mTree->state = MTree_Final;

         return TRUE;
      }
   }

   return FALSE;
}

/*******************************************************************************
   Static methods
*******************************************************************************/
static void ensureMemMgmt() {
   if (merkleTree_MemMgr == NULL) {
      merkleTree_MemMgr  = new_MM(sizeof(MTree_t));
   }

   if (leaf_MemMgr == NULL) {
      leaf_MemMgr  = new_MM(sizeof(MLeaf_t));
   }

   if (node_MemMgr == NULL) {
      node_MemMgr  = new_MM(sizeof(MNode_t));
   }
}

static MTreeNode_t *allocate_Node(MTree_t *mTree, int height, int base, MTreeNode_t *left, MTreeNode_t *right) {

   // ensure that the allocation structures exist ...
   ensureMemMgmt();

   MNode_t *newNode = allocateObject_MM(node_MemMgr);

   // increment totalNodes
   mTree->totalNodes += 1;

   // set internal node attributes
   newNode->tag       = TAG_MNode_t;
   newNode->height    = height;
   newNode->pivot     = calcPivot(height, base);
   newNode->base      = base;
   newNode->digest    = NULL;
   newNode->left      = left;
   newNode->right     = right;

   // if possible, calc digest for this node
   calcDigest(mTree, newNode);

   return (MTreeNode_t *)newNode;
}

static MTreeNode_t *allocate_Leaf(MTree_t *mTree, int position, Digest_t *digest) {
   req_NonNull(digest);

   // ensure that the allocation structures exist ...
   ensureMemMgmt();

   MLeaf_t *newLeaf = allocateObject_MM(leaf_MemMgr);

   // increment totalNodes
   mTree->totalNodes += 1;

   // set leaf node attributes
   newLeaf->tag       = TAG_MLeaf_t;
   newLeaf->position  = position;
   newLeaf->digest    = digest;

   return (MTreeNode_t *)newLeaf;
}

static void deallocate_TreeNode(MTree_t *mTree, void *obj) {
   if (obj == NULL) return;

   if (checkTag(obj, TAG_MNode_t)) {
      deallocate_Node(mTree, (MNode_t *)obj);
   }
   else if (checkTag(obj, TAG_MLeaf_t)) {
      deallocate_Leaf(mTree, (MLeaf_t *)obj);
   }
   else {
      diagnostic("deallocate_TreeNode:  Unrecognised tag value: 0x%u", tagOf(obj));
      codeError_exit();
   }
}

static void deallocate_Node(MTree_t *mTree, MNode_t *node) {
   if (node == NULL) return;

   // ensure that the allocation structures exist ...
   ensureMemMgmt();

   // deallocate the digest
   deallocate_DG(node->digest);

   // deallocate left and right nodes (recursive calls)
   deallocate_TreeNode(mTree, node->left);
   deallocate_TreeNode(mTree, node->right);

   // nullify the attributes of node (except tag)
   node->height  = 0;
   node->pivot   = 0;
   node->base    = 0;
   node->digest  = NULL;
   node->left    = NULL;
   node->right   = NULL;

   // recycle the current tree node
   deallocateObject_MM(node_MemMgr, sizeof(MNode_t), node);

   // decrement totalNodes
   mTree->totalNodes -= 1;
   if (mTree->totalNodes < 0) {
      diagnostic("merkleTree.deallocate_Node: Total number of nodes is negative!!");
      codeError_exit();
   }
}

static void deallocate_Leaf(MTree_t *mTree, MLeaf_t *leaf) {
   if (leaf == NULL) return;

   // ensure that the allocation structures exist ...
   ensureMemMgmt();

   // deallocate the digest
   deallocate_DG(leaf->digest);

   // nullify the attributes of leaf (except tag)
   leaf->position  = 0;
   leaf->digest    = NULL;

   // recycle the current tree node
   deallocateObject_MM(leaf_MemMgr, sizeof(MLeaf_t), leaf);

   // decrement totalNodes
   mTree->totalNodes -= 1;
   if (mTree->totalNodes < 0) {
      diagnostic("merkleTree.deallocate_Leaf: Total number of nodes is negative!!");
      codeError_exit();
   }
}


// Calculates the pivot value for a given height and base values
static int calcPivot(int height, int base) {
   // pivot = base + 2^(height - 1)
   return base + pow2(height-1);
}

// Calculates the height of tree needed to enclose a given position
// - minimum height = 1
// - maximum height = 31 (!!)
static int calcHeight(int position) {
   for (int h = 1; h < 32; h++) {
       if (position < pow2(h)) {
          return h;
       }
   }

   return -1;
}

// gets the height for a non-null tree node
static int getHeightOfNode(MTreeNode_t *node) {
   req_NonNull(node);

   switch (tagOf(node)) {
      case TAG_MLeaf_t: return 0;
      case TAG_MNode_t: return ((MNode_t *)node)->height;
      default:
         diagnostic("merkleTree.getHeightOfNode: Bad tag value: %i\n", tagOf(node));
         codeError_exit();
   }
}

// gets the pivot value for a non-null tree node
static int getPivotOfNode(MTreeNode_t *node) {
   req_NonNull(node);

   switch (tagOf(node)) {
      case TAG_MLeaf_t: return ((MLeaf_t *)node)->position;
      case TAG_MNode_t: return ((MNode_t *)node)->pivot;
      default:
         diagnostic("merkleTree.getPivotOfNode: Bad tag value: %i\n", tagOf(node));
         codeError_exit();
   }
}


// sets the left sub-tree and calc digest (if poss.)
static void setLeft(MTree_t *mTree, MNode_t *node, MTreeNode_t *left) {

   req_NonNull(mTree);
   req_NonNull(node);
   req_NonNull(left);

   if (node->left != NULL) {
      diagnostic("merkelTree.setLeft : Left sub-tree is already defined for node.");
      error_exit();
   }
   // update the left sub-tree
   node->left = left;
   // if possible, calc digest for this node
   calcDigest(mTree, node);
}


// sets the right sub-tree and calc digest (if poss.)
static void setRight(MTree_t *mTree, MNode_t *node, MTreeNode_t *right) {
   req_NonNull(mTree);
   req_NonNull(node);
   req_NonNull(right);

   if (node->right != NULL) {
      diagnostic("merkelTree.setRight : Right sub-tree is already defined for node.");
      error_exit();
   }
   // update the right sub-tree
   node->right = right;

   // if possible, calc digest for this node
   calcDigest(mTree, node);
}


// extracts digest if possible - otherwise NULL
static Digest_t *getDigest(MTreeNode_t *item) {
   if (item == NULL) return NULL;

   switch (tagOf(item)) {
      case TAG_MLeaf_t: return ((MLeaf_t *)item)->digest;
      case TAG_MNode_t: return ((MNode_t *)item)->digest;
      default:
         return NULL;
   }
}

// Calculates digest for tree recursively and updates item
static void calcDigest(MTree_t *mTree, MTreeNode_t *item) {
   calcTreeDigest(mTree, item, FALSE);
}

// Calculates digest for tree recursively and updates item
// - the flag isComplete signals when to complete and perform rightmost promotion
//   for any incomplete rightmost subtrees.
static void calcTreeDigest(MTree_t *mTree, MTreeNode_t *item, Boolean_t isComplete) {
   if (item == NULL) return;
   req_NonNull(mTree);

   if (isLeaf(item)) {
      // Leaf nodes always have a digest
      return;
   }
   else if (isNode(item)) {
      MNode_t *node = (MNode_t *)item;

      // check if digest already exists
      if (node->digest != NULL) return;

      // Try calc. digest if when left and right sub-trees exist.
		if (node->left != NULL) {
		   // Left hand node is non-null

		   if (node->right != NULL) {
				// if possible, calc digests (recursive step)
				calcTreeDigest(mTree, node->left, FALSE);  // No promotion step for internal nodes
				calcTreeDigest(mTree, node->right, isComplete);

				// extract digests and check if non-NULL
				Digest_t *leftDigest  = getDigest(node->left);
				if (leftDigest == NULL) return;

				Digest_t *rightDigest = getDigest(node->right);
				if (rightDigest == NULL) return;

				// Both digests exist ... so now build digest object
				HashSpec_t hSpec = getHashSpec_DG(leftDigest);
				Digest_t *nodeDigest = new_DG(hSpec);

				// set up temp bytevector
				ByteVec_t *tempBV = new_BV();
				// Load up temp bytevector
				getHashValue_DG(leftDigest, tempBV);  // Add in left bytevector

				getHashValue_DG(rightDigest, tempBV); // Add in right bytevector

				// Hash the contents of tempBV
				hashBV_DG(nodeDigest, tempBV);

				// Link new digest to node
				node->digest = nodeDigest;

				// recycle temp bytevector
				deallocate_BV(tempBV);
				// If autoClean is set, deallocate nodes
				if (mTree->autoClean) {
				   deallocate_TreeNode(mTree, node->left);
				   deallocate_TreeNode(mTree, node->right);
				}
			}
			else if (isComplete) {
            rightmostPromotion(mTree, node);
			}
		}
	}
}


// Rightmost Promotion step.
// This "rightmost promotion step" is needed when the binary tree is not completely filled
// e.g. the number of total positions filled isn't the maximum possible.
// In that case there will be some rightmost subtrees with NULL right subtrees,
// which are not going to be filled i.e. acquire a digest.
//
// Thus, promotion only used on the rightmost nodes which have NULL right nodes.
// Thus, never used "internally" to tree.
//
// Promotion then takes the non-NULL left most elements and uses
// those hashes in the nodes above.
static void rightmostPromotion(MTree_t *mTree, MNode_t *node) {
   req_NonNull(mTree);
   req_NonNull(node);

	//  recursive step ...
	calcTreeDigest(mTree, node->left, TRUE);

	// Fetch the leftDigest
	Digest_t *leftDigest = getDigest(node->left);

   // Check that the digest is defined ...
	if (leftDigest != NULL) {
		HashSpec_t hSpec = getHashSpec_DG(leftDigest);
		Digest_t *nodeDigest = new_DG(hSpec);

		if (!clone_DG(nodeDigest, leftDigest)) {
		   diagnostic("merkleTree.rightmostPromotion : Failed to clone digest");
		   codeError_exit();
		}

		// copy cloned digest ...
		node->digest = nodeDigest;
	}
}


// Inflate tree to correct height, as needed.
static void inflateTree(MTree_t *mTree, int nodeHeight) {

   req_NonNull(mTree);
   req_PosZero(nodeHeight);

   if (nodeHeight <= mTree->height) return;

   // update the mTree's height ...
   mTree->height = nodeHeight;

   // need to inflate tree ...
   if (mTree->treeRoot == NULL) {
		// set new root of correct height
      mTree->treeRoot = allocate_Node(mTree, nodeHeight, 0, NULL, NULL);
   }
   else {
		// capture old root
		MTreeNode_t *oldRoot = mTree->treeRoot;

		// set new root of correct height
      mTree->treeRoot = allocate_Node(mTree, nodeHeight, 0, NULL, NULL);

		//insert old root back into tree ...
		insertNode(mTree, mTree->treeRoot, oldRoot);
   }
}

// recursive insertion of a node into tree
static void insertNode(MTree_t *mTree, MTreeNode_t *treeNode, MTreeNode_t *newTreeNode) {

   req_NonNull(mTree);
   req_NonNull(treeNode);
   req_NonNull(newTreeNode);

   // check tags ...
   switch (tagOf(treeNode)) {
      case TAG_MLeaf_t:
		   diagnostic("merkleTree.insertNode : Current node is a leaf - can't insert anything into a leaf");
		   codeError_exit();

      case TAG_MNode_t:
         break;

      default:
         diagnostic("merkleTree.insertNode: Bad tag value: 0x%x\n", (Byte_t)tagOf(treeNode));
         codeError_exit();
   }

   MNode_t *curNode = (MNode_t *)treeNode;
   int curHeight = curNode->height;
   int curPivot = curNode->pivot;

   int nodeHeight = getHeightOfNode(newTreeNode);
   int nodePivot  = getPivotOfNode(newTreeNode);

   // sanity checks ...
   if (curHeight <= 0) {
      diagnostic("merkleTree.insertNode : Current height (%i) of node is not positive", curHeight);
      codeError_exit();
   }

   if (curHeight < nodeHeight) {
      diagnostic("merkleTree.insertNode : Height of current node (%i) < height of new node (%i)", curHeight, nodeHeight);
      codeError_exit();
   }

   if (curHeight-1 == nodeHeight) {
      // insert newTreeNode as direct subtree of curNode
      // - this must be currently NULL
      if (nodePivot < curPivot) {
         setLeft(mTree, curNode, newTreeNode);
      }
      else {
         setRight(mTree, curNode, newTreeNode);
      }
   }
   else {
      // Need to insert newTreeNode further down ...
      if (nodePivot < curPivot) {
         // insert into left sub tree
         MTreeNode_t *leftNode = curNode->left;
         if (leftNode == NULL) {
            int leftBase = curNode->base;
            leftNode = allocate_Node(mTree, curHeight-1, leftBase, NULL, NULL);

            // attach new left node to current node
            setLeft(mTree, curNode, leftNode);
         }

         // recursive call to insertNode
         insertNode(mTree, leftNode, newTreeNode);
      }
      else {
         // insert into right sub tree
         MTreeNode_t *rightNode = curNode->right;
         if (rightNode == NULL) {
            int rightBase = curPivot;
            rightNode = allocate_Node(mTree, curHeight-1, rightBase, NULL, NULL);

            // attach new right node to current node
            setRight(mTree, curNode, rightNode);
         }

         // recursive call to insertNode
         insertNode(mTree, rightNode, newTreeNode);
      }
   }
}

// Useful basic displayer of nodes ...
static StringBuf_t *displaySB = NULL;
static int fpLength = 8;
char *displayNode(MTreeNode_t *item) {
   if (item == NULL) return NULL_STR;

   if (displaySB == NULL) {
      displaySB = new_SB();
   }
   else {
      reset_SB(displaySB);
   }

   if (isNode(item)) {
      MNode_t *node = (MNode_t *)item;

      int height = node->height;
      int pivot  = node->pivot;
      int base   = node->base;
      char *digestStr = showFingerprint_DG(node->digest, fpLength);

      addItems_SB(displaySB, "Node <id=0x%lx, height=%i, pivot=%i, base=%i, digest=%s>"
                           , (unsigned long)node
                           , height
                           , pivot
                           , base
                           , digestStr
                           );
   }
   else if (isLeaf(item)) {
      MLeaf_t *leaf = (MLeaf_t *)item;
      int position  = leaf->position;
      char *digestStr = showFingerprint_DG(leaf->digest, fpLength);

      addItems_SB(displaySB, "Leaf <id=0x%lx, position=%i, digest=%s>"
                           , (unsigned long)leaf
                           , position
                           , digestStr
                           );
   }
   else {
     diagnostic("displayNode : Unknown tag for object: 0x%x", (Byte_t)tagOf(item));
     codeError_exit();
   }

   return (char *)getContent_BV(displaySB);
}


/*******************************************************************************
   Showing Hash Trees
*******************************************************************************/
static void initShowTree(StringBuf_t *sbuf);
static void showTree(MTree_t *mTree);
static void resetShowTree();

static void setCurIndent(int indentLevel);
static void showTreeNode(MTreeNode_t *node, int indentLevel);
static void showNode(MNode_t *node, int indentLevel);
static void showLeaf(MLeaf_t *node, int indentLevel);

static StringBuf_t *curSBuf = NULL;
static int maxLevel = 0;
static char *curIndent = NULL;
static int totalIndentLength = 0;
static int curIndentLevel = 0;

static int indentLen     = 0;
static int incrIndentLen = 0;

static void setCurIndent(int indentLevel) {
   // ensure initialisation
   if (curIndent == NULL) {
      totalIndentLength = LINE_BUFSIZE+1;
      curIndent = ALLOC_ARR(totalIndentLength, char);

      // initialising curIndent etc. ...
      indentLen  = strlen(show_indent);
      incrIndentLen = strlen(show_incrIndent);

      memcpy(curIndent, show_indent, indentLen);
   }

   int curLength = strlen(curIndent);
   int diffIndent = indentLevel - curIndentLevel;

   // set the current indent level
   curIndentLevel = indentLevel;

   // check if there is a difference in indent ...
   if (diffIndent == 0) {
      return;
   }
   else if (diffIndent < 0) {
      int offset = diffIndent * incrIndentLen;
      curLength +=  offset;

      if (curLength < indentLen) {
         diagnostic("merkleTree.setCurIndent: Bad indent level: %i", indentLevel);
         codeError_exit()
      }

      // update curIndent
      curIndent[curLength] = 0;

      return;
   }
   else {
      int posn = curLength;

      for (int i = 0; i < diffIndent; i++) {
         memcpy(curIndent + posn, show_incrIndent, incrIndentLen);
         posn += incrIndentLen;
      }
   }
}


static void showTreeNode(MTreeNode_t *node, int indentLevel) {
   if (node == NULL) {
      setCurIndent(curIndentLevel);
      addItems_SB(curSBuf, "%s<NULL TREE NODE>\n", curIndent);
   }

   switch (tagOf(node)) {
      case TAG_MLeaf_t: showLeaf((MLeaf_t *)node, indentLevel);
      case TAG_MNode_t: showNode((MNode_t *)node, indentLevel);
      default:
         diagnostic("merkleTree.showTreeNode: Bad tag value: %i\n", tagOf(node));
         codeError_exit();
   }
}

static void showNode(MNode_t *node, int indentLevel) {
   setCurIndent(indentLevel);

   // check if indentLevel exceed maxLevel
   if (indentLevel > maxLevel) {
      addItems_SB(curSBuf, "%s...\n", curIndent);
   }

   addItems_SB(curSBuf, "%sHeight:   %i\n", curIndent, node->height);
   addItems_SB(curSBuf, "%sPivot:    %i\n", curIndent, node->pivot);
   addItems_SB(curSBuf, "%sBase:     %i\n", curIndent, node->base);
   addItems_SB(curSBuf, "%sDigest: 0x%s\n", curIndent, showFingerprint_DG(node->digest, fpLength));

   showTreeNode(node->left, indentLevel+1);

   showTreeNode(node->right, indentLevel+1);
}

static void showLeaf(MLeaf_t *leaf, int indentLevel) {
   setCurIndent(indentLevel);

   // check if indentLevel exceed maxLevel
   if (indentLevel > maxLevel) {
      addItems_SB(curSBuf, "%s...\n", curIndent);
   }

   addItems_SB(curSBuf, "%sHeight:   0\n", curIndent);
   addItems_SB(curSBuf, "%sDigest: 0x%s\n", curIndent, showFingerprint_DG(leaf->digest, fpLength));
}

static void initShowTree(StringBuf_t *sbuf) {
   resetShowTree();

   curSBuf = sbuf;
}

static void showTree(MTree_t *mTree) {
   req_NonNull(mTree);

   // recompute maxLevel
   maxLevel = show_max_depth;
   if (maxLevel <= 0) {
      maxLevel = min(mTree->height + 1, MAX_TREE_HEIGHT);
   }

   setCurIndent(0);
   addItems_SB(curSBuf, "%sMTree <state:%s, height:%i, blockCount:%i, maxPosition:%i, digest:0x%s>\n"
                      , curIndent
                      , showState_MT(mTree)
                      , mTree->height
                      , mTree->blockCount
                      , mTree->maxPosition
                      , showFingerprint_DG(mTree->topHash, fpLength)
                      );

   // show the full tree if not compact ...
   if (!show_compact_display) {
      showTreeNode(mTree->treeRoot, 0);
   }
}

static void resetShowTree() {
   // deallocate curIndent
   free(curIndent);

   // set the curIndent to NULL to avoid double freeing ...
   curIndent = NULL;
}


/*******************************************************************************


// local debugging function ...
// - allows local tests to be exported to a wider context
void localTest();

////////////////////////////////////////////////////////////////////////////////
// Test 2
void localTest () {
   debugOn = FALSE;

   HashSpec_t hSpec = HSP_SHA256;

   Digest_t *digest0 = new_DG(hSpec);
   Digest_t *digest1 = new_DG(hSpec);

   MTree_t *mTree = new_MT(hSpec);

   MNode_t *node = allocate_Node(mTree, 1, 0, NULL, NULL);

   MLeaf_t *leaf0 = allocate_Leaf(mTree, 0, digest0);
   MLeaf_t *leaf1 = allocate_Leaf(mTree, 1, digest1);

   printf("Node = %s\n",  displayNode(node));
   printf("Leaf0 = %s\n", displayNode(leaf0));
   printf("Leaf1 = %s\n", displayNode(leaf1));

   printf("\n\nSetting right ...\n");
   setRight(node, leaf1);

   printf("\n\nSetting left ...\n");
   setLeft(node, leaf0);

   printf("\n\nReprinting ...\n");
   printf("Node = %s\n",  displayNode(node));
   printf("Leaf0 = %s\n", displayNode(leaf0));
   printf("Leaf1 = %s\n", displayNode(leaf1));

}


////////////////////////////////////////////////////////////////////////////////
// Test1
void localTest () {
   HashSpec_t hSpec = HSP_SHA256;

   MTree_t *mTree = new_MT(hSpec);

   MNode_t *node = allocate_Node(mTree, 1, 0, NULL, NULL);

   printf("tag of node = %c isNode = %s\n", tagOf(node), showBoolean(isNode(node)));

   printf("Node = %s\n", displayNode(node));
}

*/
