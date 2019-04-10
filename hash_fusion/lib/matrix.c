/* matrix.c

   Basic matrix operations ...

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

#include "utils.h"
#include "bytevector.h"
#include "stringbuffer.h"
#include "matrix.h"
#include "random.h"
#include "linearMap.h"
#include "alloc.h"

/*******************************************************************************
  Matrix structure

  - All matrices are stored square with integer entries (for simplicity of indexing).

  - Byte_t entries with arithmetic modulo 256.

  - Stored as a flat linear array in row major order (i.e. default for C/C++).

  - The size of the array is one more than the number of elements
    (i.e. compatibility with bytevectors).

  - Linear positions in matrix: [col, row] is: dim*row + col.
*******************************************************************************/

struct matrix {
   int        dimension;       // Dimension of (square) matrix
   int        base;            // Base of matrix operations
   int        capacity;        // Size of array (length of underlying array) =  dim^2 + 1
   Boolean_t  isTriangular;    // Indicates if matrix is upper triangular.
   Byte_t     *array;          // flat linear memory storage (of size: capacity).
};


// This sets the top limit for period finding ...
#define MAX_PERIOD_LIMIT 20000


/*******************************************************************************
  Static method prototypes
*******************************************************************************/
static void ensureMemMgmt();

static void calcOffsetArray(int dim);

static inline void fullMultiply(Matrix_t *result, Matrix_t *ma, Matrix_t *mb);

//static inline void auxTriMultiply_STANDARD(Matrix_t *result, Matrix_t *ma, Matrix_t *mb);
//static inline void auxTriMultiply_FAST(Matrix_t *result, Matrix_t *ma, Matrix_t *mb);
//static inline void auxTriMultiply_FAST2(Matrix_t *result, Matrix_t *ma, Matrix_t *mb);
//static inline void auxTriMultiply_FASTER(Matrix_t *result, Matrix_t *ma, Matrix_t *mb);
static inline void auxTriMultiply_FASTER2(Matrix_t *result, Matrix_t *ma, Matrix_t *mb);
//static inline void auxTriMultiply_FASTER3(Matrix_t *result, Matrix_t *ma, Matrix_t *mb);
//static inline void auxTriMultiply_FASTER4(Matrix_t *result, Matrix_t *ma, Matrix_t *mb);
//static inline void auxTriMultiply_FASTER5(Matrix_t *result, Matrix_t *ma, Matrix_t *mb);

static Byte_t dotProduct(Byte_t *aArray, Byte_t *bArray, int dim, int row, int col);
//static Byte_t dotProduct_Tri(Byte_t *aArray, Byte_t *bArray, int dim, int posn, int row, int col);
static Byte_t dotProduct_Tri2(Byte_t *aArray, Byte_t *bArray, int dim, int rowStart, int posn, int row, int col);
//static Byte_t dotProduct_Tri3(Byte_t *aArray, Byte_t *bArray, int dim, int rowStart, int posn, int row, int col);
//static Byte_t dotProduct_Tri4(Byte_t *aArray, Byte_t *bArray, int dim, int rowStart, int posn, int row, int col);
//static Byte_t dotProduct_Tri5(Byte_t *aArray, Byte_t *bArray, int dim, int rowStart, int posn, int row, int col);

static void initPowerOfMemoMap(Matrix_t *ma);
static void auxTriPowerOf(Matrix_t *result, Matrix_t *ma, int power);
static void auxPowerOf(Matrix_t *result, Matrix_t *ma, int power);
static void auxTriPowerOf(Matrix_t *result, Matrix_t *ma, int power);
static void auxPowerOf(Matrix_t *result, Matrix_t *ma, int power);

static int auxTriPeriodOfMatrix(Matrix_t *ma);
static int auxPeriodOfMatrix(Matrix_t *ma);
static void initInverseCalc(Matrix_t *ma);
static int auxTriPeriodOfMatrix(Matrix_t *ma);
static int auxPeriodOfMatrix(Matrix_t *ma);

static void disposeMatrix(void *obj);

static void auxStartOfRow(StringBuf_t *sBuf, int row, char *indent);
static void auxShowMatrix(const char *fmt, Matrix_t *ma, StringBuf_t *sBuf, char *indent);
static void auxShowMatrix(const char *fmt, Matrix_t *ma, StringBuf_t *sBuf, char *indent);
static void auxStartOfRow(StringBuf_t *sBuf, int row, char *indent);

char *debugMatrix(Matrix_t *ma);
char *xdebugMatrix(Matrix_t *ma);

char *dump_Matrix(Matrix_t *ma, char *offset);

static int currentDim = 0;

/*******************************************************************************
  Memory management
*******************************************************************************/
static MemMgr_t *matrix_MemMgr = NULL;

static void ensureMemMgmt() {
   if (matrix_MemMgr == NULL) {
      matrix_MemMgr = new_MM(sizeof(Matrix_t));
      setFinaliser_MM(matrix_MemMgr, disposeMatrix);

      // Setting up byte multiply table
      //setupByteMultiply();
   }
}


// Allocates matrix of given dimension and triangularity
// - can specify dimension of matrix.
// - can specify triangular.
// - if triangular, sets matrix as identity
// - otherwise, zeroes the matrix
Matrix_t *allocateMatrix(int dim, Boolean_t isTriangular) {
   if (dim == 0) {
      dim = currentDim;
   }

   req_Pos(dim);

   // update the current dimension
   currentDim = dim;

   ensureMemMgmt();

   Matrix_t *result = allocateObject_MM(matrix_MemMgr);

   resetMatrix(result, dim, isTriangular);

   return result;
}

Matrix_t *allocateTriMatrix(int dim) {
   return allocateMatrix(dim, TRUE);
}


// resets the given matrix appropriately
// - can specify dimension of matrix.
// - can specify triangular.
// - if triangular, sets matrix as identity
// - otherwise, zeroes the matrix
void resetMatrix(Matrix_t *ma, int dim, Boolean_t isTriangular) {
   req_NonNull(ma);
   req_Pos(dim);

	ensureMemMgmt();

   // sets triangular property
   ma->isTriangular = isTriangular;

   // new dimension  ... needs to change array allocation ...
   if (dim != ma->dimension) {

		// set dimension & capacity
		ma->dimension    = dim;
		ma->capacity     = (dim*dim)+1;

		// free any existing memory
		free(ma->array);

		// allocate fresh memory for the array
		ma->array = (Byte_t *)ALLOC_BLK(ma->capacity);
   }

   // initialise content
   if (ma->isTriangular) {
      setIdentityMatrix(ma);
   }
   else {
      setZeroMatrix(ma);
   }
}


// Releases given matrix and its memory
// - This explicitly does NOT release array storage ....
void deallocateMatrix(void *obj) {
   if (obj == NULL) return;

	ensureMemMgmt();

	Matrix_t *ma = (Matrix_t *)obj;

   deallocateObject_MM(matrix_MemMgr, sizeof(Matrix_t), ma);
}


// get/set current dimension
int getCurrentDim() {
   return currentDim;
}

void setCurrentDim(int dim) {
   currentDim = dim;
}


// Resets a given matrix as an zero matrix
// - unsets the triangular property
void setZeroMatrix(Matrix_t *ma) {
   req_NonNull(ma);

   //int dim = ma->dimension;
   int capacity = ma->capacity;
   Byte_t *array = ma->array;

   // unset triangular property
   ma->isTriangular = FALSE;

   // Zero the array
   NULLIFY(array, capacity);
}


// Resets a given matrix as an identity matrix
// - sets triangular property
void setIdentityMatrix(Matrix_t *ma) {
   req_NonNull(ma);

   int dim = ma->dimension;
   int capacity = ma->capacity;
   Byte_t *array = ma->array;

   // sets triangular property
   ma->isTriangular = TRUE;

   // first, zero the array
   NULLIFY(array, capacity);

   // Now set leading diagonal to one's.
   int posn = 0;
   for (int i = 0; i < dim; i++) {
      array[posn] = 1;
      posn += dim+1;
   }
}


/*******************************************************************************
  Getters and Setters
*******************************************************************************/

// Get value ... (column, row)
// - checks array bounds
Byte_t getValue(Matrix_t *ma, int col, int row) {
   int dim = ma->dimension;
   int capacity = ma->capacity;

   // calculate linear matrix position
   int posn = dim*row + col;

   if (0 <= posn && posn < capacity) {
      return ma->array[posn];
   }

   diagnostic("matrix.getValue: index out of range - col=%i, row=%i", col, row);
   codeError_exit();
}

// Set value ...
// - checks array bounds ..  (column, row)
void setValue(Matrix_t *ma, int col, int row, Byte_t newVal) {
   req_NonNull(ma);

   int dim = ma->dimension;
   int capacity = ma->capacity;

   // calculate linear matrix position
   int posn = dim*row + col;

   if (0 <= posn && posn < capacity) {
      ma->array[posn] = newVal;
      return;
   }

   diagnostic("matrix.setValue: index out of range - col=%i, row=%i", col, row);
   codeError_exit();
}

// Gets the dimension of the given matrix ...
int getDimension(Matrix_t *ma) {
   req_NonNull(ma);

   return ma->dimension;
}


// Returns if matrix is (upper) triangular
Boolean_t isTriangular(Matrix_t *ma) {
   req_NonNull(ma);

   return ma->isTriangular;
}

// Checks if matrix is (upper) triangular
// - updates the isTriangular flag and returns the status.
Boolean_t checkTriangular(Matrix_t *ma) {
   req_NonNull(ma);

   int dim = ma->dimension;  // dimension of matrix

   Byte_t *array = ma->array;  // the content array

   int rowStart = 0;    // row start in the array
   int posn     = 0;    // position in the array

   Byte_t curVal = 0;     // current value of element

   // Scans the matrix horizontally by column and then vertically by row
   for (int col = 0; col < dim; col++) {
      rowStart = (col == 0 ? 0 : rowStart + dim);  // Calculates position for start of the row.
      posn = rowStart + col;                       // Corresponds to the leading diagonal.

      for (int row = col; row < dim; row++) {
         curVal = array[posn];  // This extracts the current value at current position ...

         if (col < row && curVal != 0) {
            ma->isTriangular = FALSE;
            return FALSE;
         }
         else if (row == col && curVal != 1) {
            ma->isTriangular = FALSE;
            return FALSE;
         }

         posn += dim; // advances the position by one row in the same column ...
      }
   }

   ma->isTriangular = TRUE;
   return TRUE;
}


/*******************************************************************************
  Bytevector content extraction and copying ...
*******************************************************************************/
// Returns the max number of elements available in matrix
// - For upper triangular, this does not include the diagonal or the lower
//   triangular elements.
int maxElemsMatrix(Matrix_t *mat) {
   req_NonNull(mat);

   int dim  = mat->dimension;
   int size = mat->capacity;
   Boolean_t isTri = mat->isTriangular;

   return (isTri ? triNumber(dim) : size-1);
}

// triangular number i.e. number of elems above leading diagonal of matrix of size dim.
int triNumber(int dim) {
   req_LE(1, dim);

   return dim*(dim - 1)/2;
}


// Calculates the size of the smallest upper triangular matrix to contain content
// of given length.
int calcDimension(int length) {
   int dim = 2;
   int elems = triNumber(dim);

   while (elems < length) {
      dim += 1;
      elems = triNumber(dim);
   }

   return dim;
}

// Calculates the size of the zero padding for a vector of given length.
int calcPadding(int length) {
   int dim = calcDimension(length);
   return triNumber(dim) - length;
}

// Extracts content from given matrix and copies it into the given bytevector.
// - if the bytevector's data vector is NULL, then fresh memory is allocated to fit.
// - if the matrix is triangular, the upper triangular portion of the matrix is captured.
void extractContent(ByteVec_t *dest, Matrix_t *source) {
   req_NonNull(source);
   req_NonNull(dest);

   int dim  = source->dimension;
   Boolean_t isTri = source->isTriangular;

   int numEntries = maxElemsMatrix(source);

   // ensures byte vector has the capacity to contain content
   ensureCapacity_BV(dest, numEntries+1);

   Byte_t *array = source->array;

   int dataLen      = numEntries;
   Byte_t *dataVec  = getContent_BV(dest);

   if (isTri) {

      // Extract upper triangular elements ...
      int vecPosn = 0;  // data vector position
      int matPosn = 0;  // linear matrix position (col, row) is: (dim*row + col)

      // extract the upper triangular elements
      // - proceeds by reading each column vertically row-by-row
      for (int col = 0; col < dim; col++) {
         matPosn = col;
         for (int row = 0; row < col; row++) {
            if (vecPosn < dataLen) {
               dataVec[vecPosn] = array[matPosn];
            }

            vecPosn += 1;   // advances to the next element in the vector
            matPosn += dim; // advances position to next row in the column
         }
      }

   }
   else {
/*    // Extracts square array (i.e. row by row)
      int vecPosn = 0;  // data vector position
      int matPosn = 0;  // linear matrix position (col, row) is: (dim*row + col)

      // Proceeds by reading each row and then each column ...
      for (int row = 0; row < dim; row++) {
         for (int col = 0; col < dim; col++) {
            if (vecPosn < dataLen) {
               dataVec[vecPosn] = array[matPosn];
            }

            vecPosn += 1; // advances to the next element in the vector
            matPosn += 1; // advances position to next row in the column
         }
      }
*/
      memcpy(dataVec, array, dataLen);
   }

   // Ensure that the length of the data reflects the updates made.
   setLength_BV(dest, dataLen);
}


// Copies the bytevector content into given matrix
// - mapping takes into account if matrix is triangular
void insertContent(Matrix_t *dest, ByteVec_t *content) {
   req_NonNull(dest);
   req_NonNull(content);

   int dim         = dest->dimension;
   Boolean_t isTri = dest->isTriangular;
   Byte_t *array   = dest->array;

   int dataLen     = getLength_BV(content);
   Byte_t *dataVec   = getContent_BV(content);

   if (isTri) {
      // Fill upper triangular matrix ...

      int vecPosn = 0;  // data vector position
      int matPosn = 0;  // linear matrix position (col, row) is: (dim*row + col)

      // update the upper triangular elements, setting any remaining entries to zero.
      // - proceeds by filling each column (this is for column-based padding)
      for (int col = 0; col < dim; col++) {
         matPosn = col;
         for (int row = 0; row < col; row++) {
            array[matPosn] = (vecPosn < dataLen ? dataVec[vecPosn] : 0);

            vecPosn += 1;   // advances to the next element in the vector ...
            matPosn += dim; // advances position to next row in the column
         }
      }
   }
   else {
      // Fill square array (i.e. row by row)

      int vecPosn = 0;  // data vector position
      int matPosn = 0;  // linear matrix position (col, row) is: (dim*row + col)

      // update the upper triangular elements, setting any remaining entries to zero.
      // - proceeds by filling each row and then each column ...
      for (int row = 0; row < dim; row++) {
         for (int col = 0; col < dim; col++) {
            array[matPosn] = (vecPosn < dataLen ? dataVec[vecPosn] : 0);

            vecPosn += 1; // advances to the next element in the vector ...
            matPosn += 1; // advances position to next row in the column
         }
      }
   }
}

// Swops two matrices of same dimension pointed at by ma and mb
void swopMatrices(Matrix_t *ma, Matrix_t *mb) {
   req_NonNull(ma);
   req_NonNull(mb);

   if (ma == mb)
      return;  // Nothing to do

   if (ma->dimension != mb->dimension) {
      diagnostic("swopMatrices: argument matrices have different dimensions.");
      error_exit();
   }

   // Now swop content ....
   Matrix_t tempM = *ma;
   *ma = *mb;
   *mb = tempM;
}

// Copies the content of the source matrix into the destination matrix.
// - This destroys the content of the destination matrix ...
void cloneMatrix(Matrix_t *dest, Matrix_t *source) {
   req_NonNull(source);
   req_NonNull(dest);

   if (source->dimension != dest->dimension) {
      diagnostic("cloneMatrix: source and destination matrices have different dimensions.");
      error_exit();
   }

   // ensure the destination has same attributes
   dest->isTriangular = source->isTriangular;

   // directly copy the source data into the destination array
   memcpy(dest->array, source->array, source->capacity);
}


/*******************************************************************************
  Basic Predicates
*******************************************************************************/

// Checks equality of matrices
Boolean_t equalMatrix(Matrix_t *ma, Matrix_t *mb) {
   req_NonNull(ma);
   req_NonNull(mb);

   // check some basic attributes
   if (ma->dimension != mb->dimension)       return FALSE;
   if (ma->isTriangular != mb->isTriangular) return FALSE;

   // Standard case
   int dim = ma->dimension;
   Boolean_t isTri = ma->isTriangular;

   Byte_t *aArray = ma->array;
   Byte_t *bArray = mb->array;

   int posn = 0;

   if (isTri) {
      // Upper triangular matrices ...
      for (int col = 0; col < dim; col++) {
         posn = col;
         for (int row = 0; row < col; row++) {
            if (aArray[posn] != bArray[posn]) return FALSE;

            posn += dim;
         }
      }
   }
   else {
      // Square matrices ...
      for (int row = 0; row < dim; row++) {
         for (int col = 0; col < dim; col++) {
            if (aArray[posn] != bArray[posn]) return FALSE;

            posn += 1;
         }
      }
   }

   // Failed to find difference - therefore equality.
   return TRUE;
}


// Checks if matrix is the identity
Boolean_t isIdentityMatrix(Matrix_t *ma) {
   req_NonNull(ma);

   // Standard case
   int dim = ma->dimension;
   Boolean_t isTri = ma->isTriangular;

   Byte_t *aArray = ma->array;

   int posn = 0;

   if (isTri) {
      // Upper triangular matrices ...
      for (int col = 0; col < dim; col++) {
         posn = col;
         for (int row = 0; row < col; row++) {
            if (aArray[posn] != 0)
               return FALSE;

            posn += dim;
         }
      }
   }
   else {
      // Square matrices ...
      for (int row = 0; row < dim; row++) {
         for (int col = 0; col < dim; col++) {
            if (row == col && aArray[posn] != 1) {
               return FALSE;
            }
            else {
               if (aArray[posn] != 0)
                  return FALSE;
            }
            posn += 1;
         }
      }
   }

   // Failed to find difference - therefore equality.
   return TRUE;
}


// Checks if matrix is zero
Boolean_t isZeroMatrix(Matrix_t *ma) {
   req_NonNull(ma);

   // every upper triangular matrix is non-zero!
   if (ma->isTriangular) return FALSE;

   // Square matrices ...
   int size = ma->capacity;
   Byte_t *aArray = ma->array;

   for (int posn = 0; posn < size-1; posn++) {
       if (aArray[posn] != 0) return FALSE;
   }

   // Failed to find difference - therefore zero matrix.
   return TRUE;
}


/*******************************************************************************
  Randomised matrix
*******************************************************************************/
void randomMatrix(Matrix_t *dest) {
   req_NonNull(dest);

   int dim = dest->dimension;
   Byte_t *array = dest->array;

   if (dest->isTriangular) {
         // Fill upper triangular matrix ...

      int vecPosn = 0;  // data vector position
      int matPosn = 0;  // linear matrix position (col, row) is: (dim*row + col)

      // update the upper triangular elements, setting any remaining entries to zero.
      // - proceeds by filling each column (this is for column-based padding)
      for (int col = 0; col < dim; col++) {
         matPosn = col;
         for (int row = 0; row < col; row++) {
            array[matPosn] = nextRandom_BYTE();

            vecPosn += 1;   // advances to the next element in the vector ...
            matPosn += dim; // advances position to next row in the column
         }
      }

   }
   else {
      // Fill square array (i.e. row by row)

      int vecPosn = 0;  // data vector position
      int matPosn = 0;  // linear matrix position (col, row) is: (dim*row + col)

      // update the upper triangular elements, setting any remaining entries to zero.
      // - proceeds by filling each row and then each column ...
      for (int row = 0; row < dim; row++) {
         for (int col = 0; col < dim; col++) {
            array[matPosn] = nextRandom_BYTE();

            vecPosn += 1; // advances to the next element in the vector ...
            matPosn += 1; // advances position to next row in the column
         }
      }
   }
}


/*******************************************************************************
  Matrix Multiplication
  - uses currentDim
*******************************************************************************/
// This seems to win for clang
#define auxTriMultiply(a, b, c)  (auxTriMultiply_FASTER2((a), (b), (c)))

static int *offsetArray = NULL;
static void calcOffsetArray(int dim);

// Standard matrix multiplication where: result = ma * mb
// - The result is pre-allocated and distinct from ma or mb.
// - the actual multiplications are performed by auxExecMultiply
void multiply(Matrix_t *result, Matrix_t *ma, Matrix_t *mb) {
   req_NonNull(ma);
   req_NonNull(mb);
   req_NonNull(result);
   req_Distinct(ma, result);
   req_Distinct(mb, result);

   int aDim = ma->dimension;
   int bDim = mb->dimension;
   int dim = result->dimension;

   if (aDim != dim || bDim != dim) {
      diagnostic("multiply: Matrix arguments have different dimension");
      error_exit();
   }
   if (ma->isTriangular && mb->isTriangular) {
      auxTriMultiply(result, ma, mb);
      return;
   }

   fullMultiply(result, ma, mb);

}

void stdMultiply(Matrix_t *result, Matrix_t *ma, Matrix_t *mb) {
   req_NonNull(ma);
   req_NonNull(mb);
   req_NonNull(result);
   req_Distinct(ma, result);
   req_Distinct(mb, result);

   int aDim = ma->dimension;
   int bDim = mb->dimension;
   int dim = result->dimension;

   if (aDim != dim || bDim != dim) {
      diagnostic("stdMultiply: Matrix arguments have different dimension");
      error_exit();
   }

   fullMultiply(result, ma, mb);
}

/*
void inline triMultiplyStd(Matrix_t *result, Matrix_t *ma, Matrix_t *mb) {
   auxTriMultiply_STANDARD(result, ma, mb);
}

void inline triMultiplyFAST(Matrix_t *result, Matrix_t *ma, Matrix_t *mb) {
   auxTriMultiply_FAST(result, ma, mb);
}

void inline triMultiplyFAST2(Matrix_t *result, Matrix_t *ma, Matrix_t *mb) {
   auxTriMultiply_FAST2(result, ma, mb);
}

void inline triMultiplyFASTER(Matrix_t *result, Matrix_t *ma, Matrix_t *mb) {
   auxTriMultiply_FASTER(result, ma, mb);
}

void inline triMultiplyFASTER2(Matrix_t *result, Matrix_t *ma, Matrix_t *mb) {
   auxTriMultiply_FASTER2(result, ma, mb);
}

void inline triMultiplyFASTER3(Matrix_t *result, Matrix_t *ma, Matrix_t *mb) {
   auxTriMultiply_FASTER3(result, ma, mb);
}

void inline triMultiplyFASTER4(Matrix_t *result, Matrix_t *ma, Matrix_t *mb) {
   auxTriMultiply_FASTER4(result, ma, mb);
}

void inline triMultiplyFASTER5(Matrix_t *result, Matrix_t *ma, Matrix_t *mb) {
   auxTriMultiply_FASTER5(result, ma, mb);
}
*/

// Full Square matrix multiplication
static inline void fullMultiply(Matrix_t *result, Matrix_t *ma, Matrix_t *mb) {
   int dim = result->dimension;

   Byte_t *array = result->array;
   Byte_t *aArray = ma->array;
   Byte_t *bArray = mb->array;

   int posn = 0;
   for (int row = 0; row < dim; row++) {
      for (int col = 0; col < dim; col++) {
         array[posn] = dotProduct(aArray, bArray, dim, row, col);
         posn += 1;
      }
   }
}

/*
// Triangular matrix multiplication:
// - both arguments ma and mb are upper triangular
// - The result is pre-allocated and distinct from ma or mb.
static void auxTriMultiply_STANDARD(Matrix_t *result, Matrix_t *ma, Matrix_t *mb) {
   int dim = result->dimension;

   Byte_t *array = result->array;

   Byte_t *aArray = ma->array;
   Byte_t *bArray = mb->array;

   // Now traverse the array
   int posn = 0;
   for (int row = 0; row < dim; row++) {
      for (int col = 0; col < dim; col++) {

         // upper triangular matrix multiplication
         if (row > col) {
            // lower triangular elements are zero
            array[posn] = 0;
         }
         else if (row == col) {
            // leading diaagonal elements are one
            array[posn] = 1;
         }
         else {
            // upper triangular elements
            array[posn] = dotProduct(aArray, bArray, dim, row, col);
         }

         posn += 1;
      }
   }

   result-> isTriangular = TRUE;
}


// Triangular matrix multiplication:
// - both arguments ma and mb are upper triangular
// - exploits that lower half a triangular matrix is fixed ...
static void auxTriMultiply_FAST(Matrix_t *result, Matrix_t *ma, Matrix_t *mb) {
   int dim = result->dimension;

   if (!result->isTriangular) {
      setIdentityMatrix(result);
   }

   Byte_t *array  = result->array;

   Byte_t *aArray = ma->array;
   Byte_t *bArray = mb->array;

   // Iteration over the upper triangular part of the array ...
   // Calculates position ...
   int posn = 1;
   for (int col = 1; col < dim; col++) {
      posn = col;
      for (int row = 0; row < col; row++) {
         array[posn] = dotProduct(aArray, bArray, dim, row, col);
         posn += dim;
      }
   }
}


// Triangular matrix multiplication:
// - both arguments ma and mb are upper triangular
// - exploits that lower half a triangular matrix is fixed ...
static void auxTriMultiply_FAST2(Matrix_t *result, Matrix_t *ma, Matrix_t *mb) {
   int dim = result->dimension;

   if (!result->isTriangular) {
      setIdentityMatrix(result);
   }

   Byte_t *array  = result->array;

   Byte_t *aArray = ma->array;
   Byte_t *bArray = mb->array;

   // Iteration over the upper triangular part of the array ...
   // Proceeds linearly row-by-row and then col-by-col ...
   // - Corresponds to a linear scan
   int posn = 0;
   //int rowStart = 0;
   for (int row = 0; row < dim; row++) {
       posn += row+1;
   //    rowStart = posn;
       for (int col = row+1; col < dim; col++) {
         array[posn] = dotProduct(aArray, bArray, dim, row, col);
         posn += 1;
      }
   }
}

// Triangular matrix multiplication:
// - both arguments ma and mb are upper triangular
// - exploits the fact the half a triangular matrix is fixed ...
static void auxTriMultiply_FASTER(Matrix_t *result, Matrix_t *ma, Matrix_t *mb) {
   int dim = result->dimension;

   if (dim != currentDim || offsetArray == NULL) {
      calcOffsetArray(dim);
   }

   if (!result->isTriangular) {
      setIdentityMatrix(result);
   }

   Byte_t *array = result->array;
   Byte_t *aArray = ma->array;
   Byte_t *bArray = mb->array;

   // Iteration over the upper triangular part of the array ...
   // Calculates position ...
   int posn = 1;
   for (int col = 1; col < dim; col++) {
      posn = col;
      for (int row = 0; row < col; row++) {
         array[posn] = dotProduct_Tri(aArray, bArray, dim, posn, row, col);
         posn += dim;
      }
   }
}
*/

// Triangular matrix multiplication:
// - both arguments ma and mb are upper triangular
// - exploits the fact the half a triangular matrix is fixed ...
static void auxTriMultiply_FASTER2(Matrix_t *result, Matrix_t *ma, Matrix_t *mb) {
   int dim = result->dimension;

   if (!result->isTriangular) {
      setIdentityMatrix(result);
   }

   Byte_t *array  = result->array;
   Byte_t *aArray = ma->array;
   Byte_t *bArray = mb->array;

   // Iteration over the upper triangular part of the array ...
   // Calculates position ...
   int posn = 0;
   int rowStart = 0;
   for (int row = 0; row < dim; row++) {
       posn += row+1;
       rowStart = posn;
       for (int col = row+1; col < dim; col++) {
          //array[posn] = dotProduct(aArray, bArray, dim, row, col);
          array[posn] = dotProduct_Tri2(aArray, bArray, dim, rowStart, posn, row, col);
          posn += 1;
       }
   }
}


/*
// Triangular matrix multiplication:
// - both arguments ma and mb are upper triangular
// - exploits the fact the half a triangular matrix is fixed ...
static void auxTriMultiply_FASTER3(Matrix_t *result, Matrix_t *ma, Matrix_t *mb) {
   int dim = result->dimension;

   if (!result->isTriangular) {
      setIdentityMatrix(result);
   }

   Byte_t *array  = result->array;
   Byte_t *aArray = ma->array;
   Byte_t *bArray = mb->array;

   // Iteration over the upper triangular part of the array ...
   // Calculates position ...
   int posn = 0;
   int rowStart = 0;
   for (int row = 0; row < dim; row++) {
       posn += row+1;
       rowStart = posn;
       for (int col = row+1; col < dim; col++) {
          //xdebug("auxTriMultiply_FASTER3(row=%i, col=%i, posn=%i, rowStart=%i\n", row, col, posn, rowStart);
          //array[posn] = dotProduct(aArray, bArray, dim, row, col);
          array[posn] = dotProduct_Tri3(aArray, bArray, dim, rowStart, posn, row, col);
          posn += 1;
       }
   }
}

// Triangular matrix multiplication:
// - both arguments ma and mb are upper triangular
// - exploits the fact the half a triangular matrix is fixed ...
static void auxTriMultiply_FASTER4(Matrix_t *result, Matrix_t *ma, Matrix_t *mb) {
   int dim = result->dimension;

   if (!result->isTriangular) {
      setIdentityMatrix(result);
   }

   Byte_t *array  = result->array;
   Byte_t *aArray = ma->array;
   Byte_t *bArray = mb->array;

   // Iteration over the upper triangular part of the array ...
   // Calculates position ...
   int posn = 0;
   int rowStart = 0;
   for (int row = 0; row < dim; row++) {
       posn += row+1;
       rowStart = posn;
       for (int col = row+1; col < dim; col++) {
          //xdebug("auxTriMultiply_FASTER4(row=%i, col=%i, posn=%i, rowStart=%i\n", row, col, posn, rowStart);
          //array[posn] = dotProduct(aArray, bArray, dim, row, col);
          array[posn] = dotProduct_Tri4(aArray, bArray, dim, rowStart, posn, row, col);
          posn += 1;
       }
   }
}


// Triangular matrix multiplication:
// - both arguments ma and mb are upper triangular
// - exploits the fact the half a triangular matrix is fixed ...
static void auxTriMultiply_FASTER5(Matrix_t *result, Matrix_t *ma, Matrix_t *mb) {
   int dim = result->dimension;

   if (!result->isTriangular) {
      setIdentityMatrix(result);
   }

   Byte_t *array  = result->array;
   Byte_t *aArray = ma->array;
   Byte_t *bArray = mb->array;

   // Iteration over the upper triangular part of the array ...
   // Calculates position ...
   int posn = 0;
   int rowStart = 0;
   for (int row = 0; row < dim; row++) {
       posn += row+1;
       rowStart = posn;
       for (int col = row+1; col < dim; col++) {
          //xdebug("auxTriMultiply_FASTER5(row=%i, col=%i, posn=%i, rowStart=%i\n", row, col, posn, rowStart);
          //array[posn] = dotProduct(aArray, bArray, dim, row, col);
          array[posn] = dotProduct_Tri5(aArray, bArray, dim, rowStart, posn, row, col);
          posn += 1;
       }
   }
}
*/

/*******************************************************************************
  Dot Products
  - as used in Matrix Multiplication
  - special cases for upper triangular matrices
*******************************************************************************/
// Standard dot product
static Byte_t dotProduct(Byte_t *aArray, Byte_t *bArray, int dim, int row, int col) {
   Byte_t result = 0;

   int aPosn = row*dim;  // starting position for row ...
   int bPosn = col;      // starting position for col ...

   int aVal, bVal;

   for (int k = 0; k < dim; k++) {
      // current values
      aVal = aArray[aPosn];
      bVal = bArray[bPosn];

      // update positions
      aPosn += 1;
      bPosn += dim;

      // update result ...
      if (aVal == 0 || bVal == 0) continue;

      if (aVal == 1) {
         result += bVal;
      }
      else if (bVal == 1) {
         result += aVal;
      }
//      else if (aVal != 0 && bVal != 0) {
      else {
         result += (Byte_t)(aVal * bVal);
      }
   }

   return (Byte_t)result;
}

/*
// "Triangular" form of dot product.
// - Assumes that the dot product is computed in the (strictly) upper triangular part of matrix
// - - the row start is precomputed in the given offset array
static Byte_t dotProduct_Tri(Byte_t *aArray, Byte_t *bArray, int dim, int posn, int row, int col) {
   Byte_t result = aArray[posn] + bArray[posn];

   int aPosn = offsetArray[row];
   //int aPosn = row*(dim + 1) + 1; // first off-diagonal element in current row
   int bPosn = posn+dim;          // first column eement beyond posn i.e. (row+1, col)

   //xdebug("  dotProduct LOOP START: aPosn = %i bPosn = %i", aPosn, bPosn);

   while (aPosn < posn) {
      result += (Byte_t)(aArray[aPosn] * bArray[bPosn]);

      //xdebug("");
      //xdebug("  dotProduct LOOP: k = %i", k);
      //xdebug("  dotProduct LOOP: a(%i, %i) aPosn = %i aVal = %i )", row, k, aPosn, aVal);
      //xdebug("  dotProduct LOOP: b(%i, %i) bPosn = %i bVal = %i", k, col, bPosn, bVal);

      aPosn += 1;
      bPosn += dim;

      //xdebug("  dotProduct LOOP: result (so far) = %i", (Byte_t)result);
   }

   //xdebug("");
   //xdebug("  dotProduct END: ma = %p  mb = %p  row = %i col = %i", (void *)ma, (void *)mb, row, col);
   //xdebug("  dotProduct END: result = %i", (Byte_t)result);

   return (Byte_t)result;
}

static void calcOffsetArray(int dim) {
   free(offsetArray);

   offsetArray = ALLOC_ARR(dim, int);

   for (int i = 0; i < dim; i++) {
      offsetArray[i] = i*(dim+1) + 1;
   }

   currentDim = dim;
}
*/

// "Triangular" form of dot product.
// - Assumes that the dot product is computed in the (strictly) upper triangular part of matrix
// -
static Byte_t dotProduct_Tri2(Byte_t *aArray, Byte_t *bArray, int dim, int rowStart, int posn, int row, int col) {
   Byte_t result = aArray[posn] + bArray[posn];

   int aPosn = rowStart;
   //int aPosn = row*(dim + 1) + 1; // first off-diagonal element in current row
   int bPosn = posn+dim;            // first column element beyond posn i.e. (row+1, col)


   while (aPosn < posn) {
      result += (Byte_t)(aArray[aPosn] * bArray[bPosn]);

      aPosn += 1;
      bPosn += dim;
   }

   return (Byte_t)result;
}

/*
// "Triangular" form of dot product.
// - Assumes that the dot product is computed in the (strictly) upper triangular part of matrix
// -
static Byte_t dotProduct_Tri3(Byte_t *aArray, Byte_t *bArray, int dim, int rowStart, int posn, int row, int col) {
   Byte_t result = aArray[posn] + bArray[posn];

   int aPosn = rowStart;
   //int aPosn = row*(dim + 1) + 1; // first off-diagonal element in current row
   int bPosn = posn+dim;            // first column element beyond posn i.e. (row+1, col)


   while (aPosn < posn) {
      result += byteMult(aArray[aPosn] , bArray[bPosn]);

      aPosn += 1;
      bPosn += dim;
   }

   return (Byte_t)result;
}


// "Triangular" form of dot product.
// - Assumes that the dot product is computed in the (strictly) upper triangular part of matrix
// -
static Byte_t dotProduct_Tri4(Byte_t *aArray, Byte_t *bArray, int dim, int rowStart, int posn, int row, int col) {
   Byte_t result = aArray[posn] + bArray[posn];

   int aPosn = rowStart;    // first off-diagonal element in current row
   int bPosn = posn+dim;    // first column element beyond posn i.e. (row+1, col)

   Byte_t *aP = (aArray + aPosn);
   Byte_t *bP = (bArray + bPosn);

   while (aPosn < posn) {
      result += (*aP * *bP);

      aP += 1;
      bP += dim;

      aPosn += 1;
   }

   return result;
}

// "Triangular" form of dot product.
// - Assumes that the dot product is computed in the (strictly) upper triangular part of matrix
// -
static Byte_t dotProduct_Tri5(Byte_t *aArray, Byte_t *bArray, int dim, int rowStart, int posn, int row, int col) {
   Byte_t result = aArray[posn] + bArray[posn];

   int aPosn = rowStart;    // first off-diagonal element in current row
   int bPosn = posn+dim;    // first column element beyond posn i.e. (row+1, col)

   Byte_t *aP = (aArray + aPosn);
   Byte_t *bP = (bArray + bPosn);

   while (aPosn < posn) {
      result += byteMult(*aP , *bP);

      aP += 1;
      bP += dim;

      aPosn += 1;
   }

   return result;
}
*/

/*******************************************************************************
  Power of matrix
*******************************************************************************/

static LinearMap_t* powerOfMemoMap = NULL;   // basic memoisation

static void initPowerOfMemoMap(Matrix_t *ma) {
   if (powerOfMemoMap == NULL) {
      powerOfMemoMap = new_LM(deallocateMatrix);
   }
   else {
      clear_LM(powerOfMemoMap);
   }
}

void powerOfMatrix(Matrix_t *result, Matrix_t *ma, int power) {
   req_NonNull(result);
   req_NonNull(ma);

   initPowerOfMemoMap(ma);

   if (ma->isTriangular) {
      auxTriPowerOf(result, ma, power);
   }
   else {
      auxPowerOf(result, ma, power);
   }
}


static void auxTriPowerOf(Matrix_t *result, Matrix_t *ma, int power) {
   int dim = ma->dimension;

   // check for trivial results
   if (power == 0) {
      setIdentityMatrix(result);
      return;
   }
   else if (power == 1) {
      // unit case
      cloneMatrix(result, ma);
      return;
   }

   // check memoMap for previous entry
   Matrix_t *memoMatrix = getEntry_LM(powerOfMemoMap, power);
   if (memoMatrix != NULL) {
      cloneMatrix(result, memoMatrix);
      return;
   }

   // calculate the result
   if (power % 2 == 0) {
     // even powers case
     int halfPower = power / 2;  // int division

     Matrix_t *tempMat = allocateTriMatrix(dim);
     auxTriPowerOf(tempMat, ma, halfPower);

     auxTriMultiply(result, tempMat, tempMat);

     deallocateMatrix(tempMat);
   }
   else {
     // odd powers case
     int halfPower = power / 2;  // int division

     Matrix_t *tempMat1 = allocateTriMatrix(dim);
     auxTriPowerOf(tempMat1, ma, halfPower);

     Matrix_t *tempMat2 = allocateTriMatrix(dim);
     auxTriMultiply(tempMat2, tempMat1, tempMat1);
     auxTriMultiply(result, ma, tempMat2);

     deallocateMatrix(tempMat1);
     deallocateMatrix(tempMat2);
   }

   // add the result into the memo map
   Matrix_t *cloneResult = allocateTriMatrix(dim);
   cloneMatrix(cloneResult, result);
   addEntry_LM(powerOfMemoMap, power, cloneResult);
}


static void auxPowerOf(Matrix_t *result, Matrix_t *ma, int power) {
   int dim = ma->dimension;

   if (power == 0) {
      setIdentityMatrix(result);
   }
   else if (power == 1) {
      // unit case
      cloneMatrix(result, ma);
   }

   // check memoMap for previous entry
   Matrix_t *memoMatrix = getEntry_LM(powerOfMemoMap, power);
   if (memoMatrix != NULL) {
      cloneMatrix(result, memoMatrix);
      return;
   }

   if (power % 2 == 0) {
      // even powers case
      int halfPower = power / 2;   // int division

      Matrix_t *tempMat = allocateMatrix(dim, FALSE);
      auxPowerOf(tempMat, ma, halfPower);

      fullMultiply(result, tempMat, tempMat);

      deallocateMatrix(tempMat);
   }
   else {
      // odd powers case
      int halfPower = power / 2;  // int division

      Matrix_t *tempMat1 = allocateMatrix(dim, FALSE);
      auxPowerOf(tempMat1, ma, halfPower);

      Matrix_t *tempMat2 = allocateMatrix(dim, FALSE);
      fullMultiply(tempMat2, tempMat1, tempMat1);
      fullMultiply(result, ma, tempMat2);

      deallocateMatrix(tempMat1);
      deallocateMatrix(tempMat2);
   }

   // add the result into the memo map
   Matrix_t *cloneResult = allocateMatrix(dim, FALSE);
   cloneMatrix(cloneResult, result);
   addEntry_LM(powerOfMemoMap, power, cloneResult);
}


/*******************************************************************************
  Calculate periods and inverses (when exists).
*******************************************************************************/

static Matrix_t *inverseMatrix = NULL;

static void initInverseCalc(Matrix_t *ma) {
   req_NonNull(ma);

   int dim = ma->dimension;

   deallocateMatrix(inverseMatrix);             // release current inverse matrix - allows for reset dimension
   inverseMatrix = allocateMatrix(dim, FALSE);  // initialises to zero matrix
}


// Calculates period of matrix
// - if ma is triangular, its period is always a power of two (i.e. divisor of size of group).
int periodOfMatrix(Matrix_t *ma) {
   req_NonNull(ma);

   // initialises inverse calculation
   initInverseCalc(ma);

   if (isIdentityMatrix(ma)) {
      cloneMatrix(inverseMatrix, ma);
      return 1;
   }

   // Matrix is non-trivial
   return ( ma->isTriangular
          ? auxTriPeriodOfMatrix(ma)
          : auxPeriodOfMatrix(ma)
          );
}

// Calculates inverse, by using the period, if it exists.
void inverseOfMatrix(Matrix_t *result, Matrix_t *source) {
   req_NonNull(source);
   req_NonNull(result);

   setZeroMatrix(result);

   int period = periodOfMatrix(source);

   if (period >= 1) {
      cloneMatrix(result, inverseMatrix);
   }
}


static int auxTriPeriodOfMatrix(Matrix_t *ma) {
   int dim = ma->dimension;
   int count = 1;
   int result = -1;

   // Exploits triangular property ...
   Matrix_t *prevProduct      = allocateTriMatrix(dim); // initialises to identity
   Matrix_t *curProduct       = allocateTriMatrix(dim); // initialises to identity

   Matrix_t *accumMatrix      = allocateTriMatrix(dim); // initialises to identity
   Matrix_t *prevAccumMatrix  = allocateTriMatrix(dim); // initialises to identity

   // sets curProduct to initial matrix
   cloneMatrix(curProduct, ma);

   while (TRUE)  {
      swopMatrices(curProduct, prevProduct);        // swops content
      swopMatrices(accumMatrix, prevAccumMatrix);   // swops content

      // repeated squaring
      count *= 2;
      auxTriMultiply(curProduct, prevProduct, prevProduct);

      // accumulate product: (2^p - 1) = 1 + 2^1 + 2^2 + ... + 2^(p-1)
      // - this calculates the inverse (at end of calc).
      auxTriMultiply(accumMatrix, prevAccumMatrix, curProduct);

      // test
      if (isIdentityMatrix(curProduct)) {
         cloneMatrix(inverseMatrix, accumMatrix);
         result = count;
         break;
      }
      else if (count >= MAX_PERIOD_LIMIT) {
         break;
      }
   }

   // release temp resources
   deallocateMatrix(prevProduct);
   deallocateMatrix(curProduct);

   deallocateMatrix(accumMatrix);
   deallocateMatrix(prevAccumMatrix);

   return result;
}


static int auxPeriodOfMatrix(Matrix_t *ma) {
   int dim = ma->dimension;
   int count = 1;
   int result = -1;

   Matrix_t *prevProduct = allocateMatrix(dim, FALSE);
   Matrix_t *curProduct  = allocateMatrix(dim, FALSE);

   cloneMatrix(curProduct, ma);

   while (TRUE) {
      // swop around matrices
      swopMatrices(curProduct, prevProduct);

      // iterate curProduct
      count += 1;
      fullMultiply(curProduct, prevProduct, ma);

      if (isIdentityMatrix(curProduct)) {
         // if curProduct is the identity
         // - then prevProduct is the inverse!!
         cloneMatrix(inverseMatrix, prevProduct);
         result = count;

      }
      else if (isZeroMatrix(curProduct)) {
      	break;
      }
      else if (count >= MAX_PERIOD_LIMIT) {
         break;
      }
   }

   // release temp resources
   deallocateMatrix(prevProduct);
   deallocateMatrix(curProduct);

   return result;
}


/*******************************************************************************
  Disposal of matrix
  - disposes of underlying matrix memory and the objects ...
*******************************************************************************/

static void disposeMatrix(void *obj) {
   req_NonNull(obj);

   Matrix_t *ma = (Matrix_t *)obj;

   // free the allocated array
   free(ma->array);
   ma->array = NULL;

   // Now free the Matrix_t element
   free(ma);
}


/*******************************************************************************
  Fingerprinting of matrix
*******************************************************************************/
char *showMatrixFingerprint(Matrix_t *matrix, int fpLength) {
   req_NonNull(matrix);

   ByteVec_t *tempBV = new_BV();
   extractContent(tempBV, matrix);

   // calc. fingerprint of tempBV (i.e. matrix content)
   char *result = showFingerprint_BV(tempBV, fpLength);
   deallocate_BV(tempBV);

   return result;
}


/*******************************************************************************
  Show/Display matrices
*******************************************************************************/

// Extracts matrix entries to stringbuffer ...
// - adds string repn. into given string buffer
// - entries are given as decimal byte values
void showMatrix(Matrix_t *ma, StringBuf_t *sBuf, char *indent) {
   auxShowMatrix("%-3u ", ma, sBuf, indent);
}


// Extracts matrix entries to stringbuffer ...
// - adds string repn. into given string buffer.
// - entries are given as hex byte values
void showMatrixHex(Matrix_t *ma, StringBuf_t *sBuf, char *indent) {
   auxShowMatrix("%02x ", ma, sBuf, indent);
}


static void auxShowMatrix(const char *fmt, Matrix_t *ma, StringBuf_t *sBuf, char *indent) {
   req_NonNull(ma);
   req_NonNull(sBuf);

   int dim = ma->dimension;
   int size = ma->capacity;
   ensureCapacity_SB(sBuf, 4*size);

   Byte_t *array = ma->array;

   indent = (isa_Null(indent) ?  "   " :  indent);
   int posn = 0;
   for (int row = 0; row < dim; row++) {
      auxStartOfRow(sBuf, row, indent);

      for (int col = 0; col < dim; col++) {
         addUIntF_SB(sBuf, fmt, array[posn]);
         posn += 1;
      }
   }

   addStringF_SB(sBuf, "\n%s]\n", indent);
}


static void auxStartOfRow(StringBuf_t *sBuf, int row, char *indent) {

   addString_SB(sBuf, "\n");
   addString_SB(sBuf, indent);
   if (row == 0) {
      addString_SB(sBuf, "[ ");
   }
   else {
      addString_SB(sBuf, "  ");
   }
}


// Useful debugging aid for displaying matrices
static StringBuf_t *debugSB = NULL;
char *debugMatrix(Matrix_t *ma) {
   if (! debugOn) return "";

   if (ma == NULL) {
      diagnostic("debugMatrix : Null matrix pointer ...");
      codeError_exit();
   }

   if (debugSB == NULL) {
      debugSB = allocate_SB(MSG_BUFSIZE+1);
   }
   else {
      reset_SB(debugSB);
   }

   showMatrixHex(ma, debugSB, ">>>>     ");

   return (char *)getContent_BV(debugSB);
}

char *xdebugMatrix(Matrix_t *ma) {
   return "";
}


/*******************************************************************************
  Dump matrix info ... (debugging aid ...)
*******************************************************************************/
static StringBuf_t *dumpSB = NULL;
char *dump_Matrix(Matrix_t *ma, char *offset) {
   if (ma == NULL) {
      diagnostic("dump_Matrix : Null matrix pointer ...");
      codeError_exit();
   }

   // ensure defined
   if (dumpSB == NULL) {
      dumpSB = allocate_SB(MSG_BUFSIZE+1);
   }
   else {
      reset_SB(dumpSB);
   }

   addItems_SB(dumpSB, "%sMatrix_t (0x%lu)\n",      offset, (Ptr_t)ma);
   addItems_SB(dumpSB, "%s  dimension:    %i\n",    offset, ma->dimension);
   addItems_SB(dumpSB, "%s  capacity:     %i\n",    offset, ma->capacity);
   addItems_SB(dumpSB, "%s  isTriangular: %s\n",    offset, showBoolean(ma->isTriangular));
   addItems_SB(dumpSB, "%s  array:        0x%lu\n", offset, (Ptr_t)ma->array);

   return (char *)getContent_BV(dumpSB);
}
