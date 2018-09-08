#ifndef __MATRIX_H__
#define __MATRIX_H__

/*
   matrix.h

   This library defines some basic matrix operations over square integer
   matrices, where the entries of these matrices are all Byte_t entries.

   In particular his package provides special code for processing upper triangular matrices
   (with unit diagonal).

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

#include "utils.h"
#include "bytevector.h"
#include "stringbuffer.h"

typedef struct matrix Matrix_t;

//const int sizeof_MATRIX;

// Allocates matrix of given dimension and triangularity
// - can specify dimension of matrix (if 0 then uses currentDim).
// - can specify triangular.
// - if triangular, sets matrix as identity
// - otherwise, zeroes the matrix
Matrix_t *allocateMatrix(int dim, Boolean_t isTriangular);
Matrix_t *allocateTriMatrix(int dim);

// resets the given matrix appropriately
// - can specify dimension of matrix.
// - can specify triangular.
// - if triangular, sets matrix as identity
// - otherwise, zeroes the matrix
void resetMatrix(Matrix_t *ma, int dim, Boolean_t isTriangular);

// deallocates given matrix by recycling ...
void deallocateMatrix(void *obj);

// get/set current dimension
int getCurrentDim();
void setCurrentDim(int dim);

// Resets a given matrix as an zero matrix
// - unsets the triangular property
void setZeroMatrix(Matrix_t *ma);

// Resets a given matrix as an identity matrix
// - sets triangular property
void setIdentityMatrix(Matrix_t *ma);

// Get value ...
// - checks array bounds
Byte_t getValue(Matrix_t *ma, int col, int row);

// Set value
// - checks array bounds
void setValue(Matrix_t *ma, int col, int row, Byte_t newVal);

// gets the dimension of the given matrix ...
int getDimension(Matrix_t *a);

// returns if matrix is triangular
Boolean_t isTriangular(Matrix_t *a);

// independent check that matrix is triangular
Boolean_t checkTriangular(Matrix_t *a);

// Returns the max number of elements available in matrix
// - For upper triangular, this does not include the diagonal or the lower
//   triangular elements.
int maxElemsMatrix(Matrix_t *mat);

// triangular number i.e. number of elems above leading diagonal of matrix of size dim.
int triNumber(int dim);

// Calculates the dimension of the smallest upper triangular matrix to contain content
// of given length.
int calcDimension(int length);

// Calculates the size of the zero padding for a vector of given length.
int calcPadding(int length);

// Extracts content from given matrix and copies it into the given bytevector.
// - if the bytevector's data vector is NULL, then fresh memory is allocated to fit.
// - if the matrix is triangular, the upper triangular portion of the matrix is captured.
void extractContent(ByteVec_t *dest, Matrix_t *source);

// Copies the bytevector content into given matrix ...
// - mapping takes into account if matrix is triangular
void insertContent(Matrix_t *dest, ByteVec_t *content);

// Swops two matrices pointed at by ma and mb
// - both ma and mb must have the same triangular property ...
void swopMatrices(Matrix_t *ma, Matrix_t *mb);

// Copies the content of the given matrix into the dest matrix.
// - Clobbers the content of the destination matrix ...
// - The destination matrix resets transpose status.
void cloneMatrix(Matrix_t *dest, Matrix_t *source);


// Test equality of matrices
Boolean_t equalMatrix(Matrix_t *ma, Matrix_t *mb);


// Test if matrix is the identity
Boolean_t isIdentityMatrix(Matrix_t *ma);


// Test if matrix is zero
Boolean_t isZeroMatrix(Matrix_t *ma);


// Randomised matrix in given matrix
void randomMatrix(Matrix_t *dest);


// Calculate the matrix made by raising matrix ma to the specified power
// - recursive mechanism - needs temporary matrices ...
void powerOfMatrix(Matrix_t *result, Matrix_t *ma, int power);


// Standard matrix multiplication where: result = ma * mb
// - Result is an existing matrix and assumed to be distinct from ma or mb.
// - internally optimises for triangular matrices
void multiply(Matrix_t *result, Matrix_t *ma, Matrix_t *mb);    // has special case for triangular
void stdMultiply(Matrix_t *result, Matrix_t *ma, Matrix_t *mb); // no  special case for triangular

/*
// Code to find fast triangular multiply
void triMultiplyFAST(Matrix_t *result, Matrix_t *ma, Matrix_t *mb);
void triMultiplyFAST2(Matrix_t *result, Matrix_t *ma, Matrix_t *mb);
void triMultiplyFASTER(Matrix_t *result, Matrix_t *ma, Matrix_t *mb);
void triMultiplyFASTER2(Matrix_t *result, Matrix_t *ma, Matrix_t *mb);  // fastest for clang
void triMultiplyFASTER3(Matrix_t *result, Matrix_t *ma, Matrix_t *mb);
void triMultiplyFASTER4(Matrix_t *result, Matrix_t *ma, Matrix_t *mb);
void triMultiplyFASTER5(Matrix_t *result, Matrix_t *ma, Matrix_t *mb);
*/

// Calculates period of matrix
// - if triangular, period is non-zero and always a power of two
int periodOfMatrix(Matrix_t *ma);


// Calculates inverse (by using the period, if it exists).
void inverseOfMatrix(Matrix_t *result, Matrix_t *source);


// Show matrix fingerprint ...
char *showMatrixFingerprint(Matrix_t *matrix, int fpLength);


// Extracts matrix entries to string ...
// - places string into given pre-allocated output string.
// - entries are given as decimal byte values (i.e. unsigned)
void showMatrix(Matrix_t *ma, StringBuf_t *sBuf, char *offset);


// Print matrix to string (in Hex)...
// - places string into given pre-allocated string.
// - entries are given as decimal byte values (i.e. unsigned)
void showMatrixHex(Matrix_t *ma, StringBuf_t *sBuf, char *offset);

// Useful debugging aid for displaying matrices
char *debugMatrix(Matrix_t *ma);
char *xdebugMatrix(Matrix_t *ma);

#endif
