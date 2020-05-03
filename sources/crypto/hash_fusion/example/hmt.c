/* hmt.c

   Hash Fusion/Merkle Tree testing application

   Application for examining/comparing the effect of different configurations and settings.

   The basic experiment consists of:
       1) Generating a sequence of data blocks
       2) Calculating a hash of the given blocks (computed in sequence).
          (a) This could use accumulation structure to build hash (albeit trivial).
          (b) No accumulation - simply directly add to end.
       3) Randomising the blocks.
       4) Rehashing the sequence of blocks, using a given accumulation structure
          to build the hash.
       5) Compare blocks ... (should be identical)

   The properties that can be varied include
   - The kind of accumulation structure used.
   - The first hash could be accumulated sequentially without using accumulation sequence.
   - Number of repetitions to obtain an time average (+ indication of variance.)
   - blocksize used
   - Number of blocks + range of number of blocks
   - Output format:  console output/CSV output /JSON output

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
#include <math.h>

#include "utils.h"
#include "alloc.h"
#include "random.h"
#include "testLib.h"
#include "stringbuffer.h"

////////////////////////////////////////////////////////////////////////////////
// Types and Structs
////////////////////////////////////////////////////////////////////////////////

typedef enum {
     HASHFUSION_ONLY_TESTMODE = 2000,  // HashFusion only
     MERKLETREE_ONLY_TESTMODE,         // Merkle Tree only
     DEFAULT_TESTMODE                  // Default only
   } TestMode_t;

typedef enum {
     CONSOLE_OUTPUT_MODE = 2010, // Console putput mode
     CSV_OUTPUT_MODE,            // CSV output mode
     JSON_OUTPUT_MODE            // JSON output mode
   } OutputMode_t;

typedef enum {
     HASHFUSION_METHOD,  // HashFusion method
     MERKLETREE_METHOD,  // Merkle Tree method
   } MethodType_t;

typedef struct reportObj Report_t;

struct reportObj {
   MethodType_t   method;
   int            seed;
   int            blocksize;
   int            numBlocks;
   int            dataSize;
   int            runs;
   HFuseAccum_t   accumType;
   double         initialTime;
   double         initialDataRate;
   double         destTime;
   double         destDataRate;
};

////////////////////////////////////////////////////////////////////////////////
// Control Properties
////////////////////////////////////////////////////////////////////////////////
static unsigned int  argSeed         = 27652761;
static int           argTotalBlocks  = 50;
static int           argBlockSize    = 1024;
static int           argRuns         = 1;

static TestMode_t argTestMode  =  DEFAULT_TESTMODE;  // Test mode
static Boolean_t  argSendOnly  =  FALSE;             // Send only?  Otherwise do both send/receive

static HFuseAccum_t argAccumKind = TREE_SET_ACCUM_HF; // LINEAR_LIST_ACCUM_HF; DIRECT_ACCUM_HF;

static OutputMode_t argOutputMode = CONSOLE_OUTPUT_MODE;

// Total data (in bytes)
static long totalData = 0;

// Digests (hash fusion)
static Digest_t *resultDigest_src_hf = NULL;
static Digest_t *resultDigest_dest_hf = NULL;

static double srcTimeInSecs_hf = 0.0;
static double destTimeInSecs_hf = 0.0;

// Merkle Tree info
static Digest_t *resultDigest_src_mt = NULL;
static Digest_t *resultDigest_dest_mt = NULL;

static double srcTimeInSecs_mt = 0.0;
static double destTimeInSecs_mt = 0.0;

// Report objects
#define UPDATE_REPORT(rep, fld, val)      { if ((rep) != NULL) {rep->fld = (val); }}

static Report_t *report_hf = NULL;
static Report_t *report_mt = NULL;

////////////////////////////////////////////////////////////////////////////////
// Display Enum types
////////////////////////////////////////////////////////////////////////////////
static char *show_TestMode(TestMode_t val) {
   switch (val) {
      case HASHFUSION_ONLY_TESTMODE: return "HASHFUSION_ONLY_TESTMODE";
      case MERKLETREE_ONLY_TESTMODE: return "MERKLETREE_ONLY_TESTMODE";
      case DEFAULT_TESTMODE:         return "DEFAULT_TESTMODE";

      default:
         diagnostic("show_TestMode: Expected a TestMode_t value - got instead: %i", val);
         error_exit();
   }
}


static char *show_OutputMode(OutputMode_t val) {
   switch (val) {
      case CONSOLE_OUTPUT_MODE: return "CONSOLE_OUTPUT_MODE";
      case CSV_OUTPUT_MODE:     return "CSV_OUTPUT_MODE";
      case JSON_OUTPUT_MODE:    return "JSON_OUTPUT_MODE";

      default:
         diagnostic("show_OutputMode: Expected a OutputMode_t value - got instead: %i", val);
         error_exit();
   }
}


static char *show_MethodType(MethodType_t val) {
   switch (val) {
      case HASHFUSION_METHOD: return "HASHFUSION_METHOD";
      case MERKLETREE_METHOD: return "MERKLETREE_METHOD";

      default:
         diagnostic("show_MethodType: Expected a MethodType_t value - got instead: %i", val);
         error_exit();
   }
}


////////////////////////////////////////////////////////////////////////////////
// Usage
////////////////////////////////////////////////////////////////////////////////
#undef NL
#undef SP

#define NL "\n"
#define SP "   "

static void usage() {
  char *usageString =
  "Usage: hmt <options>"   NL
  NL
  "  This app provides command-line performance tests of hash-fusion code" NL
  "  compared with using Merkle Trees."  NL
  NL
  "  The basic experiment consists of:"  NL
  "     1) Generating a sequence of randomised data blocks"  NL
  "     2) Calculating hash of the given block (computed in sequence)."  NL
  "     3) Randomise the order of the blocks so that they are presented in randomised sequence."  NL
  "     4) Rehash the out-of-order sequence of blocks by using a specified accumulation structure."  NL
  "        to build the required in-order hash."  NL
  "     5) Compare the two hashes ... (hashes should be identical)"  NL
  "     6) Report statistics (e.g. timing averages)"  NL
  NL
  "  The following options are supported:" NL
  NL
  "    -a <accum-type>   : Accumulation structure (either d: direct, l: linear, t: tree)" NL
  "                        (default: t)." NL
  NL
  "    -s <seed-value>   : Seed value for generating random data.  Setting this to" NL
  "                        zero provides a seed determined by date/time"  NL
  "                        (default: 27652761)." NL
  NL
  "    -h                : HashFusion only." NL
  NL
  "    -m                : Merkle Tree only." NL
  NL
  "    -r <runs>         : Number of runs (default: 1)." NL
  NL
  "    -n <blocks>       : Number of blocks. (default: 50)" NL
  NL
  "    -b <block-size>   : Size of each data block (default: 1024 bytes)." NL
  NL
  "    -csv              : CSV format report output -- reports stats using csv output format." NL
  "                        This format will output the column header line once." NL
  NL
  "    -json             : JSON format report output." NL
  NL
  "  The block-size and number of blocks options can use a multiplier code (k = 1024)." NL
  NL
  "  When using the 'direct' accumulation structure, it doesn't make sense to deal with out-of-order" NL
  "  data.  In this case, only the first two (and final) steps are performed." NL
  NL
  "  Examples:" NL
  "     hmt -s 236483624 -b 8k -n 22k -r 20" NL
  "     -- Use seed 236483624, blocksize = 8192, number of blocks = 22528, runs = 20" NL
  "        and default binary tree accumulation structure" NL
  NL
  "     hmt -s 4526263 -b 4k -n 2k -r 30 -a l" NL
  "     -- Use seed 4526263, blocksize = 4096, number of blocks = 2048, runs = 30" NL
  "        and use the linear list accumulation structure" NL
  NL
  "     hmt -b 6035 -h -n 16k -r 25" NL
  "     -- Use default seed, blocksize = 6035, perform HashFusion only, number " NL
  "        of blocks = 16384, and runs = 25" NL
  ;

  printf("%s", usageString);
  exit(0);
}


////////////////////////////////////////////////////////////////////////////////
// Process arguments
////////////////////////////////////////////////////////////////////////////////

// Argument codes
#define ARG_SEED         's'
#define ARG_BLOCK_SIZE   'b'
#define ARG_NUM_BLOCKS   '#'
#define ARG_RUNS         'r'
#define ARG_ACCUM_TYPE   'a'

static void processArgs(int argc, char *argv[]) {
   char *argStr = NULL;

   char code;

   char str[STD_BUFSIZE];
   int intVal;

   // This encodes if the current arg is expected to encode data ...
   Boolean_t isDataArg = FALSE;
   Byte_t dataArgCode  = 0;

   if (argc == 1) {
      usage();
   }

   for (int i=1; i < argc; i++) {
       argStr = argv[i];
       toLowerCase(argStr); // lower case the argument string ...

       //printf("%i. %s\n", i, argStr);

       if (dataArgCode != 0) {
          switch (dataArgCode) {
             case ARG_SEED:
                if (sscanf(argStr, "%i", &argSeed) == 1) {
                   if (argSeed < 0) argSeed = -argSeed;
                }
                else {
                   diagnostic("Expected an integer ... got instead: %s", argStr);
                   error_exit();
                }
                break;

             case ARG_BLOCK_SIZE:
                if (sscanf(argStr, "%i%c", &argBlockSize, &code) == 2) {
                   switch (code) {
                      case 'k':  argBlockSize *= 1024; break;
                      default:
				             diagnostic("Expected an integer followed by multiplier (k) ... got instead: %s", argStr);
				             error_exit();
                   }
                }
                else if (sscanf(argStr, "%i", &argBlockSize) > 0) {
                   // SKIP - NO CODE
                }
                else {
                   diagnostic("Expected an integer ... got instead: %s", argStr);
                   error_exit();
                }

                // Limit value of argBlockSize
                argBlockSize = minmax(1, argBlockSize, 128 * 1024);
                break;

             case ARG_NUM_BLOCKS:
                if (sscanf(argStr, "%i%c", &argTotalBlocks, &code) == 2) {
                   switch (code) {
                      case 'k':  argTotalBlocks *= 1024; break;
                      default:
				             diagnostic("Expected an integer followed by multiplier (k) ... got instead: %s", argStr);
				             error_exit();
                   }
                }
                else if (sscanf(argStr, "%i", &argTotalBlocks) > 0) {
                   // SKIP - NO CODE
                }
                else {
                   diagnostic("Expected an integer ... got instead: %s", argStr);
                   error_exit();
                }

                // Limit value of argTotalBlocks
                argTotalBlocks = minmax(1, argTotalBlocks, 32 * 1024);
                break;

              case ARG_RUNS:
                if (sscanf(argStr, "%i", &argRuns) == 1) {
                   argRuns = min(argRuns, 100);

                   if (argRuns < 1) {
		                diagnostic("Number of runs should be positive: %s", argStr);
		                error_exit();
                   }
                }
                else {
                   diagnostic("Expected an integer ... got instead: %s", argStr);
                   error_exit();
                }

                // Limit value of argRuns
                argRuns = minmax(1, argRuns, 256);
                break;

              case ARG_ACCUM_TYPE:
                if (sscanf(argStr, "%c", &code) == 1) {
                   argSendOnly = FALSE;
                   switch (code) {
                      case 'd':  argAccumKind = DIRECT_ACCUM_HF; argSendOnly = TRUE; break;
                      case 'l':  argAccumKind = LINEAR_LIST_ACCUM_HF; break;
                      case 't':  argAccumKind = TREE_SET_ACCUM_HF; break;
                      default:
				             diagnostic("Expected a code specifying accumulation structure (e.g. d, l or t) ... got instead: %s", argStr);
				             error_exit();
                   }
                }
                else {
                   diagnostic("Expected a character specifying accumulation structure (e.g. d, l or t) ... got instead: %s", argStr);
                   error_exit();
                }
                break;

             default:
                diagnostic("Unexpected data element: %s", argStr);
                error_exit();
          }

          dataArgCode = 0;
          continue;
       }

       dataArgCode = 0;

       // seed option
       if (strncmp("-s", argStr, 2) == 0) {
          dataArgCode = ARG_SEED;
          continue;
       }

       // block-size option
       if (strncmp("-b", argStr, 2) == 0) {
          dataArgCode = ARG_BLOCK_SIZE;
          continue;
       }

       // hash-fusion only option
       if (strncmp("-h", argStr, 2) == 0) {
          argTestMode = HASHFUSION_ONLY_TESTMODE;
          report_hf = ALLOC_OBJ(Report_t);

          continue;
       }

       // merkle tree only option
       if (strncmp("-m", argStr, 2) == 0) {
          argTestMode = MERKLETREE_ONLY_TESTMODE;
          report_mt = ALLOC_OBJ(Report_t);

          continue;
       }

       // number of blocks option
       if (strncmp("-n", argStr, 2) == 0 || strncmp("-#", argStr, 2) == 0) {
          dataArgCode = ARG_NUM_BLOCKS;
          continue;
       }

       if (strncmp("-r", argStr, 2) == 0) {
          dataArgCode = ARG_RUNS;
          continue;
       }

       // accumulation type option
       if (strncmp("-a", argStr, 2) == 0) {
          dataArgCode = ARG_ACCUM_TYPE;
          continue;
       }

       // csv format option
       if (strncmp("-c", argStr, 2) == 0) {
          argOutputMode = CSV_OUTPUT_MODE;
          continue;
       }

       // json format option
       if (strncmp("-j", argStr, 2) == 0) {
          argOutputMode = JSON_OUTPUT_MODE;
          continue;
       }

       // unrecognised option & help option
       if (strncmp("-", argStr, 1) == 0) {
          usage();
       }

       // Error - unexpected argument
       diagnostic("Unexpected argument: %s", argStr);
       error_exit();
   }

   // Ensure definition of reports in default testmode ...
   if (argTestMode == DEFAULT_TESTMODE) {
      report_hf = ALLOC_OBJ(Report_t);
      report_mt = ALLOC_OBJ(Report_t);
   }

   /*
   if (DONT) {
		printf("\nApplication state set to:\n");
		printf("  argSeed         =  %i\n", argSeed);
		printf("  argTotalBlocks  =  %i\n", argTotalBlocks);
		printf("  argBlockSize    =  %i\n", argBlockSize);
		printf("  argRuns         =  %i\n", argRuns);
		printf("  argAccumKind    =  %s\n", show_HFuseAccum(argAccumKind));
		printf("  argTestMode     =  %s\n", show_TestMode(argTestMode));
		printf("  argOutputMode   =  %s\n", show_OutputMode(argOutputMode));
		printf("  argSendOnly     =  %s\n", showBoolean(argSendOnly));
		printf("\n");

		//exit(0);
   }
   */

   //exit(0);
}

////////////////////////////////////////////////////////////////////////////////
// Output reporting
////////////////////////////////////////////////////////////////////////////////
static void consoleOut(const char *fmt, ...) {
   if (argOutputMode != CONSOLE_OUTPUT_MODE) return;
   va_list args;

   va_start(args, fmt);
   vfprintf(stdout, fmt, args);
   va_end(args);
}

static char statsReportBuf[MSG_BUFSIZE+1];

static Report_t *new_Report() {
   return ALLOC_OBJ(Report_t);
}

static char csvHeader[] = "Method, Seed, Blocksize, NumBlocks, Datasize, Runs, AccumType, "
                          "Initial Time, Initial Data Rate, Destination Time, Destination Data Rate\n";

static Boolean_t csvHeaderShown = FALSE;

static void csvOut(Report_t *rep) {
   if (rep == NULL) return;
   if (argOutputMode != CSV_OUTPUT_MODE) return;

   if (!csvHeaderShown) {
      printf("%s", csvHeader);
      csvHeaderShown = TRUE;
   }

   printf("\"%s\", ",  show_MethodType(rep->method));
   printf("%i, ",      rep->seed);
   printf("%i, ",      rep->blocksize);
   printf("%i, ",      rep->numBlocks);
   printf("%i, ",      rep->dataSize);
   printf("%i, ",      rep->runs);
   printf("\"%s\", ",  (rep->accumType == 0 ? "" : show_HFuseAccum(rep->accumType)));
   printf("%5f, ",     rep->initialTime);
   printf("%5f, ",     rep->initialDataRate);
   printf("%5f, ",     rep->destTime);
   printf("%5f\n",     rep->destDataRate);
}

static void jsonOut(Report_t *rep) {
   if (rep == NULL) return;
   if (argOutputMode != JSON_OUTPUT_MODE) return;

   printf("{method:\"%s\", ",        show_MethodType(rep->method));
   printf("seed:%i, ",               rep->seed);
   printf("blocksize:%i, ",          rep->blocksize);
   printf("numblocks:%i, ",          rep->numBlocks);
   printf("datasize:%i, ",           rep->dataSize);
   printf("runs:%i, ",               rep->runs);
   printf("accum-type:\"%s\", ",     (rep->accumType == 0 ? "" : show_HFuseAccum(rep->accumType)));
   printf("initial-time:%5f, ",      rep->initialTime);
   printf("initial-data-rate:%5f, ", rep->initialDataRate);
   printf("dest-time:%5f, ",         rep->destTime);
   printf("dest-data-rate:%5f}",     rep->destDataRate);
}


////////////////////////////////////////////////////////////////////////////////
// Methods
////////////////////////////////////////////////////////////////////////////////
void runSrc_FusionStruct() {

   // Compute digest value
   Digest_t *curDigest = calcDigest_FusionStruct(NULL);

   if (getHashState_DG(curDigest) != HST_FINAL) {
      diagnostic("runSrc_FusionStruct: digest was not finalised: digest state = %s", showHashState_DG(curDigest));
      error_exit();
   }

   if (resultDigest_src_hf == NULL) {
      // Transfer curDigest to resultDigest_src_hf
   	resultDigest_src_hf = curDigest;
   	curDigest = NULL;
   }
   else if (!isEqual_DG(resultDigest_src_hf, curDigest)) {
      StringBuf_t *sBuf = new_SB();

      addItems_SB(sBuf, "runSrc_FusionStruct: digests not equal:\n");
      addItems_SB(sBuf, "   resultDigest_src_hf digest  = 0x%s\n", showHexHashValue_DG(resultDigest_src_hf));
      addItems_SB(sBuf, "   current digest              = 0x%s", showHexHashValue_DG(curDigest));

      error_exit_SB(sBuf);
   }

   // Deallocate the current digest ...
   deallocate_DG(curDigest);
}

void runDest_FusionStruct() {

   // Compute digest value
   Digest_t *curDigest = calcDigest_FusionStruct(destBlocksPerm);

   if (getHashState_DG(curDigest) != HST_FINAL) {
      diagnostic("runDest_FusionStruct: digest was not finalised: digest state = %s", showHashState_DG(curDigest));
      error_exit();
   }

   if (resultDigest_dest_hf == NULL) {
      // Transfer curDigest to resultDigest_dest_hf
   	resultDigest_dest_hf = curDigest;
   	curDigest = NULL;
   }
   else if (!isEqual_DG(resultDigest_dest_hf, curDigest)) {
      StringBuf_t *sBuf = new_SB();

      addItems_SB(sBuf, "runDest_FusionStruct: digests not equal:\n");
      addItems_SB(sBuf, "   resultDigest_dest_hf digest  = 0x%s\n", showHexHashValue_DG(resultDigest_dest_hf));
      addItems_SB(sBuf, "   current digest               = 0x%s", showHexHashValue_DG(curDigest));

      error_exit_SB(sBuf);
   }

   // Deallocate the current digest ...
   deallocate_DG(curDigest);
}


static void runSrc_MerkleTree() {

   // Compute digest value
   Digest_t *curDigest = calcDigest_MerkleTree(NULL);

   if (getHashState_DG(curDigest) != HST_FINAL) {
      diagnostic("runSrc_MerkleTree: digest was not finalised: digest state = %s", showHashState_DG(curDigest));
      error_exit();
   }

   if (resultDigest_src_mt == NULL) {
      // Transfer curDigest to resultDigest_src_mt
   	resultDigest_src_mt = curDigest;
   	curDigest = NULL;
   }
   else if (!isEqual_DG(resultDigest_src_mt, curDigest)) {
      StringBuf_t *sBuf = new_SB();

      addItems_SB(sBuf, "runSrc_MerkleTree: digests not equal:\n");
      addItems_SB(sBuf, "   resultDigest_src_mt digest  = 0x%s\n", showHexHashValue_DG(resultDigest_src_mt));
      addItems_SB(sBuf, "   current digest              = 0x%s", showHexHashValue_DG(curDigest));

      error_exit_SB(sBuf);
   }

   // Deallocate the current digest ...
   deallocate_DG(curDigest);
}

void runDest_MerkleTree() {

   // Compute digest value
   Digest_t *curDigest = calcDigest_MerkleTree(destBlocksPerm);

   if (getHashState_DG(curDigest) != HST_FINAL) {
      diagnostic("runDest_FusionStruct: digest was not finalised: digest state = %s", showHashState_DG(curDigest));
      error_exit();
   }

   if (resultDigest_dest_mt == NULL) {
      // Transfer curDigest to resultDigest_dest_mt
   	resultDigest_dest_mt = curDigest;
   	curDigest = NULL;
   }
   else if (!isEqual_DG(resultDigest_dest_mt, curDigest)) {
      StringBuf_t *sBuf = new_SB();

      addItems_SB(sBuf, "runDest_MerkleTree: digests not equal:\n");
      addItems_SB(sBuf, "   resultDigest_dest_mt digest  = 0x%s\n", showHexHashValue_DG(resultDigest_dest_mt));
      addItems_SB(sBuf, "   current digest               = 0x%s", showHexHashValue_DG(curDigest));

      error_exit_SB(sBuf);
   }

   // Deallocate the current digest ...
   deallocate_DG(curDigest);
}

// This code ensures that various memory caches have been flushed/overwritten.
static unsigned int *memFlushBuf = NULL;
static void flushMemoryCaches() {
   int memSize = 5 * 1024 * 1024;

   memFlushBuf = ALLOC_ARR(memSize, unsigned int);

   // load the memory with random data
   for (int i = 0; i < memSize; i++) {
      memFlushBuf[i] = nextRandom();
   }

   // Do some meaningless computation that uses the memory ...
   unsigned int limit = pow2(17) + 5;
   unsigned int sum = 0;
   for (int i = memSize-1;  0 <= i; i--) {
      sum += memFlushBuf[i];
      if (sum >= limit) {
         sum = 0;
      }
   }

   free(memFlushBuf);

   memFlushBuf = NULL;
}

////////////////////////////////////////////////////////////////////////////////
// Run tests
////////////////////////////////////////////////////////////////////////////////

static void produceResults() {
   // Produce results ...
   if (argTestMode != MERKLETREE_ONLY_TESTMODE) {
      double srcDataRate_hf  = totalData/(1024 * 1024 * srcTimeInSecs_hf);

      consoleOut("\n\nHashFusion:\n");
		consoleOut("  Source build-time: %.5f secs (data rate: %.5f MB/sec)\n", srcTimeInSecs_hf, srcDataRate_hf);

		// update report
		UPDATE_REPORT(report_hf, initialDataRate, srcDataRate_hf);

		if (!argSendOnly) {
         double destDataRate_hf = totalData/(1024 * 1024 * destTimeInSecs_hf);

   		consoleOut("  Dest.  build-time: %.5f secs (data rate: %.5f MB/sec)\n", destTimeInSecs_hf, destDataRate_hf);

         // update report
         UPDATE_REPORT(report_hf, destDataRate, destDataRate_hf);
      }
	}

   if (argTestMode != HASHFUSION_ONLY_TESTMODE) {
      double srcDataRate_mt  = totalData/(1024 * 1024 * srcTimeInSecs_mt);

      consoleOut("\n\nMerkle hash tree:\n");
		consoleOut("  Source build-time: %.5f secs (data rate: %.5f MB/sec)\n", srcTimeInSecs_mt, srcDataRate_mt);

		// update report
		UPDATE_REPORT(report_mt, initialDataRate, srcDataRate_mt);

		if (!argSendOnly) {
      	double destDataRate_mt = totalData/(1024 * 1024 * destTimeInSecs_mt);

   		consoleOut("  Dest.  build-time: %.5f secs (data rate: %.5f MB/sec)\n", destTimeInSecs_mt, destDataRate_mt);

         // update report
         UPDATE_REPORT(report_mt, destDataRate, destDataRate_mt);

      }
   }

   // stats output
   csvOut(report_hf);
   csvOut(report_mt);

   jsonOut(report_hf);
   jsonOut(report_mt);
}

void runTest () {
   consoleOut("Hashfusion-Merkle tree Testing tool (HMT)\n");
   consoleOut("-- Testing pure data transfer with randomisation\n");

   //debugOn = FALSE;
   //checkAllocation_MM = FALSE;
   //checkDeallocation_MM = FALSE;

	setSeed(argSeed);
	consoleOut("-- Current seed value: %i\n", getSeed() );

	blockSize = argBlockSize;
	totalBlocks = argTotalBlocks;
   argRuns = max(1, argRuns);
   accumKind = argAccumKind;

   totalData = (long)(blockSize * totalBlocks);


   // Update report values
   //
   // MethodType_t   method;
   // int            seed;
   // int            blocksize;
   // int            numBlocks;
   // int            dataSize;
   // int            runs;
   // HFuseAccum_t   accumType;
   // double         initialTime;
   // double         initialDataRate;
   // double         destTime;
   // double         destDataRate;
   //
   UPDATE_REPORT(report_hf, method, HASHFUSION_METHOD);
   UPDATE_REPORT(report_mt, method, MERKLETREE_METHOD);

   UPDATE_REPORT(report_hf, seed, argSeed);
   UPDATE_REPORT(report_mt, seed, argSeed);

   UPDATE_REPORT(report_hf, blocksize, blockSize);
   UPDATE_REPORT(report_mt, blocksize, blockSize);

   UPDATE_REPORT(report_hf, numBlocks, totalBlocks);
   UPDATE_REPORT(report_mt, numBlocks, totalBlocks);

   UPDATE_REPORT(report_hf, dataSize, totalData);
   UPDATE_REPORT(report_mt, dataSize, totalData);

   UPDATE_REPORT(report_hf, runs, argRuns);
   UPDATE_REPORT(report_mt, runs, argRuns);

   UPDATE_REPORT(report_hf, accumType, accumKind);
   UPDATE_REPORT(report_mt, accumType, NULL_VAL);    // accumType not relevant to Merkle Tree

   // Output accumulation info
   switch (accumKind) {
      case DIRECT_ACCUM_HF:      consoleOut("-- Using Direct accumulation (%i).\n", accumKind); break;
      case LINEAR_LIST_ACCUM_HF: consoleOut("-- Using Linear list accumulation structure (%i).\n", accumKind); break;
      case TREE_SET_ACCUM_HF:    consoleOut("-- Using Red-Black tree set accumulation structure (%i).\n", accumKind); break;
      default:
         diagnostic("runTest: accumKind not set to good value: %i", accumKind);
         error_exit();
   }

   consoleOut("\nInitialising data blocks ...\n");
   consoleOut("  -- Block size: %i\n", blockSize);
   consoleOut("  -- Number of (randomised) data blocks: %i\n", totalBlocks);
   consoleOut("  -- Amount of data: %li bytes\n", totalData);

   initialiseTestData();
   populateBlocks();

   // Build the source hash structure
   consoleOut("\nBuilding source hash structures ... (Runs: %i)\n", argRuns);
   double totalSrcTimeInSecs_hf = 0;
   double totalSrcTimeInSecs_mt = 0;

   if (argTestMode != MERKLETREE_ONLY_TESTMODE) {
		consoleOut("  -- Using HashFusion ...\n");
		totalSrcTimeInSecs_hf = timeFunction2( argRuns, flushMemoryCaches, runSrc_FusionStruct );
   }

   if (argTestMode != HASHFUSION_ONLY_TESTMODE) {
		consoleOut("  -- Using MerkelTree ...\n");
		totalSrcTimeInSecs_mt = timeFunction2( argRuns, flushMemoryCaches, runSrc_MerkleTree );
   }

   // calc average
   srcTimeInSecs_hf = totalSrcTimeInSecs_hf/argRuns;
   srcTimeInSecs_mt = totalSrcTimeInSecs_mt/argRuns;

   // update reports for initialTime
   UPDATE_REPORT(report_hf, initialTime, srcTimeInSecs_hf);
   UPDATE_REPORT(report_mt, initialTime, srcTimeInSecs_mt);

   if (argSendOnly) {
      produceResults();
      return;
   }

   // Simulates the act of receiving the data in some order at the destination
   consoleOut("\nRandomise destination order ...\n");
   randomiseDestOrder();

   consoleOut("\nDestination Order of Data Blocks\n");
   int showBlocks = min(5, totalBlocks);

   for (int i = 0; i < showBlocks; i++) {
   	consoleOut("   destBlocksPerm[%i] = %i\n", i, destBlocksPerm[i]);
   }

   if (showBlocks != totalBlocks) {
      int i = totalBlocks-1;
      consoleOut("   ...\n");
      consoleOut("   destBlocksPerm[%i] = %i\n", i, destBlocksPerm[i]);
   }

   // Run the destination Hash Fusion structure
   consoleOut("\nBuilding the destination hash structure ... (Runs: %i)\n", argRuns);
   double totalDestTimeInSecs_hf = 0;
   double totalDestTimeInSecs_mt = 0;

	if (argTestMode != MERKLETREE_ONLY_TESTMODE) {
		consoleOut("  -- Using HashFusion ...\n");
		totalDestTimeInSecs_hf = timeFunction2( argRuns, flushMemoryCaches, runDest_FusionStruct );
	}

   if (argTestMode != HASHFUSION_ONLY_TESTMODE) {
		consoleOut("  -- Using MerkelTree ...\n");
		totalDestTimeInSecs_mt = timeFunction2( argRuns, flushMemoryCaches, runDest_MerkleTree );
   }

   // calc average
   destTimeInSecs_hf = totalDestTimeInSecs_hf/argRuns;
   destTimeInSecs_mt = totalDestTimeInSecs_mt/argRuns;

   // Update reports for destTime
   UPDATE_REPORT(report_hf, destTime, destTimeInSecs_hf);
   UPDATE_REPORT(report_mt, destTime, destTimeInSecs_mt);

   // Console Results
   if (argTestMode == DEFAULT_TESTMODE) {
      // Compare results
		consoleOut("\nComparing results ...\n");

		if (resultDigest_src_hf != NULL && resultDigest_dest_hf != NULL && isEqual_DG(resultDigest_src_hf, resultDigest_dest_hf)) {
		   consoleOut("\nSUCCESS! same hashes - using HashFusion:\n   0x%s\n", showHexHashValue_DG(resultDigest_src_hf));
		}
		else  {
		   consoleOut("\nFAILED! Different HashFusion hashes:\n");
		   consoleOut("   Source hash value       =  0x%s\n", showHexHashValue_DG(resultDigest_src_hf));
		   consoleOut("   Destination hash value  =  0x%s\n", showHexHashValue_DG(resultDigest_dest_hf));

		   exit(1);
		}

		if (resultDigest_src_mt != NULL && resultDigest_dest_mt != NULL && isEqual_DG(resultDigest_src_mt, resultDigest_dest_mt)) {
		   consoleOut("\nSUCCESS! same hashes - using Merkle hash tree:\n   0x%s\n", showHexHashValue_DG(resultDigest_src_mt));
		}
		else  {
		   consoleOut("\nFAILED! Different Merkle Tree hashes:\n");
		   consoleOut("   Source hash value       =  0x%s\n", showHexHashValue_DG(resultDigest_src_mt));
		   consoleOut("   Destination hash value  =  0x%s\n", showHexHashValue_DG(resultDigest_dest_mt));

		   exit(1);
		}
   }

   produceResults();
}


//void localTest();

int main(int argc, char *argv[]) {
   //localTest();
   processArgs(argc, argv);
   runTest();
}


/*******************************************************************************
// Deprecated/Test code



static void processArgs(int argc, char *argv[]) {
   char *argStr = NULL;
   char rest[10];
   int val;

   double dbl;

   char code[1];

   for (int i=1; i < argc; i++) {
       argStr = argv[i];
       consoleOut("%i. %s", i, argStr);

       // Use a character to get option char
//       if (sscanf(argStr, "-%c", code) > 0) {
//          switch (code[0]) {
//             case 'a': consoleOut("\tFOUND -f");  break;
//          }
//       }

       if (sscanf(argStr, "%i", &val) > 0) {
          consoleOut("\tINT VALUE: %i", val);
       }

       if (sscanf(argStr, "%lf", &dbl) > 0) {
          consoleOut("\tDOUBLE VALUE: %lf", dbl);
       }

       if (sscanf(argStr, "-%s", rest) > 0) {
          consoleOut("\tARG: %s", rest);
       }

       if (strncmp("-f", argStr, 2) == 0) {
          consoleOut("\tstrcmp matched -f");
       }

       consoleOut("\n");
   }
}





********************************************************************************/
