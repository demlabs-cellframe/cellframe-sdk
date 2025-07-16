/**
 * @file dap_chain_net_srv_auctions.h
 * @brief Auction service definitions and types for Cellframe node auctions system
 * @authors Cellframe Team
 * @date 2024
 * @copyright MIT License
 *
 * This file contains all the necessary definitions, types and function declarations 
 * for the Cellframe auction system, focusing on bid management and scoring.
 * 
 * Architecture Components:
 * - Bid Transaction Composer: Creates auction bid transactions
 * - Bid Transaction Manager: Manages bid transaction processing and validation
 * - Event System: Handles auction and bid events in ledger
 * - Scoring Engine: Calculates bid scores using range × bid_amount formula
 */

#pragma once

#include <stdint.h>
#include <pthread.h>
#include "dap_chain_common.h"
#include "dap_chain_datum.h"
#include "dap_chain_net.h"
#include "dap_chain_wallet.h"
#include "dap_chain_ledger.h"
#include "dap_hash.h"
#include "dap_list.h"
#include "dap_time.h"
#include "dap_chain_datum_tx_event.h"
#include "dap_chain_datum_tx_out_cond.h"
#include "dap_enc_key.h"

#ifdef __cplusplus
extern "C" {
#endif

// ===========================================
// AUCTION SERVICE CONSTANTS
// ===========================================

/** @brief Service ID for auction operations */
#define DAP_CHAIN_NET_SRV_AUCTIONS_ID           0x07

// Cellframe auction rules constants
/** @brief Minimum CELL tokens required for 3 months (31.250 CELL) */
#define DAP_CHAIN_AUCTION_MIN_CELL_3MONTHS      31250000000000000000ULL  // 31.250 * 10^18

/** @brief Maximum CELL tokens for 2 years (250.000 CELL) */
#define DAP_CHAIN_AUCTION_MAX_CELL_2YEARS       250000000000000000000000ULL  // 250.000 * 10^18

/** @brief Minimum CellSlot range value */
#define DAP_CHAIN_AUCTION_MIN_RANGE             1

/** @brief Maximum CellSlot range value */
#define DAP_CHAIN_AUCTION_MAX_RANGE             8

/** @brief Months per range unit (3 months) */
#define DAP_CHAIN_AUCTION_MONTHS_PER_RANGE      3

// ===========================================
// AUCTION EVENT CONSTANTS
// ===========================================

/** @brief Auction event group name for event storage */
#define DAP_CHAIN_AUCTION_EVENT_GROUP                   "auctions"

/** @brief Auction event types */
#define DAP_CHAIN_AUCTION_EVENT_TYPE_AUCTION_CREATED    0x0001
#define DAP_CHAIN_AUCTION_EVENT_TYPE_BID_PLACED         0x0002
#define DAP_CHAIN_AUCTION_EVENT_TYPE_AUCTION_ENDED      0x0003
#define DAP_CHAIN_AUCTION_EVENT_TYPE_WINNER_DETERMINED  0x0004
#define DAP_CHAIN_AUCTION_EVENT_TYPE_AUCTION_CANCELLED  0x0005

// ===========================================
// AUCTION BID TRANSACTION STRUCTURES
// ===========================================

/**
 * @brief Auction bid data structure for TSD section
 * 
 * This structure represents bid parameters stored in the TSD section
 * of a conditional transaction output (TX_ITEM_TYPE_OUT_COND with 
 * subtype DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_AUCTION_BID).
 */
typedef struct dap_chain_auction_bid_tsd {
    dap_hash_fast_t auction_hash;           ///< Hash of the auction this bid belongs to
    uint8_t range_end;                      ///< Ending range for CellSlot (1-8, range_start always = 1)
    dap_time_t lock_time;                   ///< Token lock time duration
    uint256_t bid_amount;                   ///< Amount of CELL tokens bid
    uint8_t padding[7];                     ///< Padding for alignment (increased by 1)
} DAP_ALIGN_PACKED dap_chain_auction_bid_tsd_t;

/**
 * @brief TSD types for auction bid metadata
 */
typedef enum dap_chain_auction_tsd_type {
    AUCTION_TSD_TYPE_BID_DATA = 0x01,       ///< Bid data (dap_chain_auction_bid_tsd_t)
    AUCTION_TSD_TYPE_PROJECT_INFO = 0x02,   ///< Project information
    AUCTION_TSD_TYPE_BIDDER_PUBKEY = 0x03,  ///< Bidder public key
    AUCTION_TSD_TYPE_SIGNATURE = 0x04       ///< Additional signature data
} dap_chain_auction_tsd_type_t;

// ===========================================
// AUCTION EVENT DATA STRUCTURES
// ===========================================

/**
 * @brief Auction created event data
 */
typedef struct dap_chain_auction_event_auction_created {
    dap_hash_fast_t auction_hash;           ///< Hash of the auction
    dap_hash_fast_t creator_hash;           ///< Hash of auction creator
    dap_time_t start_time;                  ///< Auction start time
    dap_time_t end_time;                    ///< Planned auction end time
    bool is_candle_auction;                 ///< True if candle auction
    char project_name[256];                 ///< Project name
    char project_description[512];          ///< Project description
    char project_website[256];              ///< Project website
    bool is_crowdloan;                      ///< True if crowdloan, false if private
} DAP_ALIGN_PACKED dap_chain_auction_event_auction_created_t;

/**
 * @brief Bid placed event data
 */
typedef struct dap_chain_auction_event_bid_placed {
    dap_hash_fast_t auction_hash;           ///< Hash of the auction
    dap_hash_fast_t bid_hash;               ///< Hash of the bid transaction
    dap_hash_fast_t bidder_hash;            ///< Hash of the bidder
    uint8_t range_start;                    ///< Starting range for CellSlot
    uint8_t range_end;                      ///< Ending range for CellSlot
    uint256_t bid_amount;                   ///< Amount of CELL tokens bid
    dap_time_t lock_time;                   ///< Token lock time
    uint64_t score;                         ///< Calculated bid score
    dap_time_t timestamp;                   ///< Bid placement timestamp
} DAP_ALIGN_PACKED dap_chain_auction_event_bid_placed_t;

/**
 * @brief Auction ended event data
 */
typedef struct dap_chain_auction_event_auction_ended {
    dap_hash_fast_t auction_hash;           ///< Hash of the auction
    dap_time_t end_time;                    ///< Actual end time
    dap_time_t planned_end_time;            ///< Originally planned end time
    bool ended_early;                       ///< True if ended early (candle auction)
    uint32_t total_bids;                    ///< Total number of bids received
} DAP_ALIGN_PACKED dap_chain_auction_event_auction_ended_t;

/**
 * @brief Winner determined event data  
 */
typedef struct dap_chain_auction_event_winner_determined {
    dap_hash_fast_t auction_hash;           ///< Hash of the auction
    dap_hash_fast_t winning_bid_hash;       ///< Hash of the winning bid
    dap_hash_fast_t winner_hash;            ///< Hash of the winner
    uint64_t winning_score;                 ///< Winning bid score
    uint256_t winning_amount;               ///< Winning bid amount
    uint8_t winning_range_start;            ///< Winner's range start
    uint8_t winning_range_end;              ///< Winner's range end
    uint32_t total_bids;                    ///< Total bids in auction
} DAP_ALIGN_PACKED dap_chain_auction_event_winner_determined_t;

/**
 * @brief Auction cancelled event data
 */
typedef struct dap_chain_auction_event_auction_cancelled {
    dap_hash_fast_t auction_hash;           ///< Hash of the auction
    dap_hash_fast_t canceller_hash;         ///< Hash of who cancelled
    dap_time_t cancellation_time;           ///< When auction was cancelled
    char reason[256];                       ///< Cancellation reason
    uint32_t refunded_bids;                 ///< Number of bids refunded
} DAP_ALIGN_PACKED dap_chain_auction_event_auction_cancelled_t;

// ===========================================
// BID DATA STRUCTURES
// ===========================================

/**
 * @brief Auction bid information structure
 * 
 * Contains processed bid information for internal use and scoring calculations.
 */
typedef struct dap_chain_auction_bid_info {
    dap_hash_fast_t bid_hash;               ///< Hash of the bid transaction
    dap_hash_fast_t auction_hash;           ///< Hash of the auction
    dap_hash_fast_t bidder_hash;            ///< Hash of the bidder's public key
    uint8_t range_start;                    ///< Starting range for CellSlot
    uint8_t range_end;                      ///< Ending range for CellSlot
    uint256_t bid_amount;                   ///< Amount of CELL tokens
    dap_time_t lock_time;                   ///< Token lock time
    uint64_t score;                         ///< Calculated bid score
    dap_time_t timestamp;                   ///< Bid creation timestamp
    bool is_valid;                          ///< Bid validation status
} dap_chain_auction_bid_info_t;

/**
 * @brief Auction information structure
 * 
 * Contains auction metadata and current state information.
 */
typedef struct dap_chain_auction_info {
    dap_hash_fast_t auction_hash;           ///< Auction identifier hash
    dap_chain_net_id_t net_id;              ///< Network ID
    dap_time_t start_time;                  ///< Auction start time
    dap_time_t end_time;                    ///< Auction planned end time
    dap_time_t actual_end_time;             ///< Actual end time (for candle auction)
    bool is_active;                         ///< Auction active status
    bool is_candle_auction;                 ///< Candle auction mechanism flag
    dap_list_t *bids;                       ///< List of dap_chain_auction_bid_info_t
    dap_chain_auction_bid_info_t *winning_bid; ///< Current winning bid
    pthread_rwlock_t lock;                  ///< Thread safety lock
} dap_chain_auction_info_t;

/**
 * @brief Global auction storage
 * 
 * Thread-safe storage for all auction data and bid management.
 */
typedef struct dap_chain_auction_storage {
    dap_chain_auction_info_t *auctions;     ///< Hash table of auctions (HASH_HANDLE)
    pthread_rwlock_t auctions_lock;         ///< Global auctions lock
    uint64_t total_auctions;                ///< Total number of auctions
    uint64_t active_auctions;               ///< Number of active auctions
} dap_chain_auction_storage_t;

// ===========================================
// ERROR CODES
// ===========================================

/**
 * @brief Auction bid validation error codes
 */
typedef enum dap_chain_auction_bid_error {
    DAP_CHAIN_AUCTION_BID_OK = 0,                       ///< Success
    DAP_CHAIN_AUCTION_BID_ERROR_INVALID_PARAMS = -1,    ///< Invalid parameters
    DAP_CHAIN_AUCTION_BID_ERROR_INSUFFICIENT_AMOUNT = -2, ///< Insufficient bid amount
    DAP_CHAIN_AUCTION_BID_ERROR_INVALID_RANGE = -3,      ///< Invalid CellSlot range
    DAP_CHAIN_AUCTION_BID_ERROR_LOCK_TIME_TOO_SHORT = -4, ///< Lock time too short
    DAP_CHAIN_AUCTION_BID_ERROR_LOCK_TIME_TOO_LONG = -5,  ///< Lock time too long
    DAP_CHAIN_AUCTION_BID_ERROR_AUCTION_NOT_FOUND = -6,   ///< Auction not found
    DAP_CHAIN_AUCTION_BID_ERROR_AUCTION_EXPIRED = -7,     ///< Auction has expired
    DAP_CHAIN_AUCTION_BID_ERROR_MEMORY_ALLOCATION = -8,   ///< Memory allocation failed
    DAP_CHAIN_AUCTION_BID_ERROR_INVALID_SIGNATURE = -9,   ///< Invalid signature
    DAP_CHAIN_AUCTION_BID_ERROR_DUPLICATE_BID = -10       ///< Duplicate bid from same bidder
} dap_chain_auction_bid_error_t;

// Auction bid error codes for validation
#define DAP_CHAIN_AUCTION_BID_ERROR_INVALID_RANGE       -1
#define DAP_CHAIN_AUCTION_BID_ERROR_AMOUNT_TOO_LOW       -2
#define DAP_CHAIN_AUCTION_BID_ERROR_AMOUNT_TOO_HIGH      -3
#define DAP_CHAIN_AUCTION_BID_ERROR_LOCK_TIME_TOO_SHORT  -4
#define DAP_CHAIN_AUCTION_BID_ERROR_LOCK_TIME_TOO_LONG   -5

// Auction bid verificator error codes (returned by verificator function)
#define DAP_CHAIN_AUCTION_BID_VERIFICATOR_INVALID_ARGS        -101
#define DAP_CHAIN_AUCTION_BID_VERIFICATOR_WRONG_SUBTYPE       -102
#define DAP_CHAIN_AUCTION_BID_VERIFICATOR_WRONG_SERVICE       -103
#define DAP_CHAIN_AUCTION_BID_VERIFICATOR_TSD_MISMATCH        -104
#define DAP_CHAIN_AUCTION_BID_VERIFICATOR_INVALID_PARAMS      -105
#define DAP_CHAIN_AUCTION_BID_VERIFICATOR_BLANK_AUCTION_HASH  -106
#define DAP_CHAIN_AUCTION_BID_VERIFICATOR_VALUE_MISMATCH      -107
#define DAP_CHAIN_AUCTION_BID_VERIFICATOR_WRONG_TOKEN         -108
#define DAP_CHAIN_AUCTION_BID_VERIFICATOR_NO_SIGNATURE        -109
#define DAP_CHAIN_AUCTION_BID_VERIFICATOR_INVALID_SIGNATURE   -110

// ===========================================
// VOTE TRANSACTION COMPOSER FUNCTIONS
// ===========================================

/**
 * @brief Create conditional output for auction bid
 * 
 * Creates a TX_ITEM_TYPE_OUT_COND with subtype DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_AUCTION_BID
 * for auction bid transactions.
 * 
 * @param a_auction_hash Hash of the auction to bid on
 * @param a_range_end Ending CellSlot range (1-8, range_start always = 1)
 * @param a_bid_amount Amount of CELL tokens to bid
 * @param a_lock_time Token lock time duration
 * @param a_bidder_pkey Public key of the bidder
 * @return dap_chain_tx_out_cond_t* Created conditional output or NULL on error
 */
dap_chain_tx_out_cond_t* dap_chain_auction_bid_cond_create(
    dap_hash_fast_t *a_auction_hash,
    uint8_t a_range_end,
    uint256_t a_bid_amount,
    dap_time_t a_lock_time,
    dap_pkey_t *a_bidder_pkey
);

/**
 * @brief Create complete auction bid transaction
 * 
 * Vote Transaction Composer function that creates a complete blockchain
 * transaction containing the auction bid and all necessary metadata.
 * 
 * @param a_auction_hash Hash of the auction to bid on
 * @param a_range_start Starting CellSlot range (1-8)
 * @param a_range_end Ending CellSlot range (1-8)
 * @param a_bid_amount Amount of CELL tokens to bid
 * @param a_lock_time Token lock time duration
 * @param a_fee Transaction fee
 * @param a_wallet Wallet for signing transaction
 * @param a_net Network to submit transaction to
 * @param a_hash_out_type Output hash format type
 * @param a_hash_output Output parameter for transaction hash
 * @return int Result code (DAP_CHAIN_AUCTION_BID_OK on success)
 */
int dap_chain_net_auction_bid_create(
    dap_hash_fast_t *a_auction_hash,
    uint8_t a_range_start,
    uint8_t a_range_end,
    uint256_t a_bid_amount,
    dap_time_t a_lock_time,
    uint256_t a_fee,
    dap_chain_wallet_t *a_wallet,
    dap_chain_net_t *a_net,
    const char *a_hash_out_type,
    char **a_hash_output
);

// ===========================================
// VOTE TRANSACTION MANAGER FUNCTIONS  
// ===========================================

/**
 * @brief Process and validate auction bid transaction
 * 
 * Vote Transaction Manager function that processes incoming bid transactions,
 * validates them according to Cellframe auction rules, and updates auction state.
 * 
 * @param a_ledger Ledger instance
 * @param a_tx_item_type Transaction item type
 * @param a_tx_in Input transaction
 * @param a_tx_hash Transaction hash
 * @param a_apply Whether to apply changes or just validate
 * @return int Validation result (DAP_LEDGER_CHECK_OK on success)
 */
int dap_chain_auction_bid_verificator(
    dap_ledger_t *a_ledger,
    dap_chain_tx_item_type_t a_tx_item_type,
    dap_chain_datum_tx_t *a_tx_in,
    dap_hash_fast_t *a_tx_hash,
    bool a_apply
);

/**
 * @brief Register auction bid verification callback
 * 
 * Vote Transaction Manager function that registers the bid verification
 * callback with the ledger system for automatic bid processing.
 * 
 * @return int Registration result (0 on success)
 */
int dap_chain_auction_bid_verificator_register(void);

/**
 * @brief Find auction by hash
 * 
 * Vote Transaction Manager function for retrieving auction information
 * from the global auction storage.
 * 
 * @param a_auction_hash Hash of the auction to find
 * @param a_net_id Network ID to search in
 * @return dap_chain_auction_info_t* Auction info or NULL if not found
 */
dap_chain_auction_info_t* dap_chain_auction_find_by_hash(
    dap_hash_fast_t *a_auction_hash,
    dap_chain_net_id_t a_net_id
);

/**
 * @brief Add bid to auction
 * 
 * Vote Transaction Manager function that adds a validated bid to an auction
 * and updates the auction state including winner determination.
 * 
 * @param a_auction Auction to add bid to
 * @param a_bid_info Bid information to add
 * @return int Result code (DAP_CHAIN_AUCTION_BID_OK on success)
 */
int dap_chain_auction_add_bid(
    dap_chain_auction_info_t *a_auction,
    dap_chain_auction_bid_info_t *a_bid_info
);

/**
 * @brief Determine auction winner
 * 
 * Vote Transaction Manager function that analyzes all bids in an auction
 * and determines the winner based on the Cellframe scoring system.
 * 
 * @param a_auction Auction to analyze
 * @return dap_chain_auction_bid_info_t* Winning bid or NULL if no valid bids
 */
dap_chain_auction_bid_info_t* dap_chain_auction_determine_winner(
    dap_chain_auction_info_t *a_auction
);

// ===========================================
// EXISTING SCORING FUNCTIONS (already implemented)
// ===========================================

/**
 * @brief Calculate bid score using Cellframe auction rules
 * 
 * Calculates the score for a bid using the formula: range_end * bid_amount = score
 * (range_start is always 1 for Cellframe auctions)
 * 
 * @param a_range_end Ending range for CellSlot (1-8, range_start always = 1)  
 * @param a_bid_amount Amount of CELL tokens bid
 * @return uint64_t Calculated score, or 0 on error
 */
uint64_t dap_chain_auction_bid_calculate_score(uint8_t a_range_end, uint256_t a_bid_amount);

/**
 * @brief Validate auction bid parameters according to Cellframe rules
 * 
 * @param a_range_start Starting range for CellSlot (1-8)
 * @param a_range_end Ending range for CellSlot (1-8)
 * @param a_bid_amount Amount of CELL tokens bid
 * @param a_lock_time Token lock time duration
 * @return dap_chain_auction_bid_error_t Validation result
 */
dap_chain_auction_bid_error_t dap_chain_auction_bid_validate_params(
    uint8_t a_range_start, 
    uint8_t a_range_end, 
    uint256_t a_bid_amount, 
    dap_time_t a_lock_time
);

// ===========================================
// STORAGE MANAGEMENT FUNCTIONS
// ===========================================

/**
 * @brief Initialize auction storage system
 * 
 * @return int Initialization result (0 on success)
 */
int dap_chain_auction_storage_init(void);

/**
 * @brief Cleanup auction storage system
 */
void dap_chain_auction_storage_deinit(void);

/**
 * @brief Get global auction storage instance
 * 
 * @return dap_chain_auction_storage_t* Global storage instance
 */
dap_chain_auction_storage_t* dap_chain_auction_storage_get(void);

// ===========================================
// AUCTION EVENT READING FUNCTIONS
// ===========================================

/**
 * @brief Read all auction events from ledger by group
 * 
 * Reads all events from the auction event group stored in the ledger.
 * Events include auction creation, bid placement, auction ending, etc.
 * 
 * @param a_net Network to read events from
 * @return dap_list_t* List of dap_chain_tx_event_t* or NULL on error
 */
dap_list_t* dap_chain_auction_events_read_all(dap_chain_net_t *a_net);

/**
 * @brief Read auction events for specific auction
 * 
 * Filters events to return only those related to a specific auction hash.
 * 
 * @param a_net Network to read events from
 * @param a_auction_hash Hash of specific auction to filter events for
 * @return dap_list_t* List of dap_chain_tx_event_t* or NULL on error
 */
dap_list_t* dap_chain_auction_events_read_by_auction(dap_chain_net_t *a_net, dap_hash_fast_t *a_auction_hash);

/**
 * @brief Read auction events by type
 * 
 * Filters events to return only those of a specific event type.
 * 
 * @param a_net Network to read events from
 * @param a_event_type Event type to filter for (DAP_CHAIN_AUCTION_EVENT_TYPE_*)
 * @return dap_list_t* List of dap_chain_tx_event_t* or NULL on error
 */
dap_list_t* dap_chain_auction_events_read_by_type(dap_chain_net_t *a_net, uint16_t a_event_type);

/**
 * @brief Find specific auction event by transaction hash
 * 
 * Looks up a specific auction event by its transaction hash.
 * 
 * @param a_net Network to search in
 * @param a_tx_hash Transaction hash of the event
 * @return dap_chain_tx_event_t* Event or NULL if not found
 */
dap_chain_tx_event_t* dap_chain_auction_event_find_by_hash(dap_chain_net_t *a_net, dap_hash_fast_t *a_tx_hash);

/**
 * @brief Create and add auction event to ledger
 * 
 * Creates a new auction event and adds it to the ledger for storage.
 * 
 * @param a_net Network to add event to
 * @param a_tx_hash Transaction hash associated with event
 * @param a_pkey_hash Public key hash of event creator
 * @param a_event_type Event type (DAP_CHAIN_AUCTION_EVENT_TYPE_*)
 * @param a_event_data Event-specific data structure
 * @param a_event_data_size Size of event data
 * @return int 0 on success, negative on error
 */
int dap_chain_auction_event_add(dap_chain_net_t *a_net, 
                                dap_hash_fast_t *a_tx_hash,
                                dap_hash_fast_t *a_pkey_hash,
                                uint16_t a_event_type,
                                void *a_event_data,
                                size_t a_event_data_size);

/**
 * @brief Load auction state from ledger events
 * 
 * Reconstructs auction state by processing all auction events from the ledger.
 * This function reads events and rebuilds auction and bid information.
 * 
 * @param a_net Network to load state from
 * @return int Number of auctions loaded, negative on error
 */
int dap_chain_auction_state_load_from_events(dap_chain_net_t *a_net);

/**
 * @brief Process auction event and update state
 * 
 * Processes a single auction event and updates internal auction state.
 * Used during state reconstruction from events.
 * 
 * @param a_event Event to process
 * @return int 0 on success, negative on error
 */
int dap_chain_auction_event_process(dap_chain_tx_event_t *a_event);

/**
 * @brief Get auction information from events
 * 
 * Reconstructs auction info by processing related events from the ledger.
 * 
 * @param a_net Network to search in
 * @param a_auction_hash Hash of auction to get info for
 * @return dap_chain_auction_info_t* Reconstructed auction info or NULL
 */
dap_chain_auction_info_t* dap_chain_auction_info_from_events(dap_chain_net_t *a_net, dap_hash_fast_t *a_auction_hash);

/**
 * @brief Clean up event data structures
 * 
 * Helper function to properly free event-related memory.
 * 
 * @param a_events List of events to free
 */
void dap_chain_auction_events_list_free(dap_list_t *a_events);

// ===========================================
// CLI HELPER FUNCTIONS
// ===========================================

/**
 * @brief Create auction bid transaction
 * 
 * @param a_net Network
 * @param a_auction_hash Auction hash
 * @param a_range_end Range end (1-8)
 * @param a_bid_amount Bid amount in CELL
 * @param a_lock_time Lock time in seconds
 * @param a_fee Transaction fee
 * @param a_wallet_name Wallet name
 * @return dap_chain_datum_tx_t* Created transaction or NULL on error
 */
dap_chain_datum_tx_t* dap_chain_auction_bid_transaction_create(dap_chain_net_t *a_net, 
                                                               const dap_hash_fast_t *a_auction_hash,
                                                               uint8_t a_range_end,
                                                               uint256_t a_bid_amount,
                                                               dap_time_t a_lock_time,
                                                               uint256_t a_fee,
                                                               const char *a_wallet_name);

/**
 * @brief Convert auction status to string
 * 
 * @param a_status Auction status
 * @return const char* Status string
 */
const char* dap_chain_auction_status_to_str(dap_chain_auction_status_t a_status);

/**
 * @brief Convert event type to string
 * 
 * @param a_type Event type
 * @return const char* Type string
 */
const char* dap_chain_auction_event_type_to_str(dap_chain_auction_event_type_t a_type);

/**
 * @brief Convert string to event type
 * 
 * @param a_str Event type string
 * @return dap_chain_auction_event_type_t Event type
 */
dap_chain_auction_event_type_t dap_chain_auction_event_type_from_str(const char *a_str);

/**
 * @brief Free auction list
 * 
 * @param a_auctions Auction list
 * @param a_count Number of auctions
 */
void dap_chain_auction_storage_free_list(dap_chain_auction_info_t **a_auctions, size_t a_count);

/**
 * @brief Free auction info
 * 
 * @param a_auction_info Auction info to free
 */
void dap_chain_auction_storage_free_auction_info(dap_chain_auction_info_t *a_auction_info);

/**
 * @brief Free bid list  
 * 
 * @param a_bids Bid list
 * @param a_count Number of bids
 */
void dap_chain_auction_storage_free_bid_list(dap_chain_auction_bid_t **a_bids, size_t a_count);

/**
 * @brief Clear network auction storage
 * 
 * @param a_net Network to clear
 */
void dap_chain_auction_storage_clear_network(dap_chain_net_t *a_net);

/**
 * @brief Free events list
 * 
 * @param a_events Events list
 * @param a_count Number of events
 */
void dap_chain_auction_events_free_list(dap_chain_auction_event_t **a_events, size_t a_count);

// ===========================================
// CLI COMMAND HANDLERS  
// ===========================================

/**
 * @brief CLI handler for auction bid withdraw
 * 
 * Creates a withdraw transaction to unlock funds from auction bid conditional transaction.
 * 
 * @param argc Argument count
 * @param argv Argument values  
 * @param a_str_reply Reply string
 * @return int Result code (0 on success)
 */
static int s_cli_auction_withdraw(int argc, char **argv, void **a_str_reply);

// ===========================================
// CLI AND SERVICE INTEGRATION
// ===========================================

/**
 * @brief Initialize auction service
 * 
 * @return int Initialization result (0 on success)
 */
int dap_chain_net_srv_auctions_init(void);

/**
 * @brief Deinitialize auction service
 */
void dap_chain_net_srv_auctions_deinit(void);

#ifdef __cplusplus
}
#endif 