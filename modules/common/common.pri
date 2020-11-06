HEADERS +=  $$PWD/include/dap_chain_common.h                 \
	    $$PWD/include/dap_chain_datum.h                  \
	    $$PWD/include/dap_chain_datum_hashtree_roots.h   \ 
	    $$PWD/include/dap_chain_datum_token.h            \
	    $$PWD/include/dap_chain_datum_decree.h           \
	    $$PWD/include/dap_chain_datum_vote.h             \
	    $$PWD/include/dap_chain_datum_poll.h             \
	    $$PWD/include/dap_chain_datum_tx.h               \ 
	    $$PWD/include/dap_chain_datum_tx_in_cond.h       \
	    $$PWD/include/dap_chain_datum_tx_in.h            \
	    $$PWD/include/dap_chain_datum_tx_items.h         \
	    $$PWD/include/dap_chain_datum_tx_out_cond.h      \
	    $$PWD/include/dap_chain_datum_tx_out.h           \
	    $$PWD/include/dap_chain_datum_tx_pkey.h          \
	    $$PWD/include/dap_chain_datum_tx_receipt.h       \
	    $$PWD/include/dap_chain_datum_tx_sig.h           \
	    $$PWD/include/dap_chain_datum_tx_token.h         

SOURCES +=  $$PWD/dap_chain_common.c                     \
	    $$PWD/dap_chain_datum.c                      \
	    $$PWD/dap_chain_datum_vote.c                 \
	    $$PWD/dap_chain_datum_poll.c                 \
	    $$PWD/dap_chain_datum_decree.c               \
	    $$PWD/dap_chain_datum_hashtree_roots.c       \
	    $$PWD/dap_chain_datum_token.c                \
	    $$PWD/dap_chain_datum_tx.c                   \
	    $$PWD/dap_chain_datum_tx_items.c             \
	    $$PWD/dap_chain_datum_tx_receipt.c           \
	    $$PWD/dap_chain_datum_tx_token.c 

INCLUDEPATH += $$PWD/include 
