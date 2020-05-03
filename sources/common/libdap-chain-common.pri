HEADERS +=  $$PWD/include/dap_chain_common.h                 \
	    $$PWD/include/dap_chain_datum.h                  \
	    $$PWD/include/dap_chain_datum_hashtree_roots.h   \ 
	    $$PWD/include/dap_chain_datum_token.h            \
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

SOURCES +=  $$PWD/src/dap_chain_common.c                     \
	    $$PWD/src/dap_chain_datum.c                      \
	    $$PWD/src/dap_chain_datum_hashtree_roots.c       \
	    $$PWD/src/dap_chain_datum_token.c                \
	    $$PWD/src/dap_chain_datum_tx.c                   \
	    $$PWD/src/dap_chain_datum_tx_items.c             \
	    $$PWD/src/dap_chain_datum_tx_out_cond.c          \
	    $$PWD/src/dap_chain_datum_tx_receipt.c           \
	    $$PWD/src/dap_chain_datum_tx_token.c 

INCLUDEPATH += $$PWD/include 
