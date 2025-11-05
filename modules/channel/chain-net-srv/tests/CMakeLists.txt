cmake_minimum_required(VERSION 3.10)

project(chain-net-srv-billing-tests)

file(GLOB BILLING_TESTS_SRC *.c)

add_executable(${PROJECT_NAME} ${BILLING_TESTS_SRC})

# Link module under test and internal test framework; external deps will be mocked
target_link_libraries(${PROJECT_NAME} dap_test dap_stream_ch_chain_net_srv)

# Use linker wrapping to intercept low-level I/O/enc functions during tests
target_link_options(${PROJECT_NAME} PRIVATE
    -Wl,--wrap=dap_stream_pkt_write_unsafe
    -Wl,--wrap=dap_stream_ch_pkt_write_unsafe
    -Wl,--wrap=dap_events_socket_write_unsafe
    -Wl,--wrap=dap_enc_code
    -Wl,--wrap=dap_enc_key_get_enc_size
    -Wl,--wrap=dap_chain_net_srv_get
    -Wl,--wrap=dap_chain_net_srv_get_price_from_order
    -Wl,--wrap=dap_chain_net_by_id
    -Wl,--wrap=dap_chain_net_get_state
    -Wl,--wrap=dap_chain_net_get_role
    -Wl,--wrap=dap_ledger_tx_find_datum_by_hash
    -Wl,--wrap=dap_enc_key_serialize_pub_key
    -Wl,--wrap=dap_chain_net_srv_issue_receipt
    -Wl,--wrap=dap_chain_datum_tx_receipt_create
    -Wl,--wrap=dap_timerfd_start_on_worker
    -Wl,--wrap=dap_timerfd_delete_unsafe
    -Wl,--wrap=dap_worker_exec_callback_on
    -Wl,--wrap=dap_global_db_get_sync
    -Wl,--wrap=dap_global_db_set
    -Wl,--wrap=dap_chain_mempool_tx_create_cond_input
    -Wl,--wrap=dap_stream_ch_find_by_uuid_unsafe
    -Wl,--wrap=dap_chain_datum_tx_out_cond_get
    -Wl,--wrap=dap_chain_datum_tx_receipt_sign_get
    -Wl,--wrap=dap_ledger_tx_find_by_hash
)

add_test(
    NAME chain-net-srv-billing-tests
    COMMAND chain-net-srv-billing-tests
)


