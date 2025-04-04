/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include "s2n_test.h"

#include "testlib/s2n_testlib.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <s2n.h>

/* The number of connection pairs to allocate before measuring memory
 * usage. The greater the value, the more accurate the end result. */
#define CONNECTIONS 250

/* This is roughly the current memory usage per connection */
#define MEM_PER_CONNECTION (106 * 1024)

/* This is the maximum  memory per conneciton including 4KB of slack */
#define MAX_MEM_PER_CONNECTION (MEM_PER_CONNECTION + 4 * 1024)

#define MAX_ALLOWED_MEM_DIFF ((ssize_t) 2 * CONNECTIONS * MAX_MEM_PER_CONNECTION)


ssize_t get_vm_data_size()
{
#ifdef __linux__
    long page_size;
    ssize_t size, resident, share, text, lib, data, dt;

    page_size = sysconf(_SC_PAGESIZE);
    if (page_size < 0) {
        return -1;
    }

    FILE *status_file = fopen( "/proc/self/statm", "r" );
    if (fscanf(status_file, "%zd %zd %zd %zd %zd %zd %zd", &size, &resident, &share, &text, &lib, &data, &dt) < 7) {
        fclose(status_file);
        return -1;
    }
    fclose(status_file);

    return data * page_size;
#else
    /* Not implemented for other platforms */
    return 0;
#endif
}

int main(int argc, char **argv)
{
    int server_to_client[2 * CONNECTIONS];
    int client_to_server[2 * CONNECTIONS];
    struct s2n_connection *clients[CONNECTIONS];
    struct s2n_connection *servers[CONNECTIONS];

    char *cert_chain;
    char *private_key;

    BEGIN_TEST();

    /* Skip the test when running under valgrind or address sanitizer, as those tools
     * impact the memory usage. */
    if (getenv("S2N_VALGRIND") != NULL || getenv("S2N_ADDRESS_SANITIZER") != NULL) {
        END_TEST();
    }

    EXPECT_SUCCESS(setenv("S2N_ENABLE_CLIENT_MODE", "1", 0));

    EXPECT_NOT_NULL(cert_chain = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(private_key = malloc(S2N_MAX_TEST_PEM_SIZE));

    struct s2n_config *client_config;
    EXPECT_NOT_NULL(client_config = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_set_check_stapled_ocsp_response(client_config, 0));
    EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));

    struct s2n_cert_chain_and_key *chain_and_key;
    struct s2n_config *server_config;
    EXPECT_NOT_NULL(server_config = s2n_config_new());
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
    EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain, private_key));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));

    ssize_t vm_data_initial = get_vm_data_size();
    EXPECT_NOT_EQUAL(vm_data_initial, -1);

    /* Allocate all connections */
    for (int i = 0; i < CONNECTIONS; i++)
    {
        /* Create nonblocking pipes */
        EXPECT_SUCCESS(pipe(server_to_client + 2 * i));
        EXPECT_SUCCESS(pipe(client_to_server + 2 * i));
        for (int j = i * 2; j < (i + 1) * 2; j++) {
            EXPECT_NOT_EQUAL(fcntl(server_to_client[j], F_SETFL, fcntl(server_to_client[j], F_GETFL) | O_NONBLOCK), -1);
            EXPECT_NOT_EQUAL(fcntl(client_to_server[j], F_SETFL, fcntl(client_to_server[j], F_GETFL) | O_NONBLOCK), -1);
        }

        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        EXPECT_SUCCESS(s2n_connection_set_read_fd(client_conn, server_to_client[i * 2]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(client_conn, client_to_server[i * 2 + 1]));
        EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
        clients[i] = client_conn;

        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[i * 2]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[i * 2 + 1]));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
        EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
        servers[i] = server_conn;
    }

    ssize_t vm_data_after_allocation = get_vm_data_size();
    EXPECT_NOT_EQUAL(vm_data_after_allocation, -1);

    for (int i = 0; i < CONNECTIONS; i++) {
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(servers[i], clients[i]));
    }

    ssize_t vm_data_after_handshakes = get_vm_data_size();
    EXPECT_NOT_EQUAL(vm_data_after_handshakes, -1);

    for (int i = 0; i < CONNECTIONS; i++) {
        EXPECT_SUCCESS(s2n_connection_free(clients[i]));
        EXPECT_SUCCESS(s2n_connection_free(servers[i]));

        for (int j = i * 2; j < (i + 1) * 2; j++) {
            EXPECT_SUCCESS(close(server_to_client[j]));
            EXPECT_SUCCESS(close(client_to_server[j]));
        }
    }

    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
    EXPECT_SUCCESS(s2n_config_free(server_config));
    EXPECT_SUCCESS(s2n_config_free(client_config));

    free(cert_chain);
    free(private_key);

#if 0
    fprintf(stdout, "\n");
    fprintf(stdout, "VmData initial:           %10zu\n", vm_data_initial);
    fprintf(stdout, "VmData after allocations: %10zu\n", vm_data_after_allocation);
    fprintf(stdout, "VmData after handshakes:  %10zu\n", vm_data_after_handshakes);
    fprintf(stdout, "Max VmData diff allowed:  %10zu\n", MAX_ALLOWED_MEM_DIFF);
#endif

    EXPECT_TRUE(vm_data_after_allocation - vm_data_initial < MAX_ALLOWED_MEM_DIFF);
    EXPECT_TRUE(vm_data_after_handshakes - vm_data_initial < MAX_ALLOWED_MEM_DIFF);


    END_TEST();

    return 0;
}

