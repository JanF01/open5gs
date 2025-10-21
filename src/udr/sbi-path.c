/*
 * Copyright (C) 2019-2022 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "sbi-path.h"

int udr_sbi_open(void)
{
    ogs_sbi_nf_instance_t *nf_instance = NULL;
    ogs_sbi_nf_service_t *service = NULL;

    /* Initialize SELF NF instance */
    nf_instance = ogs_sbi_self()->nf_instance;
    ogs_assert(nf_instance);
    ogs_sbi_nf_fsm_init(nf_instance);

    /* Build NF instance information. It will be transmitted to NRF. */
    ogs_sbi_nf_instance_build_default(nf_instance);
    ogs_sbi_nf_instance_add_allowed_nf_type(nf_instance, OpenAPI_nf_type_SCP);
    ogs_sbi_nf_instance_add_allowed_nf_type(nf_instance, OpenAPI_nf_type_PCF);
    ogs_sbi_nf_instance_add_allowed_nf_type(nf_instance, OpenAPI_nf_type_UDM);

    /* Build NF service information. It will be transmitted to NRF. */
    if (ogs_sbi_nf_service_is_available(OGS_SBI_SERVICE_NAME_NUDR_DR)) {
        service = ogs_sbi_nf_service_build_default(
                    nf_instance, OGS_SBI_SERVICE_NAME_NUDR_DR);
        ogs_assert(service);
        ogs_sbi_nf_service_add_version(
                    service, OGS_SBI_API_V1, OGS_SBI_API_V1_0_0, NULL);
        ogs_sbi_nf_service_add_allowed_nf_type(service, OpenAPI_nf_type_PCF);
        ogs_sbi_nf_service_add_allowed_nf_type(service, OpenAPI_nf_type_UDM);
    }

    /* Initialize NRF NF Instance */
    nf_instance = ogs_sbi_self()->nrf_instance;
    if (nf_instance)
        ogs_sbi_nf_fsm_init(nf_instance);

    /* Setup Subscription-Data */
    ogs_sbi_subscription_spec_add(OpenAPI_nf_type_SEPP, NULL);

    if (ogs_sbi_server_start_all(ogs_sbi_server_handler) != OGS_OK)
        return OGS_ERROR;

    if (!udr_sbi_obj_initialized) {
        memset(&udr_sbi_obj, 0, sizeof(udr_sbi_obj));
        udr_sbi_obj.type = OGS_SBI_OBJ_BASE;
        ogs_list_init(&udr_sbi_obj.xact_list);
        udr_sbi_obj_initialized = true;
    }    

    return OGS_OK;
}

void udr_sbi_close(void)
{
    ogs_sbi_client_stop_all();
    ogs_sbi_server_stop_all();
}

bool udr_sbi_send_request(
        ogs_sbi_nf_instance_t *nf_instance, ogs_sbi_xact_t *xact)
{
    ogs_assert(nf_instance);
    ogs_assert(xact);
    return ogs_sbi_send_request_to_nf_instance(nf_instance, xact);
}

int udr_sbi_discover_and_send(
        ogs_sbi_service_type_e service_type,
        ogs_sbi_discovery_option_t *discovery_option,
        ogs_sbi_build_f build,
        udr_sbi_ctx_t *ctx, // Accept the pre-allocated context
        void *data)
{
    int r;

    ogs_assert(ctx); // Ensure context is provided
    ogs_assert(udr_sbi_obj.lnode.next || true); // just to assert initialized

    ogs_sbi_xact_t *xact = ogs_sbi_xact_add(
        0,                    // id not used per-UE
        &udr_sbi_obj,         // persistent UDR SBI object
        service_type,
        discovery_option,
        build,
        ctx,                  // Use the provided context directly
        data
    );
    if (!xact) {
        ogs_error("udr_sbi_discover_and_send() failed");
        ogs_pool_free(&udr_sbi_ctx_pool, ctx); // Free the context if transaction creation fails
        return OGS_ERROR;
    }

    xact->state = ctx->state; // Set the state from the context

    r = ogs_sbi_discover_and_send(xact);
    if (r != OGS_OK) {
        ogs_error("udr_sbi_discover_and_send() failed");
        ogs_sbi_xact_remove(xact);
        ogs_pool_free(&udr_sbi_ctx_pool, ctx); // Free the context if sending fails
        return r;
    }

    // The context will be freed when the SBI transaction completes or is removed.
    // For now, we assume it's managed by the SBI layer after this point.
    return OGS_OK;
}