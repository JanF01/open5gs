/*
 * Copyright (C) 2019-2023 by Sukchan Lee <acetcom@gmail.com>
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

#include "context.h"
#include "pfcp-path.h"
#include "gtp-path.h"
#include "n4-handler.h"

static void upf_n4_handle_create_urr(upf_sess_t *sess, ogs_pfcp_tlv_create_urr_t *create_urr_arr,
                                     uint8_t *cause_value, uint8_t *offending_ie_value)
{
    int i;
    ogs_pfcp_urr_t *urr;

    *cause_value = OGS_PFCP_CAUSE_REQUEST_ACCEPTED;

    for (i = 0; i < OGS_MAX_NUM_OF_URR; i++)
    {
        urr = ogs_pfcp_handle_create_urr(&sess->pfcp, &create_urr_arr[i],
                                         cause_value, offending_ie_value);
        if (!urr)
            return;

        /* TODO: enable counters somewhere else if ISTM not set, upon first pkt received */
        if (urr->meas_info.istm)
        {
            upf_sess_urr_acc_timers_setup(sess, urr);
        }
    }
}

void upf_n4_handle_session_establishment_request(
    upf_sess_t *sess, ogs_pfcp_xact_t *xact,
    ogs_pfcp_session_establishment_request_t *req)
{
    ogs_pfcp_pdr_t *pdr = NULL;
    ogs_pfcp_far_t *far = NULL;
    ogs_pfcp_pdr_t *created_pdr[OGS_MAX_NUM_OF_PDR];
    int num_of_created_pdr = 0;
    uint8_t cause_value = 0;
    uint8_t offending_ie_value = 0;
    int i;

    ogs_pfcp_sereq_flags_t sereq_flags;
    bool restoration_indication = false;

    upf_metrics_inst_global_inc(UPF_METR_GLOB_CTR_SM_N4SESSIONESTABREQ);

    ogs_assert(xact);
    ogs_assert(req);

    ogs_debug("Session Establishment Request");

    cause_value = OGS_PFCP_CAUSE_REQUEST_ACCEPTED;

    if (!sess)
    {
        ogs_error("No Context");
        ogs_pfcp_send_error_message(xact, 0,
                                    OGS_PFCP_SESSION_ESTABLISHMENT_RESPONSE_TYPE,
                                    OGS_PFCP_CAUSE_MANDATORY_IE_MISSING, 0);
        upf_metrics_inst_by_cause_add(OGS_PFCP_CAUSE_MANDATORY_IE_MISSING,
                                      UPF_METR_CTR_SM_N4SESSIONESTABFAIL, 1);
        return;
    }

    memset(&sereq_flags, 0, sizeof(sereq_flags));
    if (req->pfcpsereq_flags.presence == 1)
        sereq_flags.value = req->pfcpsereq_flags.u8;

    for (i = 0; i < OGS_MAX_NUM_OF_PDR; i++)
    {
        created_pdr[i] = ogs_pfcp_handle_create_pdr(&sess->pfcp,
                                                    &req->create_pdr[i], &sereq_flags,
                                                    &cause_value, &offending_ie_value);
        if (created_pdr[i] == NULL)
            break;
    }
    num_of_created_pdr = i;
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_FAR; i++)
    {
        if (ogs_pfcp_handle_create_far(&sess->pfcp, &req->create_far[i],
                                       &cause_value, &offending_ie_value) == NULL)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    upf_n4_handle_create_urr(sess, &req->create_urr[0], &cause_value, &offending_ie_value);
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    if (req->apn_dnn.presence)
    {
        char apn_dnn[OGS_MAX_DNN_LEN + 1];

        if (ogs_fqdn_parse(apn_dnn, req->apn_dnn.data,
                           ogs_min(req->apn_dnn.len, OGS_MAX_DNN_LEN)) <= 0)
        {
            ogs_error("Invalid APN");
            cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_INCORRECT;
            goto cleanup;
        }

        if (sess->apn_dnn)
            ogs_free(sess->apn_dnn);
        sess->apn_dnn = ogs_strdup(apn_dnn);
        ogs_assert(sess->apn_dnn);
    }

    for (i = 0; i < OGS_MAX_NUM_OF_QER; i++)
    {
        if (ogs_pfcp_handle_create_qer(&sess->pfcp, &req->create_qer[i],
                                       &cause_value, &offending_ie_value) == NULL)
            break;
        upf_metrics_inst_by_dnn_add(sess->apn_dnn,
                                    UPF_METR_GAUGE_UPF_QOSFLOWS, 1);
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    ogs_pfcp_handle_create_bar(&sess->pfcp, &req->create_bar,
                               &cause_value, &offending_ie_value);
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    /* Setup GTP Node */
    ogs_list_for_each(&sess->pfcp.far_list, far)
    {
        if (OGS_ERROR == ogs_pfcp_setup_far_gtpu_node(far))
        {
            ogs_fatal("CHECK CONFIGURATION: upf.gtpu");
            ogs_fatal("ogs_pfcp_setup_far_gtpu_node() failed");
            goto cleanup;
        }
        if (far->gnode)
            ogs_pfcp_far_f_teid_hash_set(far);
    }

    /* PFCPSEReq-Flags */
    if (sereq_flags.restoration_indication == 1)
    {
        for (i = 0; i < num_of_created_pdr; i++)
        {
            pdr = created_pdr[i];
            ogs_assert(pdr);

            /*
             * Only perform TEID restoration via swap when F-TEID.ch is false.
             *
             * When F-TEID.ch is false, it means the TEID has already been assigned, and
             * the restoration process can safely perform the swap.
             *
             * If F-TEID.ch is true, it indicates that the UPF needs to assign
             * a new TEID for the first time, so performing a swap is not appropriate
             * in this case.
             */
            if (pdr->f_teid_len > 0 && pdr->f_teid.ch == false)
            {
                cause_value = ogs_pfcp_pdr_swap_teid(pdr);
                if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
                    goto cleanup;
            }
        }
        restoration_indication = true;
    }

    for (i = 0; i < num_of_created_pdr; i++)
    {
        pdr = created_pdr[i];
        ogs_assert(pdr);

        /* Setup UE IP address */
        if (pdr->ue_ip_addr_len)
        {
            if (req->pdn_type.presence == 1)
            {
                cause_value = upf_sess_set_ue_ip(sess, req->pdn_type.u8, pdr);
                if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
                    goto cleanup;
            }
            else
            {
                ogs_error("No PDN Type");
            }
        }

        if (pdr->ipv4_framed_routes)
        {
            cause_value =
                upf_sess_set_ue_ipv4_framed_routes(sess,
                                                   pdr->ipv4_framed_routes);
            if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
                goto cleanup;
        }

        if (pdr->ipv6_framed_routes)
        {
            cause_value =
                upf_sess_set_ue_ipv6_framed_routes(sess,
                                                   pdr->ipv6_framed_routes);
            if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
                goto cleanup;
        }

        /* Setup UPF-N3-TEID & QFI Hash */
        if (pdr->f_teid_len)
            ogs_pfcp_object_teid_hash_set(
                OGS_PFCP_OBJ_SESS_TYPE, pdr, restoration_indication);
    }

    /* Send Buffered Packet to gNB/SGW */
    ogs_list_for_each(&sess->pfcp.pdr_list, pdr)
    {
        if (pdr->src_if == OGS_PFCP_INTERFACE_CORE)
        { /* Downlink */
            ogs_pfcp_send_buffered_gtpu(pdr);
        }
    }

    if (restoration_indication == true ||
        ogs_pfcp_self()->up_function_features.ftup == 0)
        ogs_assert(OGS_OK ==
                   upf_pfcp_send_session_establishment_response(
                       xact, sess, NULL, 0));
    else
        ogs_assert(OGS_OK ==
                   upf_pfcp_send_session_establishment_response(
                       xact, sess, created_pdr, num_of_created_pdr));

    return;

cleanup:
    upf_metrics_inst_by_cause_add(cause_value,
                                  UPF_METR_CTR_SM_N4SESSIONESTABFAIL, 1);
    ogs_pfcp_sess_clear(&sess->pfcp);
    ogs_pfcp_send_error_message(xact, sess ? sess->smf_n4_f_seid.seid : 0,
                                OGS_PFCP_SESSION_ESTABLISHMENT_RESPONSE_TYPE,
                                cause_value, offending_ie_value);
}

void upf_n4_handle_session_modification_request(
    upf_sess_t *sess, ogs_pfcp_xact_t *xact,
    ogs_pfcp_session_modification_request_t *req)
{
    ogs_pfcp_pdr_t *pdr = NULL;
    ogs_pfcp_far_t *far = NULL;
    ogs_pfcp_pdr_t *created_pdr[OGS_MAX_NUM_OF_PDR];
    int num_of_created_pdr = 0;
    uint8_t cause_value = 0;
    uint8_t offending_ie_value = 0;
    int i;

    ogs_assert(xact);
    ogs_assert(req);

    ogs_debug("Session Modification Request");

    cause_value = OGS_PFCP_CAUSE_REQUEST_ACCEPTED;

    if (!sess)
    {
        ogs_error("No Context");
        ogs_pfcp_send_error_message(xact, 0,
                                    OGS_PFCP_SESSION_MODIFICATION_RESPONSE_TYPE,
                                    OGS_PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND, 0);
        return;
    }

    for (i = 0; i < OGS_MAX_NUM_OF_PDR; i++)
    {
        created_pdr[i] = ogs_pfcp_handle_create_pdr(&sess->pfcp,
                                                    &req->create_pdr[i], NULL, &cause_value, &offending_ie_value);
        if (created_pdr[i] == NULL)
            break;
    }
    num_of_created_pdr = i;
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_PDR; i++)
    {
        if (ogs_pfcp_handle_update_pdr(&sess->pfcp, &req->update_pdr[i],
                                       &cause_value, &offending_ie_value) == NULL)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_PDR; i++)
    {
        if (ogs_pfcp_handle_remove_pdr(&sess->pfcp, &req->remove_pdr[i],
                                       &cause_value, &offending_ie_value) == false)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_FAR; i++)
    {
        if (ogs_pfcp_handle_create_far(&sess->pfcp, &req->create_far[i],
                                       &cause_value, &offending_ie_value) == NULL)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_FAR; i++)
    {
        if (ogs_pfcp_handle_update_far_flags(&sess->pfcp, &req->update_far[i],
                                             &cause_value, &offending_ie_value) == NULL)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    /* Send End Marker to gNB */
    ogs_list_for_each(&sess->pfcp.pdr_list, pdr)
    {
        if (pdr->src_if == OGS_PFCP_INTERFACE_CORE)
        { /* Downlink */
            far = pdr->far;
            if (far && far->smreq_flags.send_end_marker_packets)
                ogs_assert(OGS_ERROR != ogs_pfcp_send_end_marker(pdr));
        }
    }
    /* Clear PFCPSMReq-Flags */
    ogs_list_for_each(&sess->pfcp.far_list, far)
        far->smreq_flags.value = 0;

    for (i = 0; i < OGS_MAX_NUM_OF_FAR; i++)
    {
        if (ogs_pfcp_handle_update_far(&sess->pfcp, &req->update_far[i],
                                       &cause_value, &offending_ie_value) == NULL)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_FAR; i++)
    {
        if (ogs_pfcp_handle_remove_far(&sess->pfcp, &req->remove_far[i],
                                       &cause_value, &offending_ie_value) == false)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    upf_n4_handle_create_urr(sess, &req->create_urr[0], &cause_value, &offending_ie_value);
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_URR; i++)
    {
        if (ogs_pfcp_handle_update_urr(&sess->pfcp, &req->update_urr[i],
                                       &cause_value, &offending_ie_value) == NULL)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_URR; i++)
    {
        if (ogs_pfcp_handle_remove_urr(&sess->pfcp, &req->remove_urr[i],
                                       &cause_value, &offending_ie_value) == false)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_QER; i++)
    {
        if (ogs_pfcp_handle_create_qer(&sess->pfcp, &req->create_qer[i],
                                       &cause_value, &offending_ie_value) == NULL)
            break;
        upf_metrics_inst_by_dnn_add(sess->apn_dnn,
                                    UPF_METR_GAUGE_UPF_QOSFLOWS, 1);
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_QER; i++)
    {
        if (ogs_pfcp_handle_update_qer(&sess->pfcp, &req->update_qer[i],
                                       &cause_value, &offending_ie_value) == NULL)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_QER; i++)
    {
        if (ogs_pfcp_handle_remove_qer(&sess->pfcp, &req->remove_qer[i],
                                       &cause_value, &offending_ie_value) == false)
            break;
        upf_metrics_inst_by_dnn_add(sess->apn_dnn,
                                    UPF_METR_GAUGE_UPF_QOSFLOWS, -1);
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    ogs_pfcp_handle_create_bar(&sess->pfcp, &req->create_bar,
                               &cause_value, &offending_ie_value);
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    ogs_pfcp_handle_remove_bar(&sess->pfcp, &req->remove_bar,
                               &cause_value, &offending_ie_value);
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    /* Setup GTP Node */
    ogs_list_for_each(&sess->pfcp.far_list, far)
    {
        if (OGS_ERROR == ogs_pfcp_setup_far_gtpu_node(far))
        {
            ogs_fatal("CHECK CONFIGURATION: upf.gtpu");
            ogs_fatal("ogs_pfcp_setup_far_gtpu_node() failed");
            goto cleanup;
        }
        if (far->gnode)
            ogs_pfcp_far_f_teid_hash_set(far);
    }

    for (i = 0; i < num_of_created_pdr; i++)
    {
        pdr = created_pdr[i];
        ogs_assert(pdr);

        /* Setup UPF-N3-TEID & QFI Hash */
        if (pdr->f_teid_len)
            ogs_pfcp_object_teid_hash_set(OGS_PFCP_OBJ_SESS_TYPE, pdr, false);
    }

    /* Send Buffered Packet to gNB/SGW */
    ogs_list_for_each(&sess->pfcp.pdr_list, pdr)
    {
        if (pdr->src_if == OGS_PFCP_INTERFACE_CORE)
        { /* Downlink */
            ogs_pfcp_send_buffered_gtpu(pdr);
        }
    }

    if (ogs_pfcp_self()->up_function_features.ftup == 0)
        ogs_assert(OGS_OK ==
                   upf_pfcp_send_session_modification_response(
                       xact, sess, NULL, 0));
    else
        ogs_assert(OGS_OK ==
                   upf_pfcp_send_session_modification_response(
                       xact, sess, created_pdr, num_of_created_pdr));
    return;

cleanup:
    ogs_pfcp_sess_clear(&sess->pfcp);
    ogs_pfcp_send_error_message(xact, sess ? sess->smf_n4_f_seid.seid : 0,
                                OGS_PFCP_SESSION_MODIFICATION_RESPONSE_TYPE,
                                cause_value, offending_ie_value);
}

void upf_n4_handle_session_deletion_request(
    upf_sess_t *sess, ogs_pfcp_xact_t *xact,
    ogs_pfcp_session_deletion_request_t *req)
{
    ogs_pfcp_qer_t *qer = NULL;

    ogs_assert(xact);
    ogs_assert(req);

    ogs_debug("Session Deletion Request");

    if (!sess)
    {
        ogs_error("No Context");
        ogs_pfcp_send_error_message(xact, 0,
                                    OGS_PFCP_SESSION_DELETION_RESPONSE_TYPE,
                                    OGS_PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND, 0);
        return;
    }
    upf_pfcp_send_session_deletion_response(xact, sess);

    ogs_list_for_each(&sess->pfcp.qer_list, qer)
    {
        upf_metrics_inst_by_dnn_add(sess->apn_dnn,
                                    UPF_METR_GAUGE_UPF_QOSFLOWS, -1);
    }
    upf_sess_remove(sess);
}

void upf_n4_handle_session_report_response(
    upf_sess_t *sess, ogs_pfcp_xact_t *xact,
    ogs_pfcp_session_report_response_t *rsp)
{
    uint8_t cause_value = 0;

    ogs_assert(xact);
    ogs_assert(rsp);

    ogs_pfcp_xact_commit(xact);

    ogs_debug("Session Report Response");

    cause_value = OGS_PFCP_CAUSE_REQUEST_ACCEPTED;

    if (!sess)
    {
        ogs_warn("No Context");
        cause_value = OGS_PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND;
    }

    if (rsp->cause.presence)
    {
        if (rsp->cause.u8 != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        {
            ogs_error("PFCP Cause[%d] : Not Accepted", rsp->cause.u8);
            cause_value = rsp->cause.u8;
        }
    }
    else
    {
        ogs_error("No Cause");
        cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
    }

    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
    {
        ogs_error("Cause request not accepted[%d]", cause_value);
        return;
    }
    else
    {
        upf_metrics_inst_global_inc(UPF_METR_GLOB_CTR_SM_N4SESSIONREPORTSUCC);
    }
}

void upf_n4_handle_blockchain_credentials_response(
    upf_sess_t *sess, ogs_pfcp_xact_t *xact,
    ogs_pfcp_blockchain_credentials_response_t *rsp)
{
    char json[256] = {0};
    char ue_ip_str[64] = "(none)";
    char src_ip_str[64] = "(none)";
    uint32_t ue_ip_n = 0;   /* network byte order */
    uint32_t src_ip_n = 0;  /* network byte order */

    /* Basic validation */
    if (!sess) {
        ogs_error("upf_n4_handle_blockchain_credentials_response: sess == NULL");
        return;
    }
    if (!xact) {
        ogs_error("upf_n4_handle_blockchain_credentials_response: xact == NULL");
        return;
    }
    if (!rsp) {
        ogs_error("upf_n4_handle_blockchain_credentials_response: rsp == NULL");
        /* still commit/cleanup xact? we don't here because nothing to commit */
        return;
    }

    ogs_info("Received PFCP Blockchain Credentials Response for SEID: %lu",
             (unsigned long)sess->smf_n4_f_seid.seid);

    /* --- Log Cause IE if present --- */
    if (rsp->cause.presence) {
        ogs_info("PFCP Cause: %u", rsp->cause.u8);
    } else {
        ogs_warn("PFCP Cause IE not present");
    }

    /* --- Log Credentials IE if present (optional) --- */
    if (rsp->credentials.presence) {
        const char *login_str = NULL;
        const char *password_str = NULL;
        if (rsp->credentials.login.presence && rsp->credentials.login.data)
            login_str = (char *)rsp->credentials.login.data;
        if (rsp->credentials.password.presence && rsp->credentials.password.data)
            password_str = (char *)rsp->credentials.password.data;

        ogs_info("Blockchain Credentials present in response:");
        ogs_info("  - Login: %s", login_str ? login_str : "(missing)");
        ogs_info("  - Password: %s", password_str ? password_str : "(missing)");
    } else {
        ogs_debug("Blockchain Credentials IE not present in response (that's OK)");
    }

    /* --- Extract blockchain_node_id and build JSON --- */
    const char *node_data = NULL;
    int node_len = 0;

    if (rsp->blockchain_node_id.presence && rsp->blockchain_node_id.data && rsp->blockchain_node_id.len > 0) {
        node_data = (const char *)rsp->blockchain_node_id.data;
        node_len = (int)rsp->blockchain_node_id.len;
    }

    if (!node_data || node_len <= 0) {
        ogs_warn("No blockchain_node_id found in PFCP response; will send 'unknown' JSON to UE");
        snprintf(json, sizeof(json), "{\"blockchain_node_id\":\"unknown\"}");
    } else {
        /* clamp node_len so snprintf stays safe */
        int max_node_len = (int)sizeof(json) - 32; /* room for JSON wrapper */
        if (node_len > max_node_len) node_len = max_node_len;
        /* use precision to handle not-terminated binary-safe data */
        snprintf(json, sizeof(json), "{\"blockchain_node_id\":\"%.*s\"}", node_len, node_data);
    }

    ogs_info("Prepared JSON to send to UE: %s", json);

    /* --- Get UE IPv4 address (network byte order) --- */
    if (sess->ipv4) {
        ue_ip_n = sess->ipv4->addr[0]; /* network byte order */
        if (inet_ntop(AF_INET, &ue_ip_n, ue_ip_str, sizeof(ue_ip_str)) == NULL)
            snprintf(ue_ip_str, sizeof(ue_ip_str), "(inet_ntop failed)");
    } else {
        ogs_error("No sess->ipv4 present for this session; cannot send JSON to UE");
        /* commit the PFCP transaction anyway (if that is the expected behaviour) */
        ogs_pfcp_xact_commit(xact);
        return;
    }

    src_ip_n = inet_addr("10.45.0.1"); /* network byte order */
    strncpy(src_ip_str, "10.45.0.1", sizeof(src_ip_str) - 1);
    src_ip_str[sizeof(src_ip_str) - 1] = '\0';

    ogs_info("Sending JSON to UE %s (net=0x%08x) from UPF %s (net=0x%08x)",
            ue_ip_str, ntohl(ue_ip_n), src_ip_str, ntohl(src_ip_n));

    /* --- send JSON to UE via helper --- */
    upf_send_json_to_ue(NULL,
                        ue_ip_n,   /* network byte order */
                        9500,      /* destination TCP port at UE */
                        src_ip_n,  /* source IP (network order) */
                        12345,     /* source TCP port - choose appropriate ephemeral port */
                        json);

    /* --- Commit the PFCP transaction --- */
    ogs_pfcp_xact_commit(xact);

    ogs_info("Blockchain credentials PFCP exchange completed successfully for SEID: %lu",
             (unsigned long)sess->smf_n4_f_seid.seid);
}

void upf_n4_handle_blockchain_node_id_response(
    upf_sess_t *sess, ogs_pfcp_xact_t *xact,
    ogs_pfcp_blockchain_node_id_response_t *rsp)
{
    char ue_ip_str[INET_ADDRSTRLEN] = "(none)";
    uint32_t ue_ip_n = 0;

    /* --- Validate pointers --- */
    if (!sess) {
        ogs_error("upf_n4_handle_blockchain_node_id_response: sess == NULL");
        return;
    }
    if (!xact) {
        ogs_error("upf_n4_handle_blockchain_node_id_response: xact == NULL");
        return;
    }
    if (!rsp) {
        ogs_error("upf_n4_handle_blockchain_node_id_response: rsp == NULL");
        return;
    }

    ogs_info("Received PFCP Blockchain Node ID Response for SEID [%lu]",
             (unsigned long)sess->smf_n4_f_seid.seid);

    /* --- Show PFCP Cause IE if present --- */
    if (rsp->cause.presence)
        ogs_info("PFCP Cause: %u", rsp->cause.u8);
    else
        ogs_warn("PFCP Cause IE not present");

    /* --- Extract and display UE IPv4 from response --- */
    if (rsp->ue_ip_address.presence && rsp->ue_ip_address.data) {
        /* PFCP encodes IPv4 address in network byte order */
        memcpy(&ue_ip_n, rsp->ue_ip_address.data, sizeof(ue_ip_n));
        if (inet_ntop(AF_INET, &ue_ip_n, ue_ip_str, sizeof(ue_ip_str)) == NULL)
            snprintf(ue_ip_str, sizeof(ue_ip_str), "(inet_ntop fail");
        ogs_info("UE IPv4 from PFCP response: %s", ue_ip_str);
    } else {
        ogs_warn("UE IPv4 address not present in PFCP Blockchain Node ID Response");
    }

    /* --- Display blockchain_node_id if present --- */
    if (rsp->blockchain_node_id.presence && rsp->blockchain_node_id.data) {
        ogs_info("Blockchain Node ID: %.*s",
                 rsp->blockchain_node_id.len,
                 (char *)rsp->blockchain_node_id.data);
    } else {
        ogs_info("Blockchain Node ID not present in response");
    }

    /* --- Commit the PFCP transaction --- */
    ogs_pfcp_xact_commit(xact);

    ogs_info("Handled PFCP Blockchain Node ID Response successfully for SEID [%lu]",
             (unsigned long)sess->smf_n4_f_seid.seid);
}