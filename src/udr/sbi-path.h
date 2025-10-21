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

#ifndef UDR_SBI_PATH_H
#define UDR_SBI_PATH_H

#include "context.h"

#include "nudm-build.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UDR_SBI_NO_STATE                                   0

int udr_sbi_open(void);
void udr_sbi_close(void);

#ifdef __cplusplus
}
#endif

bool udr_sbi_send_request(
        ogs_sbi_nf_instance_t *nf_instance, ogs_sbi_xact_t *xact);
int udr_sbi_discover_and_send(
        ogs_sbi_service_type_e service_type,
        ogs_sbi_discovery_option_t *discovery_option,
        ogs_sbi_build_f build,
        udr_sbi_ctx_t *ctx, // Accept the pre-allocated context
        void *data);

#endif /* UDR_SBI_PATH_H */
