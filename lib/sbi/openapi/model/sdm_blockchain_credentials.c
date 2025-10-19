
#include "sdm_blockchain_credentials.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

OpenAPI_sdm_blockchain_credentials_t *OpenAPI_sdm_blockchain_credentials_create(
    char *login,
    char *password,
    OpenAPI_snssai_t *single_nssai
) {
    OpenAPI_sdm_blockchain_credentials_t *sdm_blockchain_credentials_local_var = ogs_malloc(sizeof(OpenAPI_sdm_blockchain_credentials_t));
    if (!sdm_blockchain_credentials_local_var) {
        return NULL;
    }
    sdm_blockchain_credentials_local_var->login = ogs_strdup(login);
    sdm_blockchain_credentials_local_var->password = ogs_strdup(password);
    sdm_blockchain_credentials_local_var->single_nssai = single_nssai;

    return sdm_blockchain_credentials_local_var;
}

void OpenAPI_sdm_blockchain_credentials_free(OpenAPI_sdm_blockchain_credentials_t *sdm_blockchain_credentials) {
    if (NULL == sdm_blockchain_credentials) {
        return;
    }
    OpenAPI_lnode_t *node;
    ogs_free(sdm_blockchain_credentials->login);
    ogs_free(sdm_blockchain_credentials->password);
    OpenAPI_snssai_free(sdm_blockchain_credentials->single_nssai);
    ogs_free(sdm_blockchain_credentials);
}

cJSON *OpenAPI_sdm_blockchain_credentials_convertToJSON(OpenAPI_sdm_blockchain_credentials_t *sdm_blockchain_credentials) {
    cJSON *item = cJSON_CreateObject();

    if (sdm_blockchain_credentials->login) {
        if (cJSON_AddStringToObject(item, "login", sdm_blockchain_credentials->login) == NULL) {
            ogs_error("OpenAPI_sdm_blockchain_credentials_convertToJSON: item->login");
            goto end;
        }
    }

    if (sdm_blockchain_credentials->password) {
        if (cJSON_AddStringToObject(item, "password", sdm_blockchain_credentials->password) == NULL) {
            ogs_error("OpenAPI_sdm_blockchain_credentials_convertToJSON: item->password");
            goto end;
        }
    }

    if (sdm_blockchain_credentials->single_nssai) {
        cJSON *single_nssai_local_JSON = OpenAPI_snssai_convertToJSON(sdm_blockchain_credentials->single_nssai);
        if (single_nssai_local_JSON == NULL) {
            ogs_error("OpenAPI_sdm_blockchain_credentials_convertToJSON: single_nssai_local_JSON");
            goto end;
        }
        cJSON_AddItemToObject(item, "singleNssai", single_nssai_local_JSON);
        if (item->child == NULL) {
            ogs_error("OpenAPI_sdm_blockchain_credentials_convertToJSON: item->single_nssai");
            goto end;
        }
    }

end:
    return item;
}

OpenAPI_sdm_blockchain_credentials_t *OpenAPI_sdm_blockchain_credentials_parseFromJSON(cJSON *sdm_blockchain_credentialsJSON) {
    OpenAPI_sdm_blockchain_credentials_t *sdm_blockchain_credentials_local_var = NULL;
    cJSON *login = NULL;
    cJSON *password = NULL;
    cJSON *single_nssai = NULL;

    login = cJSON_GetObjectItemCaseSensitive(sdm_blockchain_credentialsJSON, "login");
    if (login) {
        if (!cJSON_IsString(login) && !cJSON_IsNull(login)) {
            ogs_error("OpenAPI_sdm_blockchain_credentials_parseFromJSON: login (IsString)");
            goto end;
        }
    }

    password = cJSON_GetObjectItemCaseSensitive(sdm_blockchain_credentialsJSON, "password");
    if (password) {
        if (!cJSON_IsString(password) && !cJSON_IsNull(password)) {
            ogs_error("OpenAPI_sdm_blockchain_credentials_parseFromJSON: password (IsString)");
            goto end;
        }
    }

    single_nssai = cJSON_GetObjectItemCaseSensitive(sdm_blockchain_credentialsJSON, "singleNssai");
    if (single_nssai) {
        single_nssai = OpenAPI_snssai_parseFromJSON(single_nssai);
        if (!single_nssai) {
            ogs_error("OpenAPI_sdm_blockchain_credentials_parseFromJSON: single_nssai");
            goto end;
        }
    }

    sdm_blockchain_credentials_local_var = OpenAPI_sdm_blockchain_credentials_create(
        login && !cJSON_IsNull(login) ? ogs_strdup(login->valuestring) : NULL,
        password && !cJSON_IsNull(password) ? ogs_strdup(password->valuestring) : NULL,
        single_nssai
    );

    return sdm_blockchain_credentials_local_var;
end:
    if (single_nssai) {
        OpenAPI_snssai_free(single_nssai);
        single_nssai = NULL;
    }
    return NULL;
}