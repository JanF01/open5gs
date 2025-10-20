
#include "sdm_blockchain_credentials.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

OpenAPI_sdm_blockchain_credentials_t *OpenAPI_sdm_blockchain_credentials_create(
    char *login,
    char *password,
    OpenAPI_snssai_t *single_nssai)
{
    OpenAPI_sdm_blockchain_credentials_t *local_var = ogs_malloc(sizeof(OpenAPI_sdm_blockchain_credentials_t));
    ogs_assert(local_var);

    local_var->login = login ? ogs_strdup(login) : NULL;
    local_var->password = password ? ogs_strdup(password) : NULL;
    local_var->single_nssai = single_nssai;

    return local_var;
}

void OpenAPI_sdm_blockchain_credentials_free(OpenAPI_sdm_blockchain_credentials_t *obj)
{
    if (!obj)
        return;

    ogs_free(obj->login);
    ogs_free(obj->password);
    if (obj->single_nssai)
    {
        OpenAPI_snssai_free(obj->single_nssai);
        obj->single_nssai = NULL;
    }
    ogs_free(obj);
}

cJSON *OpenAPI_sdm_blockchain_credentials_convertToJSON(OpenAPI_sdm_blockchain_credentials_t *obj)
{
    if (!obj)
        return NULL;

    cJSON *item = cJSON_CreateObject();

    if (obj->login && cJSON_AddStringToObject(item, "login", obj->login) == NULL)
    {
        ogs_error("OpenAPI_sdm_blockchain_credentials_convertToJSON: login");
        goto end;
    }

    if (obj->password && cJSON_AddStringToObject(item, "password", obj->password) == NULL)
    {
        ogs_error("OpenAPI_sdm_blockchain_credentials_convertToJSON: password");
        goto end;
    }

    if (obj->single_nssai)
    {
        cJSON *single_nssai_JSON = OpenAPI_snssai_convertToJSON(obj->single_nssai);
        if (!single_nssai_JSON)
        {
            ogs_error("OpenAPI_sdm_blockchain_credentials_convertToJSON: single_nssai");
            goto end;
        }
        cJSON_AddItemToObject(item, "singleNssai", single_nssai_JSON);
    }

    return item;

end:
    if (item)
        cJSON_Delete(item);
    return NULL;
}

OpenAPI_sdm_blockchain_credentials_t *OpenAPI_sdm_blockchain_credentials_parseFromJSON(cJSON *json)
{
    if (!json)
        return NULL;

    cJSON *login = cJSON_GetObjectItemCaseSensitive(json, "login");
    cJSON *password = cJSON_GetObjectItemCaseSensitive(json, "password");
    cJSON *single_nssai_JSON = cJSON_GetObjectItemCaseSensitive(json, "singleNssai");

    OpenAPI_snssai_t *single_nssai_parsed = NULL;
    if (single_nssai_JSON)
    {
        single_nssai_parsed = OpenAPI_snssai_parseFromJSON(single_nssai_JSON);
        if (!single_nssai_parsed)
        {
            ogs_error("OpenAPI_sdm_blockchain_credentials_parseFromJSON: single_nssai");
            return NULL;
        }
    }

    OpenAPI_sdm_blockchain_credentials_t *local_var = OpenAPI_sdm_blockchain_credentials_create(
        login && cJSON_IsString(login) && !cJSON_IsNull(login) ? ogs_strdup(login->valuestring) : NULL,
        password && cJSON_IsString(password) && !cJSON_IsNull(password) ? ogs_strdup(password->valuestring) : NULL,
        single_nssai_parsed);

    return local_var;
}