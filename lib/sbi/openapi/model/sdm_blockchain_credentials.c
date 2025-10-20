
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include "sdm_blockchain_credentials.h"

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

OpenAPI_sdm_blockchain_credentials_t *
OpenAPI_sdm_blockchain_credentials_copy(OpenAPI_sdm_blockchain_credentials_t *dst, OpenAPI_sdm_blockchain_credentials_t *src)
{
    cJSON *item = NULL;
    char *content = NULL;

    ogs_assert(src);

    // Convert source object to JSON
    item = OpenAPI_sdm_blockchain_credentials_convertToJSON(src);
    if (!item)
    {
        ogs_error("OpenAPI_sdm_blockchain_credentials_convertToJSON() failed");
        return NULL;
    }

    // Serialize JSON to string
    content = cJSON_Print(item);
    cJSON_Delete(item);

    if (!content)
    {
        ogs_error("cJSON_Print() failed");
        return NULL;
    }

    // Parse the JSON string back to cJSON object
    item = cJSON_Parse(content);
    ogs_free(content);
    if (!item)
    {
        ogs_error("cJSON_Parse() failed");
        return NULL;
    }

    // Free the destination object if it exists
    OpenAPI_sdm_blockchain_credentials_free(dst);

    // Parse JSON to create a new deep-copied object
    dst = OpenAPI_sdm_blockchain_credentials_parseFromJSON(item);
    cJSON_Delete(item);

    return dst;
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