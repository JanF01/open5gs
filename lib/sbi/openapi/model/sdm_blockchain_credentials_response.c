#include "sdm_blockchain_credentials_response.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include "sdm_blockchain_node_id.h"

// Create
OpenAPI_sdm_blockchain_credentials_response_t *
OpenAPI_sdm_blockchain_credentials_response_create(OpenAPI_sdm_blockchain_node_id_t *node_id)
{
    OpenAPI_sdm_blockchain_credentials_response_t *obj =
        ogs_malloc(sizeof(OpenAPI_sdm_blockchain_credentials_response_t));
    ogs_assert(obj);
    obj->node_id = node_id;
    return obj;
}

// Free
void OpenAPI_sdm_blockchain_credentials_response_free(OpenAPI_sdm_blockchain_credentials_response_t *obj)
{
    if (!obj)
        return;

    if (obj->node_id)
    {
        OpenAPI_sdm_blockchain_node_id_free(obj->node_id);
        obj->node_id = NULL;
    }

    ogs_free(obj);
}

// Convert to JSON
cJSON *OpenAPI_sdm_blockchain_credentials_response_convertToJSON(OpenAPI_sdm_blockchain_credentials_response_t *obj)
{
    if (!obj)
        return NULL;

    cJSON *item = cJSON_CreateObject();
    if (!item)
        return NULL;

    if (obj->node_id)
    {
        cJSON *node_id_JSON = OpenAPI_sdm_blockchain_node_id_convertToJSON(obj->node_id);
        if (!node_id_JSON)
        {
            ogs_error("OpenAPI_sdm_blockchain_credentials_response_convertToJSON: node_id failed");
            cJSON_Delete(item);
            return NULL;
        }
        cJSON_AddItemToObject(item, "nodeId", node_id_JSON);
    }

    return item;
}

// Parse from JSON
OpenAPI_sdm_blockchain_credentials_response_t *
OpenAPI_sdm_blockchain_credentials_response_parseFromJSON(cJSON *json)
{
    if (!json)
        return NULL;

    cJSON *node_id_json = cJSON_GetObjectItemCaseSensitive(json, "nodeId");
    OpenAPI_sdm_blockchain_node_id_t *node_id_obj = NULL;

    if (node_id_json)
    {
        node_id_obj = OpenAPI_sdm_blockchain_node_id_parseFromJSON(node_id_json);
        if (!node_id_obj)
        {
            ogs_error("OpenAPI_sdm_blockchain_credentials_response_parseFromJSON: node_id parse failed");
            return NULL;
        }
    }

    return OpenAPI_sdm_blockchain_credentials_response_create(node_id_obj);
}

// Deep copy
OpenAPI_sdm_blockchain_credentials_response_t *
OpenAPI_sdm_blockchain_credentials_response_copy(OpenAPI_sdm_blockchain_credentials_response_t *dst,
                                                 OpenAPI_sdm_blockchain_credentials_response_t *src)
{
    if (!src)
        return NULL;

    if (!dst)
        return OpenAPI_sdm_blockchain_credentials_response_create(
            OpenAPI_sdm_blockchain_node_id_copy(NULL, src->node_id));

    if (dst->node_id)
    {
        OpenAPI_sdm_blockchain_node_id_free(dst->node_id);
        dst->node_id = NULL;
    }

    dst->node_id = OpenAPI_sdm_blockchain_node_id_copy(NULL, src->node_id);
    return dst;
}