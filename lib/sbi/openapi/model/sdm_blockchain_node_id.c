
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include "sdm_blockchain_node_id.h"

OpenAPI_sdm_blockchain_node_id_t *OpenAPI_sdm_blockchain_node_id_create(const char *blockchain_node_id)
{
    OpenAPI_sdm_blockchain_node_id_t *obj = ogs_malloc(sizeof(OpenAPI_sdm_blockchain_node_id_t));
    ogs_assert(obj);
    obj->blockchain_node_id = blockchain_node_id ? ogs_strdup(blockchain_node_id) : NULL;
    return obj;
}

void OpenAPI_sdm_blockchain_node_id_free(OpenAPI_sdm_blockchain_node_id_t *obj)
{
    if (!obj)
        return;
    if (obj->blockchain_node_id)
    {
        ogs_free(obj->blockchain_node_id);
        obj->blockchain_node_id = NULL;
    }
    ogs_free(obj);
}

cJSON *OpenAPI_sdm_blockchain_node_id_convertToJSON(OpenAPI_sdm_blockchain_node_id_t *obj)
{
    if (!obj)
        return NULL;
    cJSON *item = cJSON_CreateObject();
    if (obj->blockchain_node_id && cJSON_AddStringToObject(item, "blockchainNodeId", obj->blockchain_node_id) == NULL)
    {
        ogs_error("OpenAPI_sdm_blockchain_node_id_convertToJSON: blockchain_node_id");
        cJSON_Delete(item);
        return NULL;
    }
    return item;
}

OpenAPI_sdm_blockchain_node_id_t *OpenAPI_sdm_blockchain_node_id_parseFromJSON(cJSON *json)
{
    if (!json)
        return NULL;
    cJSON *blockchain_node_id = cJSON_GetObjectItemCaseSensitive(json, "blockchainNodeId");
    if (!blockchain_node_id || !cJSON_IsString(blockchain_node_id))
    {
        ogs_error("OpenAPI_sdm_blockchain_node_id_parseFromJSON: blockchain_node_id missing or invalid");
        return NULL;
    }
    return OpenAPI_sdm_blockchain_node_id_create(blockchain_node_id->valuestring);
}