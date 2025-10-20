#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include "sdm_blockchain_node_id.h"

// Create
OpenAPI_sdm_blockchain_node_id_t *OpenAPI_sdm_blockchain_node_id_create(char *blockchain_node_id)
{
    OpenAPI_sdm_blockchain_node_id_t *local_var = malloc(sizeof(OpenAPI_sdm_blockchain_node_id_t));
    if (!local_var)
        return NULL;

    local_var->blockchain_node_id = blockchain_node_id ? strdup(blockchain_node_id) : NULL;
    return local_var;
}

// Free
void OpenAPI_sdm_blockchain_node_id_free(OpenAPI_sdm_blockchain_node_id_t *obj)
{
    if (!obj)
        return;
    if (obj->blockchain_node_id)
        free(obj->blockchain_node_id);
    free(obj);
}

// Convert to JSON
cJSON *OpenAPI_sdm_blockchain_node_id_convertToJSON(OpenAPI_sdm_blockchain_node_id_t *obj)
{
    if (!obj)
        return NULL;
    cJSON *item = cJSON_CreateObject();
    if (!item)
        return NULL;

    if (obj->blockchain_node_id)
    {
        if (cJSON_AddStringToObject(item, "blockchainNodeId", obj->blockchain_node_id) == NULL)
        {
            cJSON_Delete(item);
            return NULL;
        }
    }

    return item;
}

// Parse from JSON
OpenAPI_sdm_blockchain_node_id_t *OpenAPI_sdm_blockchain_node_id_parseFromJSON(cJSON *json)
{
    if (!json)
        return NULL;
    cJSON *id_json = cJSON_GetObjectItemCaseSensitive(json, "blockchainNodeId");
    if (!id_json || !cJSON_IsString(id_json))
        return NULL;

    return OpenAPI_sdm_blockchain_node_id_create(strdup(id_json->valuestring));
}

// Copy
OpenAPI_sdm_blockchain_node_id_t *OpenAPI_sdm_blockchain_node_id_copy(OpenAPI_sdm_blockchain_node_id_t *dst, OpenAPI_sdm_blockchain_node_id_t *src)
{
    if (!src)
        return NULL;
    if (!dst)
        return OpenAPI_sdm_blockchain_node_id_create(src->blockchain_node_id);

    if (dst->blockchain_node_id)
        free(dst->blockchain_node_id);
    dst->blockchain_node_id = src->blockchain_node_id ? strdup(src->blockchain_node_id) : NULL;
    return dst;
}