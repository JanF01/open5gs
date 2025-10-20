#include "sdm_blockchain_credentials_response.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "../include/ogs_assert.h"

OpenAPI_sdm_blockchain_credentials_response_t *OpenAPI_sdm_blockchain_credentials_response_create(OpenAPI_sdm_blockchain_node_id_t *node_id)
{
    OpenAPI_sdm_blockchain_credentials_response_t *obj = ogs_malloc(sizeof(OpenAPI_sdm_blockchain_credentials_response_t));
    ogs_assert(obj);
    obj->node_id = node_id;
    return obj;
}

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

cJSON *OpenAPI_sdm_blockchain_credentials_response_convertToJSON(OpenAPI_sdm_blockchain_credentials_response_t *obj)
{
    if (!obj)
        return NULL;
    cJSON *item = cJSON_CreateObject();
    if (obj->node_id)
    {
        cJSON *node_id_JSON = OpenAPI_sdm_blockchain_node_id_convertToJSON(obj->node_id);
        if (!node_id_JSON)
        {
            ogs_error("OpenAPI_sdm_blockchain_credentials_response_convertToJSON: node_id");
            cJSON_Delete(item);
            return NULL;
        }
        cJSON_AddItemToObject(item, "nodeId", node_id_JSON);
    }
    return item;
}

OpenAPI_sdm_blockchain_credentials_response_t *OpenAPI_sdm_blockchain_credentials_response_parseFromJSON(cJSON *json)
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