#ifndef _OpenAPI_sdm_blockchain_node_id_H_
#define _OpenAPI_sdm_blockchain_node_id_H_

#include <string.h>
#include "../external/cJSON.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct OpenAPI_sdm_blockchain_node_id_s OpenAPI_sdm_blockchain_node_id_t;
    typedef struct OpenAPI_sdm_blockchain_node_id_s
    {
        char *blockchain_node_id; // 12 characters
    } OpenAPI_sdm_blockchain_node_id_t;

    OpenAPI_sdm_blockchain_node_id_t *OpenAPI_sdm_blockchain_node_id_create(const char *blockchain_node_id);
    void OpenAPI_sdm_blockchain_node_id_free(OpenAPI_sdm_blockchain_node_id_t *obj);
    cJSON *OpenAPI_sdm_blockchain_node_id_convertToJSON(OpenAPI_sdm_blockchain_node_id_t *obj);
    OpenAPI_sdm_blockchain_node_id_t *OpenAPI_sdm_blockchain_node_id_parseFromJSON(cJSON *json);

#ifdef __cplusplus
}
#endif

#endif