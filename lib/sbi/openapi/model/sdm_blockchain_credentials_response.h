#ifndef _OpenAPI_sdm_blockchain_credentials_response_H_
#define _OpenAPI_sdm_blockchain_credentials_response_H_

#include "../external/cJSON.h"
#include "sdm_blockchain_node_id.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct OpenAPI_sdm_blockchain_credentials_response_s OpenAPI_sdm_blockchain_credentials_response_t;
    typedef struct OpenAPI_sdm_blockchain_credentials_response_s
    {
        OpenAPI_sdm_blockchain_node_id_t *node_id;
    } OpenAPI_sdm_blockchain_credentials_response_t;

    OpenAPI_sdm_blockchain_credentials_response_t *OpenAPI_sdm_blockchain_credentials_response_create(OpenAPI_sdm_blockchain_node_id_t *node_id);
    void OpenAPI_sdm_blockchain_credentials_response_free(OpenAPI_sdm_blockchain_credentials_response_t *obj);
    cJSON *OpenAPI_sdm_blockchain_credentials_response_convertToJSON(OpenAPI_sdm_blockchain_credentials_response_t *obj);
    OpenAPI_sdm_blockchain_credentials_response_t *OpenAPI_sdm_blockchain_credentials_response_parseFromJSON(cJSON *json);

#ifdef __cplusplus
}
#endif

#endif