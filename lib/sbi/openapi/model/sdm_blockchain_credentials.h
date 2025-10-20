#ifndef OpenAPI_sdm_blockchain_credentials_H_
#define OpenAPI_sdm_blockchain_credentials_H_

#include <string.h>
#include "../external/cJSON.h"
#include "../include/list.h"
#include "../include/keyValuePair.h"
#include "../include/binary.h"

#include "snssai.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct OpenAPI_sdm_blockchain_credentials_s OpenAPI_sdm_blockchain_credentials_t;
    typedef struct OpenAPI_sdm_blockchain_credentials_s
    {
        char *login;
        char *password;
        OpenAPI_snssai_t *single_nssai;
    } OpenAPI_sdm_blockchain_credentials_t;

    OpenAPI_sdm_blockchain_credentials_t *OpenAPI_sdm_blockchain_credentials_create(
        char *login,
        char *password,
        OpenAPI_snssai_t *single_nssai);

    void OpenAPI_sdm_blockchain_credentials_free(OpenAPI_sdm_blockchain_credentials_t *sdm_blockchain_credentials);

    cJSON *OpenAPI_sdm_blockchain_credentials_convertToJSON(OpenAPI_sdm_blockchain_credentials_t *sdm_blockchain_credentials);

    OpenAPI_sdm_blockchain_credentials_t *OpenAPI_sdm_blockchain_credentials_parseFromJSON(cJSON *sdm_blockchain_credentialsJSON);

#ifdef __cplusplus
}
#endif

#endif /* OpenAPI_sdm_blockchain_credentials_H_ */