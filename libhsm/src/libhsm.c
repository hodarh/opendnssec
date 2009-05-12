/* $Id$ */

/*
 * Copyright (c) 2009 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2009 NLNet Labs.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <cryptoki.h>
#include <pkcs11.h>
#include <string.h>

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/relaxng.h>

#include "libhsm.h"
#include <config.h>

/* we need some globals, for session management, and for the initial
 * context
 */
static hsm_ctx_t *_hsm_ctx;

/* PKCS#11 specific functions */
/*
 * General PKCS11 helper functions
 */
static char *
ldns_pkcs11_rv_str(CK_RV rv)
{
    switch (rv)
        {
        case CKR_OK:
            return "CKR_OK";
        case CKR_CANCEL:
            return "CKR_CANCEL";
        case CKR_HOST_MEMORY:
            return "CKR_HOST_MEMORY";
        case CKR_GENERAL_ERROR:
            return "CKR_GENERAL_ERROR";
        case CKR_FUNCTION_FAILED:
            return "CKR_FUNCTION_FAILED";
        case CKR_SLOT_ID_INVALID:
            return "CKR_SLOT_ID_INVALID";
        case CKR_ATTRIBUTE_READ_ONLY:
            return "CKR_ATTRIBUTE_READ_ONLY";
        case CKR_ATTRIBUTE_SENSITIVE:
            return "CKR_ATTRIBUTE_SENSITIVE";
        case CKR_ATTRIBUTE_TYPE_INVALID:
            return "CKR_ATTRIBUTE_TYPE_INVALID";
        case CKR_ATTRIBUTE_VALUE_INVALID:
            return "CKR_ATTRIBUTE_VALUE_INVALID";
        case CKR_DATA_INVALID:
            return "CKR_DATA_INVALID";
        case CKR_DATA_LEN_RANGE:
            return "CKR_DATA_LEN_RANGE";
        case CKR_DEVICE_ERROR:
            return "CKR_DEVICE_ERROR";
        case CKR_DEVICE_MEMORY:
            return "CKR_DEVICE_MEMORY";
        case CKR_DEVICE_REMOVED:
            return "CKR_DEVICE_REMOVED";
        case CKR_ENCRYPTED_DATA_INVALID:
            return "CKR_ENCRYPTED_DATA_INVALID";
        case CKR_ENCRYPTED_DATA_LEN_RANGE:
            return "CKR_ENCRYPTED_DATA_LEN_RANGE";
        case CKR_FUNCTION_CANCELED:
            return "CKR_FUNCTION_CANCELED";
        case CKR_FUNCTION_NOT_PARALLEL:
            return "CKR_FUNCTION_NOT_PARALLEL";
        case CKR_KEY_HANDLE_INVALID:
            return "CKR_KEY_HANDLE_INVALID";
        case CKR_KEY_SIZE_RANGE:
            return "CKR_KEY_SIZE_RANGE";
        case CKR_KEY_TYPE_INCONSISTENT:
            return "CKR_KEY_TYPE_INCONSISTENT";
        case CKR_MECHANISM_INVALID:
            return "CKR_MECHANISM_INVALID";
        case CKR_MECHANISM_PARAM_INVALID:
            return "CKR_MECHANISM_PARAM_INVALID";
        case CKR_OBJECT_HANDLE_INVALID:
            return "CKR_OBJECT_HANDLE_INVALID";
        case CKR_OPERATION_ACTIVE:
            return "CKR_OPERATION_ACTIVE";
        case CKR_OPERATION_NOT_INITIALIZED:
            return "CKR_OPERATION_NOT_INITIALIZED";
        case CKR_PIN_INCORRECT:
            return "CKR_PIN_INCORRECT";
        case CKR_PIN_INVALID:
            return "CKR_PIN_INVALID";
        case CKR_PIN_LEN_RANGE:
            return "CKR_PIN_LEN_RANGE";
        case CKR_SESSION_CLOSED:
            return "CKR_SESSION_CLOSED";
        case CKR_SESSION_COUNT:
            return "CKR_SESSION_COUNT";
        case CKR_SESSION_HANDLE_INVALID:
            return "CKR_SESSION_HANDLE_INVALID";
        case CKR_SESSION_PARALLEL_NOT_SUPPORTED:
            return "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
        case CKR_SESSION_READ_ONLY:
            return "CKR_SESSION_READ_ONLY";
        case CKR_SESSION_EXISTS:
            return "CKR_SESSION_EXISTS";
        case CKR_SIGNATURE_INVALID:
            return "CKR_SIGNATURE_INVALID";
        case CKR_SIGNATURE_LEN_RANGE:
            return "CKR_SIGNATURE_LEN_RANGE";
        case CKR_TEMPLATE_INCOMPLETE:
            return "CKR_TEMPLATE_INCOMPLETE";
        case CKR_TEMPLATE_INCONSISTENT:
            return "CKR_TEMPLATE_INCONSISTENT";
        case CKR_TOKEN_NOT_PRESENT:
            return "CKR_TOKEN_NOT_PRESENT";
        case CKR_TOKEN_NOT_RECOGNIZED:
            return "CKR_TOKEN_NOT_RECOGNIZED";
        case CKR_TOKEN_WRITE_PROTECTED:
            return "CKR_TOKEN_WRITE_PROTECTED";
        case CKR_UNWRAPPING_KEY_HANDLE_INVALID:
            return "CKR_UNWRAPPING_KEY_HANDLE_INVALID";
        case CKR_UNWRAPPING_KEY_SIZE_RANGE:
            return "CKR_UNWRAPPING_KEY_SIZE_RANGE";
        case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT:
            return "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
        case CKR_USER_ALREADY_LOGGED_IN:
            return "CKR_USER_ALREADY_LOGGED_IN";
        case CKR_USER_NOT_LOGGED_IN:
            return "CKR_USER_NOT_LOGGED_IN";
        case CKR_USER_PIN_NOT_INITIALIZED:
            return "CKR_USER_PIN_NOT_INITIALIZED";
        case CKR_USER_TYPE_INVALID:
            return "CKR_USER_TYPE_INVALID";
        case CKR_WRAPPED_KEY_INVALID:
            return "CKR_WRAPPED_KEY_INVALID";
        case CKR_WRAPPED_KEY_LEN_RANGE:
            return "CKR_WRAPPED_KEY_LEN_RANGE";
        case CKR_WRAPPING_KEY_HANDLE_INVALID:
            return "CKR_WRAPPING_KEY_HANDLE_INVALID";
        case CKR_WRAPPING_KEY_SIZE_RANGE:
            return "CKR_WRAPPING_KEY_SIZE_RANGE";
        case CKR_WRAPPING_KEY_TYPE_INCONSISTENT:
            return "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
        case CKR_RANDOM_SEED_NOT_SUPPORTED:
            return "CKR_RANDOM_SEED_NOT_SUPPORTED";
        case CKR_VENDOR_DEFINED:
            return "CKR_VENDOR_DEFINED";
        case CKR_BUFFER_TOO_SMALL:
            return "CKR_BUFFER_TOO_SMALL";
        case CKR_SAVED_STATE_INVALID:
            return "CKR_SAVED_STATE_INVALID";
        case CKR_INFORMATION_SENSITIVE:
            return "CKR_INFORMATION_SENSITIVE";
        case CKR_STATE_UNSAVEABLE:
            return "CKR_STATE_UNSAVEABLE";
        case CKR_CRYPTOKI_NOT_INITIALIZED:
            return "CKR_CRYPTOKI_NOT_INITIALIZED";
        case CKR_CRYPTOKI_ALREADY_INITIALIZED:
            return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
        case CKR_MUTEX_BAD:
            return "CKR_MUTEX_BAD";
        case CKR_MUTEX_NOT_LOCKED:
            return "CKR_MUTEX_NOT_LOCKED";
        default:
            return "Unknown error";
        }
}

static void
hsm_pkcs11_check_rv(CK_RV rv, const char *message)
{
    if (rv != CKR_OK) {
        fprintf(stderr,
                "Error in %s: %s (%d)\n",
                message,
                ldns_pkcs11_rv_str(rv),
                (int) rv);
        exit(EXIT_FAILURE);
    }
}

static void
hsm_pkcs11_unload_functions(void *handle)
{
    int result;
    if (handle) {
#if defined(HAVE_LOADLIBRARY)
        // no idea
#elif defined(HAVE_DLOPEN)
        result = dlclose(handle);
#endif
    }
}

static CK_RV
hsm_pkcs11_load_functions(hsm_module_t *module)
{
    CK_C_GetFunctionList pGetFunctionList = NULL;
                          
    if (module && module->path) {
        /* library provided by application or user */
#if defined(HAVE_LOADLIBRARY)
fprintf(stderr, "have loadlibrary\n");
        /* Load PKCS #11 library */
        HINSTANCE hDLL = LoadLibrary(_T(module->path));

        if (hDLL == NULL)
        {
            /* Failed to load the PKCS #11 library */
            return CKR_FUNCTION_FAILED;
        }

        /* Retrieve the entry point for C_GetFunctionList */
        pGetFunctionList = (CK_C_GetFunctionList)
            GetProcAddress(hDLL, _T("C_GetFunctionList"));
#elif defined(HAVE_DLOPEN)
        /* Load PKCS #11 library */
        void* pDynLib = dlopen(module->path, RTLD_LAZY);

        if (pDynLib == NULL)
        {
            /* Failed to load the PKCS #11 library */
            fprintf(stderr, "dlopen() failed: %s\n", dlerror());
            return CKR_FUNCTION_FAILED;
        }

        /* Retrieve the entry point for C_GetFunctionList */
        pGetFunctionList = (CK_C_GetFunctionList) dlsym(pDynLib, "C_GetFunctionList");
        /* Store the handle so we can dlclose it later */
        module->handle = pDynLib;
#else
        fprintf(stderr, "dl given, no dynamic library support compiled in\n");
#endif
    } else {
        /* no library provided, use the statically compiled softHSM */
#ifdef HAVE_PKCS11_MODULE
fprintf(stderr, "have pkcs11_module\n");
        return C_GetFunctionList(pkcs11_functions);
#else 
        fprintf(stderr, "Error, no pkcs11 module given, none compiled in\n");
#endif
    }

    if (pGetFunctionList == NULL)
    {
        fprintf(stderr, "no function list\n");
        /* Failed to load the PKCS #11 library */
        return CKR_FUNCTION_FAILED;
    }

    /* Retrieve the function list */
    (pGetFunctionList)(&module->sym);
    return CKR_OK;
}

static int
hsm_pkcs11_check_token_name(CK_FUNCTION_LIST_PTR pkcs11_functions,
                             CK_SLOT_ID slotId,
                             const char *token_name)
{
    /* token label is always 32 bytes */
    char *token_name_bytes = malloc(32);
    int result = 0;
    CK_RV rv;
    CK_TOKEN_INFO token_info;
    
    rv = pkcs11_functions->C_GetTokenInfo(slotId, &token_info);
    hsm_pkcs11_check_rv(rv, "C_GetTokenInfo");
    
    memset(token_name_bytes, ' ', 32);
    memcpy(token_name_bytes, token_name, strlen(token_name));
    
    result = memcmp(token_info.label, token_name_bytes, 32) == 0;
    
    free(token_name_bytes);
    return result;
}


static CK_SLOT_ID
ldns_hsm_get_slot_id(CK_FUNCTION_LIST_PTR pkcs11_functions,
                     const char *token_name)
{
    CK_RV rv;
    CK_SLOT_ID slotId = 0;
    CK_ULONG slotCount = 10;
    CK_SLOT_ID cur_slot;
    CK_SLOT_ID *slotIds = malloc(sizeof(CK_SLOT_ID) * slotCount);
    int found = 0;
    
    rv = pkcs11_functions->C_GetSlotList(CK_TRUE, slotIds, &slotCount);
    hsm_pkcs11_check_rv(rv, "get slot list");

    if (slotCount < 1) {
        fprintf(stderr, "Error; could not find token with the name %s\n", token_name);
        exit(1);
    }

    for (cur_slot = 0; cur_slot < slotCount; cur_slot++) {
        if (hsm_pkcs11_check_token_name(pkcs11_functions,
                                         slotIds[cur_slot],
                                         token_name)) {
            slotId = slotIds[cur_slot];
            found = 1;
            break;
        }
    }
    free(slotIds);
    if (!found) {
        fprintf(stderr, "Error; could not find token with the name %s\n", token_name);
        exit(1);
    }

    return slotId;
}

/* internal functions */
static hsm_module_t *
hsm_module_new(const char *name, const char *path)
{
    size_t strl;
    hsm_module_t *module;
    module = malloc(sizeof(hsm_module_t));
    module->id = 0; /*TODO what should this value be?*/
    strl = strlen(name) + 1;
    module->name = strdup(name);
    module->path = strdup(path);
    module->handle = NULL;
    module->sym = NULL;
    return module;
}

static void
hsm_module_free(hsm_module_t *module)
{
    if (module) {
        if (module->name) free(module->name);
        if (module->path) free(module->path);
        
        free(module);
    }
}

static hsm_session_t *
hsm_session_new(hsm_module_t *module, CK_SESSION_HANDLE session_handle)
{
    hsm_session_t *session;
    session = malloc(sizeof(hsm_session_t));
    session->module = module;
    session->session = session_handle;
    return session;
}

static void
hsm_session_free(hsm_session_t *session) {
    if (session) {
        free(session);
    }
}

/* creates a session_t srtucture, and automatically adds and initializes
 * a module_t struct for it
 */
hsm_session_t *
hsm_session_init(char *module_name, char *module_path, char *pin)
{
    CK_RV rv;
    hsm_module_t *module;
    CK_SLOT_ID slot_id;
    CK_SESSION_HANDLE session_handle;
    hsm_session_t *session;

    module = hsm_module_new(module_name, module_path);
    rv = hsm_pkcs11_load_functions(module);
    hsm_pkcs11_check_rv(rv, "Load functions");
    rv = module->sym->C_Initialize(NULL);
    hsm_pkcs11_check_rv(rv, "Initialization");
    slot_id = ldns_hsm_get_slot_id(module->sym, module_name);
    rv = module->sym->C_OpenSession(slot_id,
                               CKF_SERIAL_SESSION,
                               NULL,
                               NULL,
                               &session_handle);
    hsm_pkcs11_check_rv(rv, "Open first session");
    rv = module->sym->C_Login(session_handle,
                                   CKU_USER,
                                   (unsigned char *) pin,
                                   strlen((char *)pin));
    hsm_pkcs11_check_rv(rv, "log in");
    session = hsm_session_new(module, session_handle);

    return session;
}

/* open a second session from the given one */
hsm_session_t *
hsm_session_clone(hsm_session_t *session)
{
    CK_RV rv;
    CK_SLOT_ID slot_id;
    CK_SESSION_HANDLE session_handle;
    hsm_session_t *new_session;
    
    slot_id = ldns_hsm_get_slot_id(session->module->sym,
                                   session->module->name);
    rv = session->module->sym->C_OpenSession(slot_id,
                                    CKF_SERIAL_SESSION,
                                    NULL,
                                    NULL,
                                    &session_handle);
    
    hsm_pkcs11_check_rv(rv, "Open first session");
    new_session = hsm_session_new(session->module, session_handle);

    return new_session;
    
}

static hsm_ctx_t *
hsm_ctx_new()
{
    hsm_ctx_t *ctx;
    ctx = malloc(sizeof(hsm_ctx_t));
    memset(ctx->session, 0, HSM_MAX_SESSIONS);
    ctx->session_count = 0;
    return ctx;
}



/* ctx_free frees the structure */
static void
hsm_ctx_free(hsm_ctx_t *ctx)
{
    unsigned int i;
    if (ctx) {
        if (ctx->session) {
            for (i = 0; i < ctx->session_count; i++) {
                hsm_session_free(ctx->session[i]);
            }
        }
        free(ctx);
    }
}

/* close the session, and free the allocated data
 * 
 * if unload is non-zero, the dlopen()d module is closed and unloaded
 * (only call this on the last session for each module, ie. the one
 * in the global ctx)
 */
void
hsm_session_close(hsm_session_t *session, int unload)
{
    CK_RV rv;
    rv = session->module->sym->C_CloseSession(session->session);
    hsm_pkcs11_check_rv(rv, "Close session");
    if (unload) {
        rv = session->module->sym->C_Finalize(NULL);
        hsm_pkcs11_check_rv(rv, "Finalize");
        hsm_pkcs11_unload_functions(session->module->handle);
        hsm_module_free(session->module);
        session->module = NULL;
    }
    hsm_session_free(session);
}

/* ctx_close closes all session, and free
 * the structures. 
 * 
 * if unload is non-zero, the associated dynamic libraries are unloaded
 * (hence only use that on the last, global, ctx)
 */
static void
hsm_ctx_close(hsm_ctx_t *ctx, int unload)
{
    unsigned int i;

    if (ctx) {
        for (i = 0; i < ctx->session_count; i++) {
            printf("close session %u (unload: %d)\n", i, unload);
            hsm_print_ctx(ctx);
            hsm_session_close(ctx->session[i], unload);
            ctx->session[i] = NULL;
            if (i == _hsm_ctx->session_count) {
                while(i > 0 && !ctx->session[i]) {
                    i--;
                }
            }
        }
        free(ctx);
    }
}


/* adds a session to the context.
 * returns  0 on succes
 *          1 if one of the arguments is NULL
 *         -1 if the maximum number of sessions (HSM_MAX_SESSIONS) was
 *            reached
 */
static int
hsm_ctx_add_session(hsm_ctx_t *ctx, hsm_session_t *session)
{
    if (!ctx || !session) return -1;
    if (ctx->session_count >= HSM_MAX_SESSIONS) return 1;
    ctx->session[ctx->session_count] = session;
    fprintf(stderr, "added session %u\n", ctx->session_count);
    ctx->session_count++;
    return 0;
}

hsm_ctx_t *
hsm_ctx_clone(hsm_ctx_t *ctx)
{
    unsigned int i;
    hsm_ctx_t *new_ctx;
    hsm_session_t *new_session;

    new_ctx = NULL;
    if (ctx) {
        new_ctx = hsm_ctx_new();
        for (i = 0; i < ctx->session_count; i++) {
            new_session = hsm_session_clone(ctx->session[i]);
            hsm_ctx_add_session(new_ctx, new_session);
        }
    }
    return new_ctx;
}

hsm_key_t *
hsm_key_new()
{
    hsm_key_t *key;
    key = malloc(sizeof(hsm_key_t));
    key->module = NULL;
    key->private_key = 0;
    key->public_key = 0;
    key->uuid = NULL;
    return key;
}

/* frees the data for the key structure. If uuid is not NULL
 * the data at the uuid pointer is freed as well */
void
hsm_key_free(hsm_key_t *key)
{
    if (key) {
        if (key->uuid) free(key->uuid);
        free(key);
    }
}

/* external functions */
int
hsm_open(const char *config,
         char *(pin_callback)(char *token_name, void *), void *data)
{
    xmlDocPtr doc;
    xmlXPathContextPtr xpath_ctx;
    xmlXPathObjectPtr xpath_obj;
    xmlNode *curNode;
    xmlChar *xexpr;

    int i;
    char *module_name;
    char *module_path;
    char *module_pin;
    hsm_session_t *session;

    /* create an internal context with an attached session for each
     * configured HSM. */
    fprintf(stderr,"creating global ctx\n");
    _hsm_ctx = hsm_ctx_new();
    
    /* Load XML document */
    fprintf(stdout, "Opening %s\n", config);
    doc = xmlParseFile(config);
    if (doc == NULL) {
        fprintf(stderr, "Error: unable to parse file \"%s\"\n", config);
        return -1;
    }

    /* Create xpath evaluation context */
    xpath_ctx = xmlXPathNewContext(doc);
    if(xpath_ctx == NULL) {
        fprintf(stderr,"Error: unable to create new XPath context\n");
        xmlFreeDoc(doc);
        hsm_ctx_free(_hsm_ctx);
        _hsm_ctx = NULL;
        return -1;
    }

    /* Evaluate xpath expression */
    xexpr = (xmlChar *)"//Configuration/RepositoryList/Repository";
    xpath_obj = xmlXPathEvalExpression(xexpr, xpath_ctx);
    if(xpath_obj == NULL) {
        fprintf(stderr,"Error: unable to evaluate xpath expression\n");
        xmlXPathFreeContext(xpath_ctx);
        xmlFreeDoc(doc);
        hsm_ctx_free(_hsm_ctx);
        _hsm_ctx = NULL;
        return -1;
    }
    
    if (xpath_obj->nodesetval) {
        fprintf(stderr, "%u nodes\n", xpath_obj->nodesetval->nodeNr);
        for (i = 0; i < xpath_obj->nodesetval->nodeNr; i++) {
            /*module = hsm_module_new();*/
            module_name = NULL;
            module_path = NULL;
            module_pin = NULL;
            curNode = xpath_obj->nodesetval->nodeTab[i]->xmlChildrenNode;
            while (curNode) {
                if (xmlStrEqual(curNode->name, (const xmlChar *)"Name"))
                    module_name = (char *) xmlNodeGetContent(curNode);
                if (xmlStrEqual(curNode->name, (const xmlChar *)"Module"))
                    module_path = (char *) xmlNodeGetContent(curNode);
                if (xmlStrEqual(curNode->name, (const xmlChar *)"PIN"))
                    module_pin = (char *) xmlNodeGetContent(curNode);
                curNode = curNode->next;
            }
            if (module_name && module_path) {
                if (module_pin || pin_callback) {
                    if (!module_pin) {
                        module_pin = pin_callback(module_name, data);
                    }
                    session = hsm_session_init(module_name, module_path, "1111");
                    hsm_ctx_add_session(_hsm_ctx, session);
                    fprintf(stdout, "module added\n");
                    /* ok we have a module, start a session */
                }
                free(module_name);
                free(module_path);
                free(module_pin);
            }
        }
    }

    xmlXPathFreeObject(xpath_obj);
    xmlXPathFreeContext(xpath_ctx);
    xmlFreeDoc(doc);
    xmlCleanupParser();
    return 0;
}

int
hsm_close()
{
    hsm_ctx_close(_hsm_ctx, 1);
    return 0;
}

hsm_ctx_t *
hsm_create_context()
{
    return hsm_ctx_clone(_hsm_ctx);
}

void
hsm_destroy_context(hsm_ctx_t *ctx)
{
    hsm_ctx_close(ctx, 0);
}

void
hsm_print_session(hsm_session_t *session)
{
    printf("\t\tmodule at %p (sym %p)\n", (void *) session->module, (void *) session->module->sym);
    printf("\t\tsess handle: %u\n", (unsigned int) session->session);
}

void
hsm_print_ctx(hsm_ctx_t *gctx) {
    hsm_ctx_t *ctx;
    unsigned int i;
    if (!gctx) {
        ctx = _hsm_ctx;
    } else {
        ctx = gctx;
    }
    printf("CTX Sessions: %u\n", ctx->session_count);
    for (i = 0; i < ctx->session_count; i++) {
        printf("\tSession at %p\n", (void *) ctx->session[i]);
        hsm_print_session(ctx->session[i]);
    }
}

CK_OBJECT_HANDLE
hsm_find_object_handle_for_uuid(const hsm_session_t *session, CK_OBJECT_CLASS key_class, uuid_t *uuid)
{
    CK_ULONG objectCount;
    CK_OBJECT_HANDLE object;
    CK_RV rv;
    
    CK_ATTRIBUTE template[] = {
        { CKA_CLASS, &key_class, sizeof(key_class) },
        { CKA_ID, uuid, sizeof(uuid_t) },
    };
    
    rv = session->module->sym->C_FindObjectsInit(session->session, template, 1);
    hsm_pkcs11_check_rv(rv, "Find objects init");
    
    rv = session->module->sym->C_FindObjects(session->session,
                                         &object,
                                         1,
                                         &objectCount);
    hsm_pkcs11_check_rv(rv, "Find object");

	rv = session->module->sym->C_FindObjectsFinal(session->session);
    hsm_pkcs11_check_rv(rv, "Find object final");
	if (objectCount > 0) {
		hsm_pkcs11_check_rv(rv, "Find objects final");
		return object;
	} else {
		return 0;
	}
}

hsm_key_t *
hsm_key_new_privkey_object_handle(const hsm_session_t *session, CK_OBJECT_HANDLE object)
{
    hsm_key_t *key;
    CK_RV rv;
    uuid_t *uuid = NULL;
    
	CK_ATTRIBUTE template[] = {
		{CKA_ID, uuid, sizeof(uuid_t)}
    };

    template[0].pValue = malloc(sizeof(uuid_t));
	rv = session->module->sym->C_GetAttributeValue(
	                                  session->session,
	                                  object,
	                                  template,
	                                  1);
	hsm_pkcs11_check_rv(rv, "Get attr value\n");
    key = hsm_key_new();
    key->uuid = template[0].pValue;
    key->module = session->module;
    key->private_key = object;
    key->public_key = hsm_find_object_handle_for_uuid(session, CKO_PUBLIC_KEY, key->uuid);
    
    return key;
}

hsm_key_t **
hsm_list_keys_session(const hsm_session_t *session, size_t *count)
{
    hsm_key_t **keys;
    hsm_key_t *key;
    CK_RV rv;
    CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE template[] = {
        { CKA_CLASS, &key_class, sizeof(key_class) },
    };
    CK_ULONG total_count = 0;
    CK_ULONG objectCount;
    CK_ULONG max_object_count = 100;
    CK_ULONG i;
    CK_OBJECT_HANDLE object[max_object_count];

    rv = session->module->sym->C_FindObjectsInit(session->session, template, 1);
    hsm_pkcs11_check_rv(rv, "Find objects init");
    
    rv = session->module->sym->C_FindObjects(session->session,
                                         object,
                                         max_object_count,
                                         &objectCount);
    hsm_pkcs11_check_rv(rv, "Find first object");
    rv = session->module->sym->C_FindObjectsFinal(session->session);

    printf("objectCount: %u\n", (unsigned int) objectCount);
    keys = malloc(objectCount * sizeof(hsm_key_t *));
    for (i = 0; i < objectCount; i++) {
        key = hsm_key_new_privkey_object_handle(session, object[i]);
        keys[i] = key;
    }
    total_count += objectCount;

    hsm_pkcs11_check_rv(rv, "Find objects final");

    *count = total_count;
    return keys;
}

hsm_key_t **
hsm_list_keys(const hsm_ctx_t *ctx, size_t *count)
{
    hsm_key_t **keys = NULL;
    size_t key_count = 0;
    size_t cur_key_count;
    hsm_key_t **session_keys;
    unsigned int i, j;
    
    if (!ctx) {
        ctx = _hsm_ctx;
    }
    
    printf("Finding keys in %u sessions\n", ctx->session_count);
    for (i = 0; i < ctx->session_count; i++) {
        printf("Finding keys for session %u\n", i);
        session_keys = hsm_list_keys_session(ctx->session[i], &cur_key_count);
        fprintf(stderr, "Adding %u keys from session number %u\n", (unsigned int) cur_key_count, i);
        keys = realloc(keys, key_count + cur_key_count * sizeof(hsm_key_t *));
        for (j = 0; j < cur_key_count; j++) {
            keys[key_count + j] = session_keys[j];
        }
        key_count += cur_key_count;
        free(session_keys);
    }
    if (count) {
        *count = key_count;
    }
    return keys;
}

void
hsm_print_key(hsm_key_t *key) {
    char uuid_str[37];
    if (key) {
        uuid_unparse(*key->uuid, uuid_str);
        printf("key:\n");
        printf("\tmodule %p\n", (void *) key->module);
        printf("\tprivkey handle %u\n", (unsigned int) key->private_key);
        printf("\tpubkey handle  %u\n", (unsigned int) key->public_key);
        printf("\tid %s\n", uuid_str);
    } else {
        printf("key: <void>\n");
    }
}
