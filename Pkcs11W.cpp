
#include "Pkcs11W.h"

const char* Pkcs11W::strRv()
{
   switch (rc) {
      case CKR_OK:                               return(" CKR_OK");                               break;
      case CKR_CANCEL:                           return(" CKR_CANCEL");                           break;
      case CKR_HOST_MEMORY:                      return(" CKR_HOST_MEMORY");                      break;
      case CKR_SLOT_ID_INVALID:                  return(" CKR_SLOT_ID_INVALID");                  break;
      case CKR_GENERAL_ERROR:                    return(" CKR_GENERAL_ERROR");                    break;
      case CKR_FUNCTION_FAILED:                  return(" CKR_FUNCTION_FAILED");                  break;
      case CKR_ARGUMENTS_BAD:                    return(" CKR_ARGUMENTS_BAD");                    break;
      case CKR_NO_EVENT:                         return(" CKR_NO_EVENT");                         break;
      case CKR_NEED_TO_CREATE_THREADS:           return(" CKR_NEED_TO_CREATE_THREADS");           break;
      case CKR_CANT_LOCK:                        return(" CKR_CANT_LOCK");                        break;
      case CKR_ATTRIBUTE_READ_ONLY:              return(" CKR_ATTRIBUTE_READ_ONLY");              break;
      case CKR_ATTRIBUTE_SENSITIVE:              return(" CKR_ATTRIBUTE_SENSITIVE");              break;
      case CKR_ATTRIBUTE_TYPE_INVALID:           return(" CKR_ATTRIBUTE_TYPE_INVALID");           break;
      case CKR_ATTRIBUTE_VALUE_INVALID:          return(" CKR_ATTRIBUTE_VALUE_INVALID");          break;
      case CKR_DATA_INVALID:                     return(" CKR_DATA_INVALID");                     break;
      case CKR_DATA_LEN_RANGE:                   return(" CKR_DATA_LEN_RANGE");                   break;
      case CKR_DEVICE_ERROR:                     return(" CKR_DEVICE_ERROR");                     break;
      case CKR_DEVICE_MEMORY:                    return(" CKR_DEVICE_MEMORY");                    break;
      case CKR_DEVICE_REMOVED:                   return(" CKR_DEVICE_REMOVED");                   break;
      case CKR_ENCRYPTED_DATA_INVALID:           return(" CKR_ENCRYPTED_DATA_INVALID");           break;
      case CKR_ENCRYPTED_DATA_LEN_RANGE:         return(" CKR_ENCRYPTED_DATA_LEN_RANGE");         break;
      case CKR_FUNCTION_CANCELED:                return(" CKR_FUNCTION_CANCELED");                break;
      case CKR_FUNCTION_NOT_PARALLEL:            return(" CKR_FUNCTION_NOT_PARALLEL");            break;
      case CKR_FUNCTION_NOT_SUPPORTED:           return(" CKR_FUNCTION_NOT_SUPPORTED");           break;
      case CKR_KEY_HANDLE_INVALID:               return(" CKR_KEY_HANDLE_INVALID");               break;
      case CKR_KEY_SIZE_RANGE:                   return(" CKR_KEY_SIZE_RANGE");                   break;
      case CKR_KEY_TYPE_INCONSISTENT:            return(" CKR_KEY_TYPE_INCONSISTENT");            break;
      case CKR_KEY_NOT_NEEDED:                   return(" CKR_KEY_NOT_NEEDED");                   break;
      case CKR_KEY_CHANGED:                      return(" CKR_KEY_CHANGED");                      break;
      case CKR_KEY_NEEDED:                       return(" CKR_KEY_NEEDED");                       break;
      case CKR_KEY_INDIGESTIBLE:                 return(" CKR_KEY_INDIGESTIBLE");                 break;
      case CKR_KEY_FUNCTION_NOT_PERMITTED:       return(" CKR_KEY_FUNCTION_NOT_PERMITTED");       break;
      case CKR_KEY_NOT_WRAPPABLE:                return(" CKR_KEY_NOT_WRAPPABLE");                break;
      case CKR_KEY_UNEXTRACTABLE:                return(" CKR_KEY_UNEXTRACTABLE");                break;
      case CKR_MECHANISM_INVALID:                return(" CKR_MECHANISM_INVALID");                break;
      case CKR_MECHANISM_PARAM_INVALID:          return(" CKR_MECHANISM_PARAM_INVALID");          break;
      case CKR_OBJECT_HANDLE_INVALID:            return(" CKR_OBJECT_HANDLE_INVALID");            break;
      case CKR_OPERATION_ACTIVE:                 return(" CKR_OPERATION_ACTIVE");                 break;
      case CKR_OPERATION_NOT_INITIALIZED:        return(" CKR_OPERATION_NOT_INITIALIZED");        break;
      case CKR_PIN_INCORRECT:                    return(" CKR_PIN_INCORRECT");                    break;
      case CKR_PIN_INVALID:                      return(" CKR_PIN_INVALID");                      break;
      case CKR_PIN_LEN_RANGE:                    return(" CKR_PIN_LEN_RANGE");                    break;
      case CKR_PIN_EXPIRED:                      return(" CKR_PIN_EXPIRED");                      break;
      case CKR_PIN_LOCKED:                       return(" CKR_PIN_LOCKED");                       break;
      case CKR_SESSION_CLOSED:                   return(" CKR_SESSION_CLOSED");                   break;
      case CKR_SESSION_COUNT:                    return(" CKR_SESSION_COUNT");                    break;
      case CKR_SESSION_HANDLE_INVALID:           return(" CKR_SESSION_HANDLE_INVALID");           break;
      case CKR_SESSION_PARALLEL_NOT_SUPPORTED:   return(" CKR_SESSION_PARALLEL_NOT_SUPPORTED");   break;
      case CKR_SESSION_READ_ONLY:                return(" CKR_SESSION_READ_ONLY");                break;
      case CKR_SESSION_EXISTS:                   return(" CKR_SESSION_EXISTS");                   break;
      case CKR_SESSION_READ_ONLY_EXISTS:         return(" CKR_SESSION_READ_ONLY_EXISTS");         break;
      case CKR_SESSION_READ_WRITE_SO_EXISTS:     return(" CKR_SESSION_READ_WRITE_SO_EXISTS");     break;
      case CKR_SIGNATURE_INVALID:                return(" CKR_SIGNATURE_INVALID");                break;
      case CKR_SIGNATURE_LEN_RANGE:              return(" CKR_SIGNATURE_LEN_RANGE");              break;
      case CKR_TEMPLATE_INCOMPLETE:              return(" CKR_TEMPLATE_INCOMPLETE");              break;
      case CKR_TEMPLATE_INCONSISTENT:            return(" CKR_TEMPLATE_INCONSISTENT");            break;
      case CKR_TOKEN_NOT_PRESENT:                
           return(" CKR_TOKEN_NOT_PRESENT - ICSF is not active or not configured for TKDS operations"); break;
      case CKR_TOKEN_NOT_RECOGNIZED:             
           return(" CKR_TOKEN_NOT_RECOGNIZED - You are not authorized to perform the token operation"); break;
      case CKR_TOKEN_WRITE_PROTECTED:            return(" CKR_TOKEN_WRITE_PROTECTED");            break;
      case CKR_UNWRAPPING_KEY_HANDLE_INVALID:    return(" CKR_UNWRAPPING_KEY_HANDLE_INVALID");    break;
      case CKR_UNWRAPPING_KEY_SIZE_RANGE:        return(" CKR_UNWRAPPING_KEY_SIZE_RANGE");        break;
      case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT: return(" CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT"); break;
      case CKR_USER_ALREADY_LOGGED_IN:           return(" CKR_USER_ALREADY_LOGGED_IN");           break;
      case CKR_USER_NOT_LOGGED_IN:               return(" CKR_USER_NOT_LOGGED_IN");               break;
      case CKR_USER_PIN_NOT_INITIALIZED:         return(" CKR_USER_PIN_NOT_INITIALIZED");         break;
      case CKR_USER_TYPE_INVALID:                return(" CKR_USER_TYPE_INVALID");                break;
      case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:   return(" CKR_USER_ANOTHER_ALREADY_LOGGED_IN");   break;
      case CKR_USER_TOO_MANY_TYPES:              return(" CKR_USER_TOO_MANY_TYPES");              break;
      case CKR_WRAPPED_KEY_INVALID:              return(" CKR_WRAPPED_KEY_INVALID");              break;
      case CKR_WRAPPED_KEY_LEN_RANGE:            return(" CKR_WRAPPED_KEY_LEN_RANGE");            break;
      case CKR_WRAPPING_KEY_HANDLE_INVALID:      return(" CKR_WRAPPING_KEY_HANDLE_INVALID");      break;
      case CKR_WRAPPING_KEY_SIZE_RANGE:          return(" CKR_WRAPPING_KEY_SIZE_RANGE");          break;
      case CKR_WRAPPING_KEY_TYPE_INCONSISTENT:   return(" CKR_WRAPPING_KEY_TYPE_INCONSISTENT");   break;
      case CKR_RANDOM_SEED_NOT_SUPPORTED:        return(" CKR_RANDOM_SEED_NOT_SUPPORTED");        break;
      case CKR_RANDOM_NO_RNG:                    return(" CKR_RANDOM_NO_RNG");                    break;
      case CKR_BUFFER_TOO_SMALL:                 return(" CKR_BUFFER_TOO_SMALL");                 break;
      case CKR_SAVED_STATE_INVALID:              return(" CKR_SAVED_STATE_INVALID");              break;
      case CKR_INFORMATION_SENSITIVE:            return(" CKR_INFORMATION_SENSITIVE");            break;
      case CKR_STATE_UNSAVEABLE:                 return(" CKR_STATE_UNSAVEABLE");                 break;
      case CKR_CRYPTOKI_NOT_INITIALIZED:         return(" CKR_CRYPTOKI_NOT_INITIALIZED");         break;
      case CKR_CRYPTOKI_ALREADY_INITIALIZED:     return(" CKR_CRYPTOKI_ALREADY_INITIALIZED");     break;
      case CKR_MUTEX_BAD:                        return(" CKR_MUTEX_BAD");                        break;
      case CKR_MUTEX_NOT_LOCKED:                 return(" CKR_MUTEX_NOT_LOCKED");                 break;
      default:
						return(" UNKNOWN_RETURN_CODE");  
   }
}

Pkcs11W::Pkcs11W()
{
	functions = NULL_PTR;
	pInfo = NULL_PTR;
	pSlotList = NULL_PTR;
	pSlotInfo = NULL_PTR;
	pTokenInfo = NULL_PTR;
	pMechanismList = NULL_PTR;
	pMechanismInfo = NULL_PTR;
	pSession = NULL_PTR;
	pSessionInfo = NULL_PTR;
	loaded = false;
}

Pkcs11W::Pkcs11W(const char* lib_location)
{
	functions = NULL_PTR;
	pInfo = NULL_PTR;
	pSlotList = NULL_PTR;
	pSlotInfo = NULL_PTR;
	pTokenInfo = NULL_PTR;
	pMechanismList = NULL_PTR;
	pMechanismInfo = NULL_PTR;
	pSession = NULL_PTR;
	pSessionInfo = NULL_PTR;
	load(lib_location);
}

Pkcs11W::~Pkcs11W()
{
	delete [] pSlotList;
	delete pInfo;
	delete pSlotInfo;
	delete pTokenInfo;
	delete [] pMechanismList;
	delete pMechanismInfo;
	delete pSession;
	delete pSessionInfo;
}

bool Pkcs11W::load(const char* lib_location, int rtld)
{
	lib_handle = dlopen(lib_location, rtld);
	if (!lib_handle)
		return false;
	loaded = true;
	CK_FUNCTION_LIST_PTR ptr = GetFunctionList();
	if (ptr == NULL) return false;
	return true;
}

bool Pkcs11W::unload()
{
	int result = dlclose(lib_handle);
	if (result != 0) return false;
	loaded = false;
	return true;
}

char* Pkcs11W::loadError()
{
	return dlerror();
}	

CK_RV Pkcs11W::returnValue()
{
	return rv();
}

CK_RV Pkcs11W::rv()
{
	return rc;
}

CK_RV Pkcs11W::Initialize(CK_VOID_PTR p_init_args)
{
	rc = functions->C_Initialize( p_init_args );
	return rc;
}

CK_RV Pkcs11W::Finalize(CK_VOID_PTR p_reserved)
{
	rc = functions->C_Finalize( p_reserved );
	return rc;
}

CK_FUNCTION_LIST_PTR Pkcs11W::GetFunctionList()
{
	if (functions!=NULL_PTR)
		return functions;
	void* ptr = dlsym(lib_handle, "C_GetFunctionList");
	if (ptr == NULL) return NULL_PTR;
	CK_RV  (*pFunc)(CK_FUNCTION_LIST_PTR_PTR);
	pFunc = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR)) ptr;
	CK_FUNCTION_LIST_PTR_PTR  funcs_ptr = &functions;
	rc = pFunc(funcs_ptr);
	if (rc != CKR_OK) 
	{
		return NULL_PTR;
	}
	return functions;
}	

CK_INFO_PTR Pkcs11W::GetInfo()
{
	if (pInfo == NULL_PTR) pInfo = new CK_INFO();
	rc = functions->C_GetInfo(pInfo);
	return pInfo;
}

CK_ULONG Pkcs11W::GetNumSlots(CK_BBOOL only_slots_with_token)
{
	CK_ULONG num_slots = 0;
	rc = functions->C_GetSlotList(only_slots_with_token, NULL_PTR, &num_slots);
	return num_slots;
}

CK_SLOT_ID_PTR Pkcs11W::GetSlotList(CK_BBOOL only_slots_with_token)
{
	delete [] pSlotList;
	pSlotList = NULL_PTR;
	CK_ULONG num_slots = 0;
	rc = functions->C_GetSlotList(only_slots_with_token, NULL_PTR, &num_slots);
	if (num_slots > 0 )
	{
		pSlotList = (CK_SLOT_ID_PTR) malloc(num_slots*sizeof(CK_SLOT_ID));
		rc = functions->C_GetSlotList(only_slots_with_token, pSlotList, &num_slots);
	}
	return pSlotList;
}

CK_SLOT_INFO_PTR Pkcs11W::GetSlotInfo(CK_SLOT_ID slot_id)
{
	if (pSlotInfo == NULL_PTR) pSlotInfo = new CK_SLOT_INFO();
	rc = functions->C_GetSlotInfo(slot_id, pSlotInfo);
	return pSlotInfo;	
}

CK_TOKEN_INFO_PTR Pkcs11W::GetTokenInfo(CK_SLOT_ID slot_id)
{
	if (pTokenInfo == NULL_PTR) pTokenInfo = new CK_TOKEN_INFO();
	rc = functions->C_GetTokenInfo(slot_id, pTokenInfo);
	return pTokenInfo;	
}	

void Pkcs11W::WaitForSlotEvent(CK_SLOT_ID slot_id, CK_FLAGS flags, CK_VOID_PTR pReserved)
{
	rc = functions->C_WaitForSlotEvent(flags, &slot_id, pReserved);	
}	

CK_ULONG Pkcs11W::GetNumMechanisms(CK_SLOT_ID slot_id)
{
	CK_ULONG num_mechs = 0;
	rc = functions->C_GetMechanismList(slot_id, NULL_PTR, &num_mechs);
	return num_mechs;
}

CK_MECHANISM_TYPE_PTR Pkcs11W::GetMechanismList(CK_SLOT_ID slot_id)
{
	delete [] pMechanismList;
	pMechanismList = NULL_PTR;
	CK_ULONG num_mechs = 0;
	rc = functions->C_GetMechanismList(slot_id, NULL_PTR, &num_mechs);
	if (num_mechs > 0 )
	{
		pMechanismList = (CK_MECHANISM_TYPE_PTR) malloc(num_mechs*sizeof(CK_MECHANISM_TYPE));
		rc = functions->C_GetMechanismList(slot_id, pMechanismList, &num_mechs);
	}
	return pMechanismList;
}

CK_MECHANISM_INFO_PTR Pkcs11W::GetMechanismInfo(CK_SLOT_ID slot_id, CK_MECHANISM_TYPE mech_type)
{
	if(pMechanismInfo == NULL_PTR) pMechanismInfo = new CK_MECHANISM_INFO();
	rc = functions->C_GetMechanismInfo(slot_id, mech_type, pMechanismInfo);
	return pMechanismInfo;
}

CK_SESSION_HANDLE_PTR Pkcs11W::OpenSession(CK_SLOT_ID slot_id, bool rw_session, CK_VOID_PTR callback_param, CK_NOTIFY callback)
{
	if(pSession == NULL_PTR) pSession = new CK_SESSION_HANDLE();
	CK_FLAGS flags = CKF_SERIAL_SESSION;
	if (rw_session) flags = flags | CKF_RW_SESSION;
	rc = functions->C_OpenSession(slot_id, flags, callback_param, callback, pSession);
	return pSession;
}

CK_RV Pkcs11W::CloseSession()
{
	rc = functions->C_CloseSession(*pSession);
	delete pSession;
	pSession = NULL_PTR;
	return rc;
}

CK_RV Pkcs11W::CloseAllSessions(CK_SLOT_ID slot_id)
{
	rc = functions->C_CloseAllSessions(slot_id);
	return rc;
}

CK_SESSION_INFO_PTR Pkcs11W::GetSessionInfo()
{
	if (pSessionInfo == NULL_PTR) pSessionInfo = new CK_SESSION_INFO();
	rc = functions->C_GetSessionInfo(*pSession, pSessionInfo);
	return pSessionInfo;
}

CK_RV Pkcs11W::InitToken(CK_SLOT_ID slot_id, CK_UTF8CHAR aSOPin [], CK_UTF8CHAR aLabel [])
{
	CK_UTF8CHAR label[32];
	memset(label, ' ', sizeof(label));
	memcpy(label, aLabel, strlen((char*)aLabel));
	rc = functions->C_InitToken(slot_id, aSOPin, strlen((char*)aSOPin), label);
	return rc;
}

CK_RV Pkcs11W::InitPin(CK_UTF8CHAR aPin[])  //aPin *must* be \0-terminated. 
{
	rc = functions->C_InitPIN(*pSession, aPin, strlen((char*)aPin));
	return rc;
}

CK_RV Pkcs11W::SetPin(CK_UTF8CHAR aOldPin[], CK_UTF8CHAR aNewPin[])  //aPin *must* be \0-terminated. 
{
	rc = functions->C_SetPIN(*pSession, aOldPin, strlen((char*)aOldPin), aNewPin, strlen((char*)aNewPin));
	return rc;
}

CK_RV Pkcs11W::Login(CK_UTF8CHAR aPin[], CK_USER_TYPE user_type)
{
	rc = functions->C_Login(*pSession, user_type, aPin, strlen((char*)aPin));
	return rc;
}

CK_RV Pkcs11W::SOLogin(CK_UTF8CHAR aPin[])
{
	return Login(aPin, CKU_SO);
}

CK_RV Pkcs11W::Logout()
{
	rc = functions->C_Logout(*pSession);
	return rc;
}





