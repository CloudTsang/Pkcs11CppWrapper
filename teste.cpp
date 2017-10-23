//https://www.cryptsoft.com/pkcs11doc/v210/pkcs11__all_8h.html#aC_GetFunctionList
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <dlfcn.h>

#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name)  returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "pkcs11.h"



CK_FUNCTION_LIST_PTR  funcs = NULL_PTR;
CK_SLOT_ID        slotID = CK_UNAVAILABLE_INFORMATION;
CK_BYTE           tokenName[32];
 
using namespace std;

void ProcessRetCode( CK_RV rc )
{
   switch (rc) {
      case CKR_OK:                               printf(" CKR_OK");                               break;
      case CKR_CANCEL:                           printf(" CKR_CANCEL");                           break;
      case CKR_HOST_MEMORY:                      printf(" CKR_HOST_MEMORY");                      break;
      case CKR_SLOT_ID_INVALID:                  printf(" CKR_SLOT_ID_INVALID");                  break;
      case CKR_GENERAL_ERROR:                    printf(" CKR_GENERAL_ERROR");                    break;
      case CKR_FUNCTION_FAILED:                  printf(" CKR_FUNCTION_FAILED");                  break;
      case CKR_ARGUMENTS_BAD:                    printf(" CKR_ARGUMENTS_BAD");                    break;
      case CKR_NO_EVENT:                         printf(" CKR_NO_EVENT");                         break;
      case CKR_NEED_TO_CREATE_THREADS:           printf(" CKR_NEED_TO_CREATE_THREADS");           break;
      case CKR_CANT_LOCK:                        printf(" CKR_CANT_LOCK");                        break;
      case CKR_ATTRIBUTE_READ_ONLY:              printf(" CKR_ATTRIBUTE_READ_ONLY");              break;
      case CKR_ATTRIBUTE_SENSITIVE:              printf(" CKR_ATTRIBUTE_SENSITIVE");              break;
      case CKR_ATTRIBUTE_TYPE_INVALID:           printf(" CKR_ATTRIBUTE_TYPE_INVALID");           break;
      case CKR_ATTRIBUTE_VALUE_INVALID:          printf(" CKR_ATTRIBUTE_VALUE_INVALID");          break;
      case CKR_DATA_INVALID:                     printf(" CKR_DATA_INVALID");                     break;
      case CKR_DATA_LEN_RANGE:                   printf(" CKR_DATA_LEN_RANGE");                   break;
      case CKR_DEVICE_ERROR:                     printf(" CKR_DEVICE_ERROR");                     break;
      case CKR_DEVICE_MEMORY:                    printf(" CKR_DEVICE_MEMORY");                    break;
      case CKR_DEVICE_REMOVED:                   printf(" CKR_DEVICE_REMOVED");                   break;
      case CKR_ENCRYPTED_DATA_INVALID:           printf(" CKR_ENCRYPTED_DATA_INVALID");           break;
      case CKR_ENCRYPTED_DATA_LEN_RANGE:         printf(" CKR_ENCRYPTED_DATA_LEN_RANGE");         break;
      case CKR_FUNCTION_CANCELED:                printf(" CKR_FUNCTION_CANCELED");                break;
      case CKR_FUNCTION_NOT_PARALLEL:            printf(" CKR_FUNCTION_NOT_PARALLEL");            break;
      case CKR_FUNCTION_NOT_SUPPORTED:           printf(" CKR_FUNCTION_NOT_SUPPORTED");           break;
      case CKR_KEY_HANDLE_INVALID:               printf(" CKR_KEY_HANDLE_INVALID");               break;
      case CKR_KEY_SIZE_RANGE:                   printf(" CKR_KEY_SIZE_RANGE");                   break;
      case CKR_KEY_TYPE_INCONSISTENT:            printf(" CKR_KEY_TYPE_INCONSISTENT");            break;
      case CKR_KEY_NOT_NEEDED:                   printf(" CKR_KEY_NOT_NEEDED");                   break;
      case CKR_KEY_CHANGED:                      printf(" CKR_KEY_CHANGED");                      break;
      case CKR_KEY_NEEDED:                       printf(" CKR_KEY_NEEDED");                       break;
      case CKR_KEY_INDIGESTIBLE:                 printf(" CKR_KEY_INDIGESTIBLE");                 break;
      case CKR_KEY_FUNCTION_NOT_PERMITTED:       printf(" CKR_KEY_FUNCTION_NOT_PERMITTED");       break;
      case CKR_KEY_NOT_WRAPPABLE:                printf(" CKR_KEY_NOT_WRAPPABLE");                break;
      case CKR_KEY_UNEXTRACTABLE:                printf(" CKR_KEY_UNEXTRACTABLE");                break;
      case CKR_MECHANISM_INVALID:                printf(" CKR_MECHANISM_INVALID");                break;
      case CKR_MECHANISM_PARAM_INVALID:          printf(" CKR_MECHANISM_PARAM_INVALID");          break;
      case CKR_OBJECT_HANDLE_INVALID:            printf(" CKR_OBJECT_HANDLE_INVALID");            break;
      case CKR_OPERATION_ACTIVE:                 printf(" CKR_OPERATION_ACTIVE");                 break;
      case CKR_OPERATION_NOT_INITIALIZED:        printf(" CKR_OPERATION_NOT_INITIALIZED");        break;
      case CKR_PIN_INCORRECT:                    printf(" CKR_PIN_INCORRECT");                    break;
      case CKR_PIN_INVALID:                      printf(" CKR_PIN_INVALID");                      break;
      case CKR_PIN_LEN_RANGE:                    printf(" CKR_PIN_LEN_RANGE");                    break;
      case CKR_PIN_EXPIRED:                      printf(" CKR_PIN_EXPIRED");                      break;
      case CKR_PIN_LOCKED:                       printf(" CKR_PIN_LOCKED");                       break;
      case CKR_SESSION_CLOSED:                   printf(" CKR_SESSION_CLOSED");                   break;
      case CKR_SESSION_COUNT:                    printf(" CKR_SESSION_COUNT");                    break;
      case CKR_SESSION_HANDLE_INVALID:           printf(" CKR_SESSION_HANDLE_INVALID");           break;
      case CKR_SESSION_PARALLEL_NOT_SUPPORTED:   printf(" CKR_SESSION_PARALLEL_NOT_SUPPORTED");   break;
      case CKR_SESSION_READ_ONLY:                printf(" CKR_SESSION_READ_ONLY");                break;
      case CKR_SESSION_EXISTS:                   printf(" CKR_SESSION_EXISTS");                   break;
      case CKR_SESSION_READ_ONLY_EXISTS:         printf(" CKR_SESSION_READ_ONLY_EXISTS");         break;
      case CKR_SESSION_READ_WRITE_SO_EXISTS:     printf(" CKR_SESSION_READ_WRITE_SO_EXISTS");     break;
      case CKR_SIGNATURE_INVALID:                printf(" CKR_SIGNATURE_INVALID");                break;
      case CKR_SIGNATURE_LEN_RANGE:              printf(" CKR_SIGNATURE_LEN_RANGE");              break;
      case CKR_TEMPLATE_INCOMPLETE:              printf(" CKR_TEMPLATE_INCOMPLETE");              break;
      case CKR_TEMPLATE_INCONSISTENT:            printf(" CKR_TEMPLATE_INCONSISTENT");            break;
      case CKR_TOKEN_NOT_PRESENT:                
           printf(" CKR_TOKEN_NOT_PRESENT - ICSF is not active or not configured for TKDS operations"); break;
      case CKR_TOKEN_NOT_RECOGNIZED:             
           printf(" CKR_TOKEN_NOT_RECOGNIZED - You are not authorized to perform the token operation"); break;
      case CKR_TOKEN_WRITE_PROTECTED:            printf(" CKR_TOKEN_WRITE_PROTECTED");            break;
      case CKR_UNWRAPPING_KEY_HANDLE_INVALID:    printf(" CKR_UNWRAPPING_KEY_HANDLE_INVALID");    break;
      case CKR_UNWRAPPING_KEY_SIZE_RANGE:        printf(" CKR_UNWRAPPING_KEY_SIZE_RANGE");        break;
      case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT: printf(" CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT"); break;
      case CKR_USER_ALREADY_LOGGED_IN:           printf(" CKR_USER_ALREADY_LOGGED_IN");           break;
      case CKR_USER_NOT_LOGGED_IN:               printf(" CKR_USER_NOT_LOGGED_IN");               break;
      case CKR_USER_PIN_NOT_INITIALIZED:         printf(" CKR_USER_PIN_NOT_INITIALIZED");         break;
      case CKR_USER_TYPE_INVALID:                printf(" CKR_USER_TYPE_INVALID");                break;
      case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:   printf(" CKR_USER_ANOTHER_ALREADY_LOGGED_IN");   break;
      case CKR_USER_TOO_MANY_TYPES:              printf(" CKR_USER_TOO_MANY_TYPES");              break;
      case CKR_WRAPPED_KEY_INVALID:              printf(" CKR_WRAPPED_KEY_INVALID");              break;
      case CKR_WRAPPED_KEY_LEN_RANGE:            printf(" CKR_WRAPPED_KEY_LEN_RANGE");            break;
      case CKR_WRAPPING_KEY_HANDLE_INVALID:      printf(" CKR_WRAPPING_KEY_HANDLE_INVALID");      break;
      case CKR_WRAPPING_KEY_SIZE_RANGE:          printf(" CKR_WRAPPING_KEY_SIZE_RANGE");          break;
      case CKR_WRAPPING_KEY_TYPE_INCONSISTENT:   printf(" CKR_WRAPPING_KEY_TYPE_INCONSISTENT");   break;
      case CKR_RANDOM_SEED_NOT_SUPPORTED:        printf(" CKR_RANDOM_SEED_NOT_SUPPORTED");        break;
      case CKR_RANDOM_NO_RNG:                    printf(" CKR_RANDOM_NO_RNG");                    break;
      case CKR_BUFFER_TOO_SMALL:                 printf(" CKR_BUFFER_TOO_SMALL");                 break;
      case CKR_SAVED_STATE_INVALID:              printf(" CKR_SAVED_STATE_INVALID");              break;
      case CKR_INFORMATION_SENSITIVE:            printf(" CKR_INFORMATION_SENSITIVE");            break;
      case CKR_STATE_UNSAVEABLE:                 printf(" CKR_STATE_UNSAVEABLE");                 break;
      case CKR_CRYPTOKI_NOT_INITIALIZED:         printf(" CKR_CRYPTOKI_NOT_INITIALIZED");         break;
      case CKR_CRYPTOKI_ALREADY_INITIALIZED:     printf(" CKR_CRYPTOKI_ALREADY_INITIALIZED");     break;
      case CKR_MUTEX_BAD:                        printf(" CKR_MUTEX_BAD");                        break;
      case CKR_MUTEX_NOT_LOCKED:                 printf(" CKR_MUTEX_NOT_LOCKED");                 break;
      /* Otherwise - Value does not match a known PKCS11 return value */
   }
}

int main()
{

	void *lib_handle;
	double (*fn)(int *);
	int x;
	char *error;

	lib_handle = dlopen("/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so", RTLD_NOW);

	if (!lib_handle)
	{
	fprintf(stderr, "%s\n", dlerror());
	cout << "erro!" << endl;
	exit(1);
	}
	
	
	/*
	referencia de codigo que compila
	void *ptr;

	ptr = dlsym(lib_handle, "C_Initialize");

	double (*func)(int*) = (double(*)(int*))ptr;
	fn = func;

	if ((error = dlerror()) != NULL) 
	{
	fprintf(stderr, "%s\n", error);
	exit(1);
	}

	(*fn)(&x);
	printf("Valx=%d\n",x);
	dlclose(lib_handle);
	*/

	void *ptr;
	CK_RV            rc;
	CK_RV  (*pFunc)(CK_FUNCTION_LIST_PTR_PTR);

	ptr = dlsym(lib_handle, "C_GetFunctionList");
	pFunc = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR)) ptr;

	if ((error = dlerror()) != NULL) 
	{
	fprintf(stderr, "%s\n", error);
	exit(1);
	}

	cout << "Funcs =" << funcs << endl;
	
	CK_FUNCTION_LIST_PTR_PTR  funcs_ptr = &funcs;

	rc = pFunc(funcs_ptr);
	if (rc != CKR_OK) {
	   cout << "   C_GetFunctionList (pFunc) erro ";
	   ProcessRetCode(rc);
	   cout << endl;
	}		

	cout << "Funcs =" << funcs << endl;
	cout << "rc ok =" << rc /*(rc == CKR_OK)*/ << endl;

	
	rc = funcs->C_Initialize( NULL_PTR );
	if (rc != CKR_OK) {
	   cout << "   C_Initialize erro";
	}	
	
	CK_INFO  Info;
	rc = funcs->C_GetInfo( &Info );
	
	CK_ULONG ulSlotCount, ulSlotWithTokenCount;
	CK_SLOT_ID_PTR pSlotList;
	CK_TOKEN_INFO tokenInfo;
	CK_RV rv;

	/* Get list of all slots */
	rv = funcs->C_GetSlotList(FALSE, NULL_PTR, &ulSlotCount);
	if (rv == CKR_OK) 
	{
		pSlotList = (CK_SLOT_ID_PTR) malloc(ulSlotCount*sizeof(CK_SLOT_ID));
		rv = funcs->C_GetSlotList(FALSE, pSlotList, &ulSlotCount);
		if (rv == CKR_OK) 
		{
			/* Now use that list of all slots */
			cout << "Achamos " << ulSlotCount << " slots" << endl;	
			CK_SLOT_INFO slotInfo;
		
			rv = funcs->C_GetSlotInfo(pSlotList[0], &slotInfo);	
			cout << slotInfo.slotDescription << endl;

			rv = funcs->C_GetTokenInfo(pSlotList[0], &tokenInfo);
			if (rv != CKR_TOKEN_NOT_PRESENT)
			{
				cout << "Token encontrado: " << endl;	
				cout << tokenInfo.label << endl;	
				cout << tokenInfo.manufacturerID << endl;	
				cout << tokenInfo.model << endl;	
			}
			else 
			{
				ProcessRetCode(rv); 
				cout << endl;
			}
		}
	
	}


      	funcs->C_Finalize( NULL );
      
	dlclose(lib_handle);
	
	cout << "Teste" << endl;

	

	return 0;
}
