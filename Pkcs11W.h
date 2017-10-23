#ifndef PKCS11W_H
#define PKCS11W_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <dlfcn.h>

// Per SO definitions, following Pkcs11 documentation.
#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name)  returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0

#define CKF_DONT_BLOCK 1

#endif

#include "pkcs11.h"

class Pkcs11W
{
	protected:
		CK_FUNCTION_LIST_PTR  functions = NULL_PTR; //Pointer that should get all the functions from pkcs11 lib
		CK_RV rc; //return code

		CK_INFO_PTR  pInfo;
		CK_SLOT_ID_PTR pSlotList;
		CK_SLOT_INFO_PTR pSlotInfo;
		CK_TOKEN_INFO_PTR pTokenInfo;
		CK_MECHANISM_TYPE_PTR pMechanismList;
		CK_MECHANISM_INFO_PTR pMechanismInfo;

		CK_SESSION_HANDLE_PTR pSession;
		CK_SESSION_INFO_PTR pSessionInfo;

		void* lib_handle;
		bool loaded;

	public:
		
		const char* strRv();

		Pkcs11W();
		Pkcs11W(const char* lib_location);
		~Pkcs11W();

		bool load(const char* lib_location, int rtld=RTLD_NOW); 
		bool unload();
		char* loadError(); 

		CK_RV returnValue();
		CK_RV rv(); 
		CK_FUNCTION_LIST_PTR GetFunctionList();	/* Returns a pointer to CK_FUNCTION_LIST so you can use the orignal pkcs11 library functions directly if desired. */

		CK_RV Initialize(CK_VOID_PTR p_init_args = NULL_PTR);
		CK_RV Finalize(CK_VOID_PTR p_reserved = NULL_PTR);

		/* The functions below extract info about the library, the slots, tokens and supported mechanisms and do not need a session  */
		CK_INFO_PTR GetInfo();
		CK_ULONG GetNumSlots(CK_BBOOL with_token_only = FALSE);
		CK_SLOT_ID_PTR GetSlotList(CK_BBOOL with_token_only = FALSE);
		CK_SLOT_INFO_PTR GetSlotInfo(CK_SLOT_ID);
		CK_TOKEN_INFO_PTR GetTokenInfo(CK_SLOT_ID);		
		void WaitForSlotEvent(CK_SLOT_ID, CK_FLAGS = NULL_PTR, CK_VOID_PTR = NULL_PTR);
		CK_ULONG GetNumMechanisms(CK_SLOT_ID);
		CK_MECHANISM_TYPE_PTR GetMechanismList(CK_SLOT_ID);
		CK_MECHANISM_INFO_PTR GetMechanismInfo(CK_SLOT_ID, CK_MECHANISM_TYPE);
		/* --- */

		/* Session management functions */
		/* In this implementation we support only one session at a time. If you
		need concurrent sessions you'll need to create multiple Pkcs11W ojects. */
		CK_SESSION_HANDLE_PTR OpenSession(CK_SLOT_ID, bool rw_session, CK_VOID_PTR callback_param=NULL_PTR, CK_NOTIFY callback=NULL_PTR);
		CK_RV CloseSession();
		CK_RV CloseAllSessions(CK_SLOT_ID);
		CK_SESSION_INFO_PTR GetSessionInfo();
		//TODO: Set & Get OperationState
		CK_RV Login(CK_UTF8CHAR aPin[], CK_USER_TYPE user_type = CKU_USER); // aPin *must* be \0-terminated.
		CK_RV Logout();
		CK_RV SOLogin(CK_UTF8CHAR aPuk[]);
		//...
		/* --- */

		/* Token initialization and Pin related functions */
		CK_RV InitToken(CK_SLOT_ID, CK_UTF8CHAR aSOPin[], CK_UTF8CHAR aLabel[]); //WARNING: This wipes out everything in the token. Char arrays *must* be \0-terminated. No session needed.
		/* 
		If the token has not been initialized (i.e. new from the factory), then the aPin parameter becomes the initial value of the SO PIN. 			If the token is being reinitialized, the pPin parameter is checked against the existing SO PIN to authorize the initialization operation.
		*/
		CK_RV InitPin(CK_UTF8CHAR aPin[]);  //aPin *must* be \0-terminated. 
		CK_RV SetPin(CK_UTF8CHAR aOldPin[], CK_UTF8CHAR aNewPin[]); //xPin *must* be \0-terminated. 
		/* --- */
		
		
};	




	

#endif
