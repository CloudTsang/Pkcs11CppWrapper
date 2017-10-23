#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <dlfcn.h>
#include "Pkcs11W.h"

using namespace std;

#include "strMechanismType.cpp"

const char* strState(CK_STATE state)
{
	if (state==CKS_RO_PUBLIC_SESSION) return "CKS_RO_PUBLIC_SESSION";
	if (state==CKS_RO_USER_FUNCTIONS) return "CKS_RO_USER_FUNCTIONS";
	if (state==CKS_RW_PUBLIC_SESSION) return "CKS_RW_PUBLIC_SESSION";
	if (state==CKS_RW_USER_FUNCTIONS) return "CKS_RW_USER_FUNCTIONS";
	if (state==CKS_RW_SO_FUNCTIONS)   return "CKS_RW_SO_FUNCTIONS";
}

std::ostream& operator << (ostream &o, const CK_VERSION version)
{
	o << (int)(version.major) << "." << (int)(version.minor);
	return o;
}

std::ostream& operator << (ostream &o, const CK_INFO info)
{
	o 
	<< "CryptokiVersion:       \t" << info.cryptokiVersion 
	<< "\nManufacturerID:      \t" << info.manufacturerID
	<< "\nFlags:               \t0x" << std::hex <<info.flags
	<< "\nLibrary Description: \t" << info.libraryDescription
	<< "\nLibraryVersion:      \t" << info.libraryVersion 
	;
	return o;
}

std::ostream& operator << (ostream &o, const CK_SLOT_INFO info)
{
	o 
	<< "SlotDescription:       \t" << info.slotDescription
	<< "\nManufacturerID:      \t" << info.manufacturerID
	<< "\nFlags:               \t" << std::hex <<info.flags
	<< "\nHardwareVersion:     \t" << info.hardwareVersion
	<< "\nFirmwareVersion:     \t" << info.firmwareVersion
	;
	return o;
}

std::ostream& operator << (ostream &o, const CK_TOKEN_INFO info)
{
	o 
	<< "Label:                \t" << info.label
	<< "\nManufacturerID:     \t" << info.manufacturerID
	<< "\nModel:              \t" << info.model
	<< "\nSerialNumber:       \t" << info.serialNumber
	<< "\nFlags:              \t0x" << std::hex << info.flags
	<< "\nMaxSessionCount:    \t" << info.ulMaxSessionCount
	<< "\nSessionCount:       \t" << info.ulSessionCount
	<< "\nMaxRwSessionCount:  \t" << info.ulMaxRwSessionCount
	<< "\nRwSessionCount:     \t" << info.ulRwSessionCount
	<< "\nMaxPinLen:          \t" << info.ulMaxPinLen
	<< "\nMinPinLen:          \t" << info.ulMinPinLen
	<< "\nTotalPublicMemory:  \t" << info.ulTotalPublicMemory
	<< "\nFreePublicMemory:   \t" << info.ulFreePublicMemory
	<< "\nTotalPrivateMemory: \t" << info.ulTotalPrivateMemory
	<< "\nTotalPrivateMemory: \t" << info.ulTotalPrivateMemory
	<< "\nHardwareVersion:    \t" << info.hardwareVersion
	<< "\nFirmwareVersion:    \t" << info.firmwareVersion
	<< "\nUtcTime:            \t" << info.utcTime
	;
	return o;
}

std::ostream& operator << (ostream &o, const CK_MECHANISM_INFO info)
{
	o 
	<< "MinKeySize:           \t" << info.ulMinKeySize
	<< "\nMaxKeySize:         \t" << info.ulMaxKeySize
	<< "\nFlags:              \t0x" << std::hex << info.flags
	;
	return o;
}

std::ostream& operator << (ostream &o, const CK_SESSION_INFO info)
{
	o 
	<< "slotId:               \t" << info.slotID
	<< "\nstate:              \t" << strState(info.state)
	<< "\nflags:              \t0x" << std::hex << info.flags
	<< "\nulDeviceError:      \t" << info.ulDeviceError
	;
	return o;
}

CK_VERSION hardwareVersion;
CK_VERSION firmwareVersion;
CK_CHAR utcTime[16];

int main()
{
	/*https://www.certificainfo.com.br/pagina/drives.html*/
	//Pkcs11W pkcs("/usr/lib/libaetpkss.so.3");
	//Pkcs11W pkcs("/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so");
	Pkcs11W pkcs("/usr/lib/libcastle.so.1.0.0");
	pkcs.Initialize();
	cout << "==> Initialize" << pkcs.strRv() << endl;
	CK_INFO_PTR info = pkcs.GetInfo();
	cout << "==> GetInfo" << pkcs.strRv() << endl;
	cout << *info << endl;

	

	/* SLOTS SEM TOKEN */
	CK_SLOT_INFO_PTR slot_info;
	CK_TOKEN_INFO_PTR token_info;
	CK_ULONG num_slots;
	CK_SLOT_ID_PTR slot_id_array;
	/*
	cout << endl << " --- Slots sem token --- " << endl << endl;
	num_slots = pkcs.GetNumSlots();
	cout << "==> GetNumSlots" << pkcs.strRv() << endl;
	cout << "NumSlots = " << num_slots << endl;
	slot_id_array = pkcs.GetSlotList();
	cout << "==> GetSlotList" << pkcs.strRv() << endl;
	CK_SLOT_INFO_PTR slot_info;
	CK_TOKEN_INFO_PTR token_info;
	for (CK_ULONG i = 0; i< num_slots; i++)
	{
		slot_info = pkcs.GetSlotInfo(slot_id_array[i]);
		cout << "==> GetSlotInfo" << pkcs.strRv() << endl;
		cout << *slot_info << endl;

		token_info = pkcs.GetTokenInfo(slot_id_array[i]);
		cout << "==> GetTokenInfo" << pkcs.strRv() << endl;
		if (pkcs.rv() == CKR_OK)
			cout << *token_info << endl;
	}
	//pkcs.WaitForSlotEvent(slot_id_array[0], NULL_PTR);
	
	*/

	/* Slots com token */
	cout << endl << " --- Slots com token --- " << endl << endl;
	num_slots = pkcs.GetNumSlots(TRUE);
	cout << "==> GetNumSlots (com token)" << pkcs.strRv() << endl;
	cout << "NumSlots (com token) = " << num_slots << endl;
	slot_id_array = pkcs.GetSlotList(TRUE);
	cout << "==> GetSlotList(com token)" << pkcs.strRv() << endl;
	for (CK_ULONG i = 0; i< num_slots; i++)
	{
		slot_info = pkcs.GetSlotInfo(slot_id_array[i]);
		cout << "==> GetSlotInfo" << pkcs.strRv() << endl;
		cout << *slot_info << endl;

		token_info = pkcs.GetTokenInfo(slot_id_array[i]);
		cout << "==> GetTokenInfo" << pkcs.strRv() << endl;
		if (pkcs.rv() == CKR_OK)
			cout << *token_info << endl;
	}
	//slot_id_array = pkcs.GetSlotList(); // primeiro slot da lista sera escolhido!

	/* Mechanisms */
	/*
	cout << "Mechanisms:" << endl;
	CK_ULONG num_mechs = pkcs.GetNumMechanisms(slot_id_array[0]);
	cout << "==> GetNumMechanisms" << pkcs.strRv() << endl;
	CK_MECHANISM_TYPE_PTR mechanism_array = pkcs.GetMechanismList(slot_id_array[0]);
	cout << "==> GetMechList" << pkcs.strRv() << endl;
	for (CK_ULONG i = 0; i< num_mechs; i++)
	{
		CK_MECHANISM_INFO_PTR mechanism_info_ptr = pkcs.GetMechanismInfo(slot_id_array[0], mechanism_array[i]);
		cout << strMechanismType(mechanism_array[i]) << " : 0x" << std::hex << mechanism_array[i] << endl;
		cout << "==> GetMechInfo" << pkcs.strRv() << endl;
		cout << *mechanism_info_ptr << endl;
		cout << endl;
	}
	*/

	CK_UTF8CHAR sopin[] = "entersafe";
	CK_UTF8CHAR pin[] = "12345678";
	CK_UTF8CHAR label[] = "Meu token epass2003";
	CK_SESSION_INFO_PTR session_info;
	
	/* Session */
	
	pkcs.OpenSession(slot_id_array[0], true);
	cout << "==> OpenSession" << pkcs.strRv() << endl;
	session_info = pkcs.GetSessionInfo();
	cout << "==> GetSessionInfo" << pkcs.strRv() << endl;
	cout << *session_info << endl;
	/**/
	
	/* Login, logout */
	
	pkcs.Login(pin, 1);
	cout << "==> Login" << pkcs.strRv() << endl;
	session_info = pkcs.GetSessionInfo();
	cout << "==> GetSessionInfo" << pkcs.strRv() << endl;
	cout << *session_info << endl;
	pkcs.Logout();
	cout << "==> Logout" << pkcs.strRv() << endl;
	pkcs.CloseSession();
	cout << "==> CloseSession" << pkcs.strRv() << endl;
	/**/
	

	/* Token initialization (WIPES ALL DATA!) */ 
	/*
	pkcs.InitToken(slot_id_array[0], pin, label);	
	cout << "==> InitToken" << pkcs.strRv() << endl;	
	/**/

	pkcs.Finalize();
	pkcs.unload();
	return 0;
}




