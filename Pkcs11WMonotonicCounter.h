#ifndef PKCS11WMONOTONICCOUNTER_H
#define PKCS11WMONOTONICCOUNTER_H

#include "Pkcs11WHardwareFeature.h"

class Pkcs11WMonotonicCounter : public Pkcs11WHardwareFeature
{
	private:
		bool reset_on_init;
		bool has_reset;
		CKA_VALUE value; 
	public:	
		
};



#endif
