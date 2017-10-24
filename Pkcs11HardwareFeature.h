#ifndef PKCS11WHHARDWAREFEATURE_H
#define PKCS11WHHARDWAREFEATURE_H

#include "Pkcs11WObject.h"

class Pkcs11WHardwareFeature
{
	private:

	protected:
		virtual CK_ATTRIBUTE getCKAttribute(CK_ATTRIBUTE_TYPE);
	public:	
		virtual CK_ATTRIBUTE_PTR getCKAttributes(); // remember to take care of deleting the returned pointer	
};



#endif
