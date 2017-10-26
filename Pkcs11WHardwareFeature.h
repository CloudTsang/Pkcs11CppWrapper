#ifndef PKCS11WHHARDWAREFEATURE_H
#define PKCS11WHHARDWAREFEATURE_H

#include "Pkcs11WObject.h"

class Pkcs11WHardwareFeature : public Pkcs11WObject
{
	private:
		CK_HW_FEATURE_TYPE hw_feature_type;
	public:	
		CK_HW_FEATURE_TYPE getHardwareFeatureType();
		void setHardwareFeatureType(CK_HW_FEATURE_TYPE);
};



#endif
