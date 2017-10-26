
#include "Pkcs11WHardwareFeature.h"
#include "Pkcs11WMonotonicCounter.h"

CK_HW_FEATURE_TYPE Pkcs11WHardwareFeature::getHardwareFeatureType()
{
	return hw_feature_type;
}

void Pkcs11WHardwareFeature::setHardwareFeatureType(CK_HW_FEATURE_TYPE type)
{
	hw_feature_type = type;
}
