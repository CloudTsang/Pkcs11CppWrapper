
#include "Pkcs11WObject.h"

CK_OBJECT_CLASS Pkcs11WObject::getClass()
{
	return classs;
}

void Pkcs11WObject::setClass(CK_OBJECT_CLASS c)
{
	classs = c;
}

CK_ATTRIBUTE Pkcs11WObject::getCKAttribute(CK_ATTRIBUTE_TYPE attr_type)
{
	CK_ATTRIBUTE attr;
	if (attr_type == CKA_CLASS)
	{
		attr = {CKA_CLASS, &classs, sizeof(classs)};
		return attr;
	}
	attr = {attr_type, NULL_PTR, 0};
	return attr;
}

CK_ATTRIBUTE_PTR Pkcs11WObject::getCKAttributes()
{
	CK_ATTRIBUTE_PTR attrs = new CK_ATTRIBUTE[1];
	attrs[0] = getCKAttribute(CKA_CLASS);
	return attrs;
}


