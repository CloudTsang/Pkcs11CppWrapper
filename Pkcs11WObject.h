#ifndef PKCS11WOBJECT_H
#define PKCS11WOBJECT_H

#include "Pkcs11W.h"

class Pkcs11WObject
{
	private:
		CK_OBJECT_CLASS classs;
	protected:
		virtual CK_ATTRIBUTE getCKAttribute(CK_ATTRIBUTE_TYPE); //?
		CK_ATTRIBUTE getCKAttributeClass();
	public:	
		virtual CK_ATTRIBUTE_PTR getCKAttributes(); // ??
		CK_OBJECT_CLASS getClass();
		void setClass(CK_OBJECT_CLASS);
};



#endif
