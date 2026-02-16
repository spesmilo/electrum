// This is the SIP interface definition for the QFlags based mapped types.
//
// Copyright (c) 2026 Riverbank Computing Limited <info@riverbankcomputing.com>
// 
// This file is part of PyQt6.
// 
// This file may be used under the terms of the GNU General Public License
// version 3.0 as published by the Free Software Foundation and appearing in
// the file LICENSE included in the packaging of this file.  Please review the
// following information to ensure the GNU General Public License version 3.0
// requirements will be met: http://www.gnu.org/copyleft/gpl.html.
// 
// If you do not wish to use this file under the terms of the GPL version 3.0
// then you may purchase a commercial license.  For more information contact
// info@riverbankcomputing.com.
// 
// This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
// WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.


template<ENUM>
%MappedType QFlags<ENUM> /PyQtFlags=1, TypeHint="ENUM"/
{
%TypeHeaderCode
#include <qglobal.h>
%End

%ConvertToTypeCode
bool is_enm = true;
unsigned enm = (unsigned)sipConvertToEnum(sipPy, sipType_ENUM);

if (PyErr_Occurred())
{
    PyErr_Clear();
    is_enm = false;
}

if (sipIsErr == NULL)
    return is_enm;

*sipCppPtr = new QFlags<ENUM>(static_cast<ENUM>(enm));

return sipGetState(sipTransferObj);
%End

%ConvertFromTypeCode
return sipConvertFromEnum(sipCpp->operator::QFlags<ENUM>::Int(), sipType_ENUM);
%End
};
