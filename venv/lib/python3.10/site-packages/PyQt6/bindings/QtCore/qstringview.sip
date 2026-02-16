// This is the SIP interface definition for the QStringView mapped type.
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


%MappedType QStringView /TypeHint="str",TypeHintValue="''"/
{
%TypeHeaderCode
#include <qstringview.h>
%End

%ConvertToTypeCode
if (sipIsErr == NULL)
    return PyUnicode_Check(sipPy);

// TODO: consider creating the view directly from the Python object if it is
// using UTF-16.
QString *qs = new QString(qpycore_PyObject_AsQString(sipPy));
*sipCppPtr = new QStringView(*qs);
*sipUserStatePtr = qs;

return sipGetState(sipTransferObj);
%End

%ConvertFromTypeCode
    return qpycore_PyObject_FromQString(sipCpp->toString());
%End

%ReleaseCode
delete sipCpp;
delete reinterpret_cast<QString *>(sipUserState);
%End
};
