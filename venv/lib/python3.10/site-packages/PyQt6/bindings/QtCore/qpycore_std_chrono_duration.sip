// This is the SIP interface definition for the std::chrono::duration based
// mapped types.
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


%If (Qt_6_8_0 -)

%MappedType std::chrono::milliseconds /TypeHint="int"/
{
%TypeHeaderCode
#include <chrono>
%End

%ConvertFromTypeCode
    return PyLong_FromLong(sipCpp->count());
%End

%ConvertToTypeCode
    if (!sipIsErr)
    {
        PyErr_Clear();
        sipLong_AsLong(sipPy);

        return !PyErr_Occurred();
    }

    *sipCppPtr = new std::chrono::milliseconds(sipLong_AsLong(sipPy));
 
    return sipGetState(sipTransferObj);
%End
};

%End


%If (Qt_6_9_0 -)

%MappedType std::chrono::seconds /TypeHint="int"/
{
%TypeHeaderCode
#include <chrono>
%End

%ConvertFromTypeCode
    return PyLong_FromLong(sipCpp->count());
%End

%ConvertToTypeCode
    if (!sipIsErr)
    {
        PyErr_Clear();
        sipLong_AsLong(sipPy);

        return !PyErr_Occurred();
    }

    *sipCppPtr = new std::chrono::seconds(sipLong_AsLong(sipPy));
 
    return sipGetState(sipTransferObj);
%End
};

%End
