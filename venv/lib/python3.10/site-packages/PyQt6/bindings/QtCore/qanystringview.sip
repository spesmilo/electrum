// This is the SIP interface definition for the QAnyStringView mapped type.
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


%If (Qt_6_4_0 -)

%MappedType QAnyStringView /AllowNone, TypeHint="Union[QByteArray, QString]",TypeHintValue="''"/
{
%TypeHeaderCode
#include <qanystringview.h>
%End

%TypeCode
struct PyQtAnyStringState
{
    const sipTypeDef *instance_type;    // The instance's generated type.
    void *instance;                     // Either the QByteArray or QString.
    int instance_state;                 // The state of the instance conversion.
};
%End

%ConvertToTypeCode
if (sipIsErr == NULL)
    return sipCanConvertToType(sipPy, sipType_QString, 0) ||
           sipCanConvertToType(sipPy, sipType_QByteArray, SIP_NOT_NONE);

PyQtAnyStringState *state = new PyQtAnyStringState;

if (sipCanConvertToType(sipPy, sipType_QString, 0))
{
    QString *qs = reinterpret_cast<QString *>(
            sipConvertToType(sipPy, sipType_QString, sipTransferObj, 0,
                    &state->instance_state, sipIsErr));

    if (*sipIsErr)
        return 0;

    *sipCppPtr = new QAnyStringView(*qs);
    state->instance_type = sipType_QString;
    state->instance = qs;
}
else
{
    QByteArray *qba = reinterpret_cast<QByteArray *>(
            sipConvertToType(sipPy, sipType_QByteArray, sipTransferObj,
                    SIP_NOT_NONE, &state->instance_state, sipIsErr));

    if (*sipIsErr)
        return 0;

    *sipCppPtr = new QAnyStringView(*qba);
    state->instance_type = sipType_QByteArray;
    state->instance = qba;
}

*sipUserStatePtr = state;

return sipGetState(sipTransferObj);
%End

%ConvertFromTypeCode
    return qpycore_PyObject_FromQString(sipCpp->toString());
%End

%ReleaseCode
delete sipCpp;

PyQtAnyStringState *state = reinterpret_cast<PyQtAnyStringState *>(sipUserState);

sipReleaseType(state->instance, state->instance_type, state->instance_state);

delete state;
%End
};

%End
