// This is the SIP specification of the template versions of qmlRegisterType()
// and related functions.
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


%ModuleHeaderCode
#include <qpyqml_api.h>
%End


%ModuleCode
// Imports from QtCore.
pyqt6_qtqml_get_qmetaobject_t pyqt6_qtqml_get_qmetaobject;
%End


%PostInitialisationCode
// Imports from QtCore.
pyqt6_qtqml_get_qmetaobject = (pyqt6_qtqml_get_qmetaobject_t)sipImportSymbol(
        "pyqt6_get_qmetaobject");
Q_ASSERT(pyqt6_qtqml_get_qmetaobject);
%End


int qmlRegisterRevision(SIP_PYTYPE, const char *uri, int major, int minor,
        SIP_PYTYPE attachedProperties = 0);
%MethodCode
    if ((sipRes = qpyqml_register_library_type((PyTypeObject *)a0, a1, a2, a3, nullptr, (PyTypeObject *)a4)) < 0)
        sipError = sipErrorFail;
%End


int qmlRegisterSingletonInstance(const char *uri, int major, int minor,
        const char *typeName, QObject *cppObject);


int qmlRegisterSingletonType(SIP_PYTYPE, const char *uri, int major, int minor,
        SIP_PYCALLABLE factory /TypeHint="Callable[[QQmlEngine, QJSEngine], Any]"/,
        const char *name = 0);
%MethodCode
    if ((sipRes = qpyqml_register_singleton_type((PyTypeObject *)a0, a1, a2, a3, a5, a4)) < 0)
        sipError = sipErrorFail;
%End


int qmlRegisterType(SIP_PYTYPE, const char *uri, int major, int minor,
        const char *name = 0, SIP_PYTYPE attachedProperties = 0);
%MethodCode
    if ((sipRes = qpyqml_register_library_type((PyTypeObject *)a0, a1, a2, a3, a4, (PyTypeObject *)a5)) < 0)
        sipError = sipErrorFail;
%End


int qmlRegisterAnonymousType(SIP_PYTYPE, const char *uri, int major);
%MethodCode
    if ((sipRes = qpyqml_register_anonymous_type((PyTypeObject *)a0, a1, a2)) < 0)
        sipError = sipErrorFail;
%End


int qmlRegisterUncreatableType(SIP_PYTYPE, const char *uri, int major,
        int minor, const QString &reason, const char *qmlName = 0);
%MethodCode
    if ((sipRes = qpyqml_register_uncreatable_type((PyTypeObject *)a0, a1, a2, a3, a5, *a4)) < 0)
        sipError = sipErrorFail;
%End
