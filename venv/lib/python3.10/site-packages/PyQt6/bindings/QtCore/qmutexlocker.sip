// This is the SIP interface definition for the QMutexLocker class.
//
// In Qt6 this is a template so we wrap our own class that implements the Qt5
// API.
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


class PyQtMutexLocker /PyName=QMutexLocker/
{
%TypeHeaderCode
#include "qpycore_pyqtmutexlocker.h"
%End

public:
    PyQtMutexLocker(QMutex *mutex /GetWrapper/) /ReleaseGIL/;
%MethodCode
    Py_BEGIN_ALLOW_THREADS
    sipCpp = new PyQtMutexLocker(a0, a0Wrapper);
    Py_END_ALLOW_THREADS
%End

    PyQtMutexLocker(QRecursiveMutex *mutex /GetWrapper/) /ReleaseGIL/;
%MethodCode
    Py_BEGIN_ALLOW_THREADS
    sipCpp = new PyQtMutexLocker(a0, a0Wrapper);
    Py_END_ALLOW_THREADS
%End

    ~PyQtMutexLocker();

    SIP_PYOBJECT mutex() /TypeHint="Union[QMutex, QRecursiveMutex]"/;
    void unlock() /ReleaseGIL/;
    void relock() /ReleaseGIL/;

    SIP_PYOBJECT __enter__();
%MethodCode
    // Just return a reference to self.
    sipRes = sipSelf;
    Py_INCREF(sipRes);
%End

    void __exit__(SIP_PYOBJECT type, SIP_PYOBJECT value, SIP_PYOBJECT traceback);
%MethodCode
    sipCpp->unlock();
%End

private:
    PyQtMutexLocker(const PyQtMutexLocker &);
};
