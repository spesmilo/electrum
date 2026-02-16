// This is the SIP interface definition for the QNultiHash based mapped types.
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


%If (Qt_6_2_0 -)

template<quint16, _TYPE_>
%MappedType QMultiHash<quint16, _TYPE_>
        /TypeHint="Dict[int, _TYPE_]", TypeHintValue="{}"/
{
%TypeHeaderCode
#include <QMultiHash>
%End

%ConvertFromTypeCode
    PyObject *d = PyDict_New();

    if (!d)
        return 0;

    QMultiHash<quint16, _TYPE_>::const_iterator it = sipCpp->constBegin();
    QMultiHash<quint16, _TYPE_>::const_iterator end = sipCpp->constEnd();

    while (it != end)
    {
        PyObject *kobj = PyLong_FromLong(it.key());

        if (!kobj)
        {
            Py_DECREF(d);

            return 0;
        }

        QList<_TYPE_> values = sipCpp->values(it.key());

        PyObject *py_values = PyList_New(values.size());

        if (!py_values)
        {
            Py_DECREF(kobj);
            Py_DECREF(d);

            return 0;
        }

        int rc = PyDict_SetItem(d, kobj, py_values);

        Py_DECREF(py_values);
        Py_DECREF(kobj);

        if (rc < 0)
        {
            Py_DECREF(d);

            return 0;
        }

        for (int i = 0; i < values.size(); ++i)
        {
            _TYPE_ *v = new _TYPE_(values.at(i));
            PyObject *vobj = sipConvertFromNewType(v, sipType__TYPE_,
                    sipTransferObj);

            if (!vobj)
            {
                delete v;
                Py_DECREF(d);

                return 0;
            }

            PyList_SetItem(py_values, i, vobj);
        }

        ++it;
    }

    return d;
%End
};

%End


%If (Qt_6_3_0 -)

template<_TYPE1_, _TYPE2_>
%MappedType QMultiHash<_TYPE1_, _TYPE2_>
        /TypeHint="Dict[_TYPE1_, _TYPE2_]", TypeHintValue="{}"/
{
%TypeHeaderCode
#include <QMultiHash>
%End

%ConvertFromTypeCode
    PyObject *d = PyDict_New();

    if (!d)
        return 0;

    QMultiHash<_TYPE1_, _TYPE2_>::const_iterator it = sipCpp->constBegin();
    QMultiHash<_TYPE1_, _TYPE2_>::const_iterator end = sipCpp->constEnd();

    while (it != end)
    {
        _TYPE1_ *k = new _TYPE1_(it.key());
        PyObject *kobj = sipConvertFromNewType(k, sipType__TYPE1_,
                sipTransferObj);

        if (!kobj)
        {
            delete k;
            Py_DECREF(d);

            return 0;
        }

        QList<_TYPE2_> values = sipCpp->values(it.key());

        PyObject *py_values = PyList_New(values.size());

        if (!py_values)
        {
            Py_DECREF(kobj);
            Py_DECREF(d);

            return 0;
        }

        int rc = PyDict_SetItem(d, kobj, py_values);

        Py_DECREF(py_values);
        Py_DECREF(kobj);

        if (rc < 0)
        {
            Py_DECREF(d);

            return 0;
        }

        for (int i = 0; i < values.size(); ++i)
        {
            _TYPE2_ *v = new _TYPE2_(values.at(i));
            PyObject *vobj = sipConvertFromNewType(v, sipType__TYPE2_,
                    sipTransferObj);

            if (!vobj)
            {
                delete v;
                Py_DECREF(d);

                return 0;
            }

            PyList_SetItem(py_values, i, vobj);
        }

        ++it;
    }

    return d;
%End
};

%End
