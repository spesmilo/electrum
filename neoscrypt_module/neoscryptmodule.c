#include <Python.h>

#include "neoscrypt.h"

static PyObject *neoscrypt_getpowhash(PyObject *self, PyObject *args)
{
    unsigned char *output;
    PyObject *value;
    PyStringObject *input;
    if (!PyArg_ParseTuple(args, "S", &input))
        return NULL;
    Py_INCREF(input);
    output = PyMem_Malloc(32);

    neoscrypt((unsigned char *)PyString_AsString((PyObject*) input), output);

    Py_DECREF(input);
    value = Py_BuildValue("s#", output, 32);
    PyMem_Free(output);
    return value;
}

static PyMethodDef NeoScryptMethods[] = {
    { "getPoWHash", neoscrypt_getpowhash, METH_VARARGS, "Returns proof-of-work hash using NeoScrypt" },
    { NULL, NULL, 0, NULL }
};

PyMODINIT_FUNC initneoscrypt(void) {
    (void) Py_InitModule("neoscrypt", NeoScryptMethods);
}
