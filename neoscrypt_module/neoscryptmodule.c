#include <Python.h>

#include "neoscrypt.h"

static PyObject *neoscrypt_getpowhash(PyObject *self, PyObject *args)
{
    const char *input;
    int len;
    if (!PyArg_ParseTuple(args, "y#", &input, &len))
        return NULL;

    unsigned char *output = PyMem_Malloc(32);
    neoscrypt((const unsigned char *)input, output);

    PyObject *value = Py_BuildValue("y#", output, 32);
    PyMem_Free(output);
    return value;
}

static PyMethodDef NeoScryptMethods[] = {
    { "getPoWHash", neoscrypt_getpowhash, METH_VARARGS, "Returns proof-of-work hash using NeoScrypt" },
    { NULL, NULL, 0, NULL }
};

static struct PyModuleDef modDef =
{
    PyModuleDef_HEAD_INIT,
    "neoscrypt",
    "",
    -1,
    NeoScryptMethods
};

PyMODINIT_FUNC PyInit_neoscrypt(void) {
    return PyModule_Create(&modDef);
}
