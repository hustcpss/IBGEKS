// PEKS_wrapper.cpp
#include <Python.h>
#include <map>
#include "PEKS.h"
using namespace std;

map <int, PEKS*> peks_ins;

static PyObject* peks_setup(PyObject *self , PyObject *args)
{
    PyObject *ret;

    int instanceID;

    if(!PyArg_ParseTuple(args , "i" , &instanceID))
    {
      return NULL;
    }   

    peks_ins[instanceID] = new PEKS();
    peks_ins[instanceID]->setup();

    ret = (PyObject *)Py_BuildValue("i" , instanceID);

    return ret;
}

static PyObject* peks_encrypt(PyObject *self , PyObject *args)
{
    PyObject *ret;
    
    char* keyword;
    int instanceID;

    if(!PyArg_ParseTuple(args , "is" , &instanceID, &keyword))
    {
      return NULL;
    }        

    unsigned char Ca[G1_LEN],Cb[HASH_LEN];

    peks_ins[instanceID]->encrypt(Ca, Cb, keyword);

    ret = (PyObject *)Py_BuildValue("y#y#" , Ca, G1_LEN, Cb, HASH_LEN);

    return ret;
}

static PyObject* peks_trapdoor(PyObject *self , PyObject *args)
{
    PyObject *ret;

    int instanceID;
    char* keyword;

    if(!PyArg_ParseTuple(args , "is" , &instanceID, &keyword))
    {
      return NULL;
    }      


    unsigned char Tw[G1_LEN];

    peks_ins[instanceID]->trapdoor(Tw, keyword);


    ret = (PyObject *)Py_BuildValue("y#", Tw, G1_LEN);

    return ret;

}

static PyObject* peks_test(PyObject *self , PyObject *args)
{
    PyObject *ret;
    unsigned char *Tw, *Ca, *Cb;
    int Tw_l,Ca_l,Cb_l;
    int instanceID;

    if(!PyArg_ParseTuple(args , "iy#y#y#" , &instanceID, &Tw, &Tw_l, &Ca, &Ca_l, &Cb, &Cb_l))
    {
      return NULL;
    }      


    int result = peks_ins[instanceID]->test(Tw, Ca, Cb); 


    ret = (PyObject *)Py_BuildValue("i", result);

    return ret;
}

static PyObject* peks_importkey(PyObject *self , PyObject *args)
{
    PyObject *ret;
    unsigned char *pk, *sk;
    int instanceID;
    int pk_l,sk_l;

    if(!PyArg_ParseTuple(args , "iy#y#" , &instanceID, &pk, &pk_l, &sk, &sk_l))
    {
      return NULL;
    }

    int result = peks_ins[instanceID]->importkey(pk,sk);      

    ret = (PyObject *)Py_BuildValue("i", result);

    return ret;
}

static PyObject* peks_exportkey(PyObject *self , PyObject *args)
{
    PyObject *ret;
    unsigned char pk[G1_LEN],sk[Zr_LEN];
    int instanceID;

    if(!PyArg_ParseTuple(args , "i" , &instanceID))
    {
      return NULL;
    }    

    int result = peks_ins[instanceID]->exportkey(pk,sk);

    ret = (PyObject *)Py_BuildValue("y#y#" , pk, G1_LEN, sk, Zr_LEN);

    return ret;
}

static PyMethodDef
Peks_methods[] = {
    {"setup" , peks_setup, METH_VARARGS},
    {"encrypt" , peks_encrypt , METH_VARARGS},
    {"trapdoor" , peks_trapdoor, METH_VARARGS},
    {"test" , peks_test,METH_VARARGS},
    {"importkey" , peks_importkey,METH_VARARGS},
    {"exportkey",peks_exportkey,METH_VARARGS},
    {0, 0, 0},
};

static struct PyModuleDef
Peks_mod = {
    PyModuleDef_HEAD_INIT,
    "Peks_mod",
    "",
    -1,
    Peks_methods,
    NULL,
    NULL,
    NULL,
    NULL
};


PyMODINIT_FUNC PyInit_Peks_mod(void)
{
    return PyModule_Create(&Peks_mod);
}
