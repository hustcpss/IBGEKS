// SAPeks_wrapper.cpp
#include <Python.h>
#include <map>
#include <cstring>
#include "SA_PEKS.h"
using namespace std;

map <int, SAPeks*> SAPeks_ins;

static PyObject* SAPeks_setup(PyObject *self , PyObject *args)
{
    PyObject *ret;

    int instanceID;

    if(!PyArg_ParseTuple(args , "i" , &instanceID))
    {
      return NULL;
    }   

    SAPeks_ins[instanceID] = new SAPeks();

    ret = (PyObject *)Py_BuildValue("i" , instanceID);

    return ret;
}

static PyObject* SAPeks_encrypt(PyObject *self , PyObject *args)
{
    PyObject *ret;
    
    char* keyword;
    int instanceID, keyword_len;

    if(!PyArg_ParseTuple(args , "is#" , &instanceID, &keyword, &keyword_len))
    {
      return NULL;
    }        

    unsigned char Ca[G1_LEN],Cb[HASH_LEN];

    SAPeks_ins[instanceID]->encrypt(Ca, Cb, std::string(keyword,keyword_len));

    ret = (PyObject *)Py_BuildValue("y#y#" , Ca, G1_LEN, Cb, HASH_LEN);

    return ret;
}

static PyObject* SAPeks_trapdoor(PyObject *self , PyObject *args)
{
    PyObject *ret;

    int instanceID;
    char* keyword;
    int keyword_len;

    if(!PyArg_ParseTuple(args , "is#" , &instanceID, &keyword,&keyword_len))
    {
      return NULL;
    }      


    unsigned char Tw[G1_LEN];

    SAPeks_ins[instanceID]->trapdoor(Tw, std::string(keyword,keyword_len));


    ret = (PyObject *)Py_BuildValue("y#", Tw, G1_LEN);

    return ret;

}

static PyObject* SAPeks_test(PyObject *self , PyObject *args)
{
    PyObject *ret;
    unsigned char *Tw, *Ca, *Cb;
    int Tw_l,Ca_l,Cb_l;
    int instanceID;

    if(!PyArg_ParseTuple(args , "iy#y#y#" , &instanceID, &Tw, &Tw_l, &Ca, &Ca_l, &Cb, &Cb_l))
    {
      return NULL;
    }      


    int result = SAPeks_ins[instanceID]->test(Tw, Ca, Cb); 


    ret = (PyObject *)Py_BuildValue("i", result);

    return ret;
}

static PyObject* SAPeks_importkey(PyObject *self , PyObject *args)
{
    PyObject *ret;
    unsigned char *pk, *sk;
    int instanceID;
    int pk_l,sk_l;

    if(!PyArg_ParseTuple(args , "iy#y#" , &instanceID, &pk, &pk_l, &sk, &sk_l))
    {
      return NULL;
    }

    int result = SAPeks_ins[instanceID]->importkey(pk,sk);      

    ret = (PyObject *)Py_BuildValue("i", result);

    return ret;
}

static PyObject* SAPeks_exportkey(PyObject *self , PyObject *args)
{
    PyObject *ret;
    unsigned char pk[G1_LEN],sk[Zr_LEN];
    int instanceID;

    if(!PyArg_ParseTuple(args , "i" , &instanceID))
    {
      return NULL;
    }    

    int result = SAPeks_ins[instanceID]->exportkey(pk,sk);

    ret = (PyObject *)Py_BuildValue("y#y#" , pk, G1_LEN, sk, Zr_LEN);

    return ret;
}

static PyMethodDef
SAPeks_methods[] = {
    {"setup" , SAPeks_setup, METH_VARARGS},
    {"encrypt" , SAPeks_encrypt , METH_VARARGS},
    {"trapdoor" , SAPeks_trapdoor, METH_VARARGS},
    {"test" , SAPeks_test,METH_VARARGS},
    {"importkey" , SAPeks_importkey,METH_VARARGS},
    {"exportkey",SAPeks_exportkey,METH_VARARGS},
    {0, 0, 0},
};

static struct PyModuleDef
SAPeks_mod = {
    PyModuleDef_HEAD_INIT,
    "SAPeks_mod",
    "",
    -1,
    SAPeks_methods,
    NULL,
    NULL,
    NULL,
    NULL
};


PyMODINIT_FUNC PyInit_SAPeks_mod(void)
{
    return PyModule_Create(&SAPeks_mod);
}
