// PAEKS17_wrapper.cpp
#include <Python.h>
#include <map>
#include <cstring>
#include "PAEKS17.h"
using namespace std;

map <int, PAEKS17*> paeks17_ins;

static PyObject* paeks17_setup(PyObject *self , PyObject *args)
{
    PyObject *ret;

    int instanceID;

    if(!PyArg_ParseTuple(args , "i" , &instanceID))
    {
      return NULL;
    }   

    paeks17_ins[instanceID] = new PAEKS17();
    paeks17_ins[instanceID]->setup();

    ret = (PyObject *)Py_BuildValue("i" , instanceID);

    return ret;
}

static PyObject* paeks17_encrypt(PyObject *self , PyObject *args)
{
    PyObject *ret;
    
    char* keyword;
    int instanceID, keyword_len;

    if(!PyArg_ParseTuple(args , "is#" , &instanceID, &keyword, &keyword_len))
    {
      return NULL;
    }        

    unsigned char Ca[G1_LEN],Cb[G2_LEN];

    paeks17_ins[instanceID]->encrypt(Ca, Cb, std::string(keyword,keyword_len));

    ret = (PyObject *)Py_BuildValue("y#y#" , Ca, G1_LEN, Cb, G2_LEN);

    return ret;
}

static PyObject* paeks17_trapdoor(PyObject *self , PyObject *args)
{
    PyObject *ret;

    int instanceID;
    char* keyword;
    int keyword_len;

    if(!PyArg_ParseTuple(args , "is#" , &instanceID, &keyword,&keyword_len))
    {
      return NULL;
    }      


    unsigned char Tw[GT_LEN];

    paeks17_ins[instanceID]->trapdoor(Tw, std::string(keyword,keyword_len));


    ret = (PyObject *)Py_BuildValue("y#", Tw, GT_LEN);

    return ret;

}

static PyObject* paeks17_test(PyObject *self , PyObject *args)
{
    PyObject *ret;
    unsigned char *Tw, *Ca, *Cb;
    int Tw_l,Ca_l,Cb_l;
    int instanceID;

    if(!PyArg_ParseTuple(args , "iy#y#y#" , &instanceID, &Tw, &Tw_l, &Ca, &Ca_l, &Cb, &Cb_l))
    {
      return NULL;
    }      


    int result = paeks17_ins[instanceID]->test(Tw, Ca, Cb); 


    ret = (PyObject *)Py_BuildValue("i", result);

    return ret;
}

static PyObject* paeks17_importkey(PyObject *self , PyObject *args)
{
    PyObject *ret;
    unsigned char *pk, *sk;
    int instanceID;
    int pk_l,sk_l;

    if(!PyArg_ParseTuple(args , "iy#y#" , &instanceID, &pk, &pk_l, &sk, &sk_l))
    {
      return NULL;
    }

    int result = paeks17_ins[instanceID]->importkey(pk,sk);      

    ret = (PyObject *)Py_BuildValue("i", result);

    return ret;
}

static PyObject* paeks17_exportkey(PyObject *self , PyObject *args)
{
    PyObject *ret;
    unsigned char pk[G1_LEN],sk[Zr_LEN];
    int instanceID;

    if(!PyArg_ParseTuple(args , "i" , &instanceID))
    {
      return NULL;
    }    

    int result = paeks17_ins[instanceID]->exportkey(pk,sk);

    ret = (PyObject *)Py_BuildValue("y#y#" , pk, G1_LEN, sk, Zr_LEN);

    return ret;
}

static PyMethodDef
Paeks17_methods[] = {
    {"setup" , paeks17_setup, METH_VARARGS},
    {"encrypt" , paeks17_encrypt , METH_VARARGS},
    {"trapdoor" , paeks17_trapdoor, METH_VARARGS},
    {"test" , paeks17_test,METH_VARARGS},
    {"importkey" , paeks17_importkey,METH_VARARGS},
    {"exportkey",paeks17_exportkey,METH_VARARGS},
    {0, 0, 0},
};

static struct PyModuleDef
Paeks17_mod = {
    PyModuleDef_HEAD_INIT,
    "Paeks17_mod",
    "",
    -1,
    Paeks17_methods,
    NULL,
    NULL,
    NULL,
    NULL
};


PyMODINIT_FUNC PyInit_Paeks17_mod(void)
{
    return PyModule_Create(&Paeks17_mod);
}
