// PAEKS20_wrapper.cpp
#include <Python.h>
#include <map>
#include <cstring>
#include "PAEKS20.h"
using namespace std;

map <int, PAEKS20*> Paeks20_ins;

static PyObject* Paeks20_setup(PyObject *self , PyObject *args)
{
    PyObject *ret;

    int instanceID;

    if(!PyArg_ParseTuple(args , "i" , &instanceID))
    {
      return NULL;
    }   

    Paeks20_ins[instanceID] = new PAEKS20();
    Paeks20_ins[instanceID]->setup();

    ret = (PyObject *)Py_BuildValue("i" , instanceID);

    return ret;
}

static PyObject* Paeks20_encrypt(PyObject *self , PyObject *args)
{
    PyObject *ret;
    
    char* keyword;
    int instanceID, keyword_len;

    if(!PyArg_ParseTuple(args , "is#" , &instanceID, &keyword, &keyword_len))
    {
      return NULL;
    }        

    unsigned char Ca[G1_LEN],Cb[HASH_LEN];

    Paeks20_ins[instanceID]->encrypt(Ca, Cb, std::string(keyword,keyword_len));

    ret = (PyObject *)Py_BuildValue("y#y#" , Ca, G1_LEN, Cb, HASH_LEN);

    return ret;
}

static PyObject* Paeks20_trapdoor(PyObject *self , PyObject *args)
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

    Paeks20_ins[instanceID]->trapdoor(Tw, std::string(keyword,keyword_len));


    ret = (PyObject *)Py_BuildValue("y#", Tw, G1_LEN);

    return ret;

}

static PyObject* Paeks20_test(PyObject *self , PyObject *args)
{
    PyObject *ret;
    unsigned char *Tw, *Ca, *Cb;
    int Tw_l,Ca_l,Cb_l;
    int instanceID;

    if(!PyArg_ParseTuple(args , "iy#y#y#" , &instanceID, &Tw, &Tw_l, &Ca, &Ca_l, &Cb, &Cb_l))
    {
      return NULL;
    }      


    int result = Paeks20_ins[instanceID]->test(Tw, Ca, Cb); 


    ret = (PyObject *)Py_BuildValue("i", result);

    return ret;
}

static PyObject* Paeks20_importkey(PyObject *self , PyObject *args)
{
    PyObject *ret;
    unsigned char *pk, *sk;
    int instanceID;
    int pk_l,sk_l;

    if(!PyArg_ParseTuple(args , "iy#y#" , &instanceID, &pk, &pk_l, &sk, &sk_l))
    {
      return NULL;
    }

    int result = Paeks20_ins[instanceID]->importkey(pk,sk);      

    ret = (PyObject *)Py_BuildValue("i", result);

    return ret;
}

static PyObject* Paeks20_exportkey(PyObject *self , PyObject *args)
{
    PyObject *ret;
    unsigned char pk[G2_LEN],sk[Zr_LEN];
    int instanceID;

    if(!PyArg_ParseTuple(args , "i" , &instanceID))
    {
      return NULL;
    }    

    int result = Paeks20_ins[instanceID]->exportkey(pk,sk);

    ret = (PyObject *)Py_BuildValue("y#y#" , pk, G2_LEN, sk, Zr_LEN);

    return ret;
}

static PyMethodDef
Paeks20_methods[] = {
    {"setup" , Paeks20_setup, METH_VARARGS},
    {"encrypt" , Paeks20_encrypt , METH_VARARGS},
    {"trapdoor" , Paeks20_trapdoor, METH_VARARGS},
    {"test" , Paeks20_test,METH_VARARGS},
    {"importkey" , Paeks20_importkey,METH_VARARGS},
    {"exportkey",Paeks20_exportkey,METH_VARARGS},
    {0, 0, 0},
};

static struct PyModuleDef
Paeks20_mod = {
    PyModuleDef_HEAD_INIT,
    "Paeks20_mod",
    "",
    -1,
    Paeks20_methods,
    NULL,
    NULL,
    NULL,
    NULL
};


PyMODINIT_FUNC PyInit_Paeks20_mod(void)
{
    return PyModule_Create(&Paeks20_mod);
}
