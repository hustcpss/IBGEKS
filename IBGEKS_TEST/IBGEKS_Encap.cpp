// IBGEKS_wrapper.cpp
#include <Python.h>
#include <map>
#include <cstring>
#include "IBGEKS.h"
using namespace std;

map <int, IBGEKS*> Ibgeks_ins;

static PyObject* Ibgeks_setup(PyObject *self , PyObject *args)
{
    PyObject *ret;

    int instanceID;

    if(!PyArg_ParseTuple(args , "i" , &instanceID))
    {
      return NULL;
    }   

    Ibgeks_ins[instanceID] = new IBGEKS();
    Ibgeks_ins[instanceID]->setup();

    ret = (PyObject *)Py_BuildValue("i" , instanceID);

    return ret;
}

static PyObject* Ibgeks_join(PyObject *self , PyObject *args)
{
	PyObject *ret;
	char *ID;
	int ID_len,instanceID;

  if(!PyArg_ParseTuple(args , "is#" , &instanceID, &ID, &ID_len))
  {
    return NULL;
  }    

  unsigned char gsk[G1_LEN];

  Ibgeks_ins[instanceID]->join(gsk, std::string(ID,ID_len));

  ret = (PyObject *)Py_BuildValue("y#" , gsk, G1_LEN);

  return ret;

}


static PyObject* Ibgeks_encrypt(PyObject *self , PyObject *args)
{
    PyObject *ret;
    
    char *keyword, *ID;
    unsigned char *gsk;
    int instanceID, ID_len, keyword_len,gsk_len;

    if(!PyArg_ParseTuple(args , "is#s#y#" , &instanceID, &keyword, &keyword_len,&ID, &ID_len, &gsk, &gsk_len))
    {
      return NULL;
    }        

    unsigned char Ca[G1_LEN],Cb[HASH_LEN];

    Ibgeks_ins[instanceID]->encrypt(Ca, Cb, std::string(keyword,keyword_len),std::string(ID,ID_len), gsk);

    ret = (PyObject *)Py_BuildValue("y#y#" , Ca, G1_LEN, Cb, HASH_LEN);

    return ret;
}

static PyObject* Ibgeks_trapdoor(PyObject *self , PyObject *args)
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

    Ibgeks_ins[instanceID]->trapdoor(Tw, std::string(keyword,keyword_len));


    ret = (PyObject *)Py_BuildValue("y#", Tw, G1_LEN);

    return ret;

}

static PyObject* Ibgeks_test(PyObject *self , PyObject *args)
{
    PyObject *ret;
    unsigned char *Tw, *Ca, *Cb;
    int Tw_l,Ca_l,Cb_l;
    int instanceID;

    if(!PyArg_ParseTuple(args , "iy#y#y#" , &instanceID, &Tw, &Tw_l, &Ca, &Ca_l, &Cb, &Cb_l))
    {
      return NULL;
    }      


    int result = Ibgeks_ins[instanceID]->test(Tw, Ca, Cb); 


    ret = (PyObject *)Py_BuildValue("i", result);

    return ret;
}

static PyObject* Ibgeks_importkey(PyObject *self , PyObject *args)
{
    PyObject *ret;
    unsigned char *sk;
    int instanceID;
    int sk_l;

    if(!PyArg_ParseTuple(args , "iy#" , &instanceID, &sk, &sk_l))
    {
      return NULL;
    }

    int result = Ibgeks_ins[instanceID]->importkey(sk);      

    ret = (PyObject *)Py_BuildValue("i", result);

    return ret;
}

static PyObject* Ibgeks_exportkey(PyObject *self , PyObject *args)
{
    PyObject *ret;
    unsigned char sk[Zr_LEN];
    int instanceID;

    if(!PyArg_ParseTuple(args , "i" , &instanceID))
    {
      return NULL;
    }    

    int result = Ibgeks_ins[instanceID]->exportkey(sk);

    ret = (PyObject *)Py_BuildValue("y#", sk, Zr_LEN);

    return ret;
}

static PyMethodDef
Ibgeks_methods[] = {
    {"setup" , Ibgeks_setup, METH_VARARGS},
    {"encrypt" , Ibgeks_encrypt , METH_VARARGS},
    {"trapdoor" , Ibgeks_trapdoor, METH_VARARGS},
    {"join" , Ibgeks_join, METH_VARARGS},
    {"test" , Ibgeks_test,METH_VARARGS},
    {"importkey" , Ibgeks_importkey,METH_VARARGS},
    {"exportkey",Ibgeks_exportkey,METH_VARARGS},
    {0, 0, 0},
};

static struct PyModuleDef
Ibgeks_mod = {
    PyModuleDef_HEAD_INIT,
    "Ibgeks_mod",
    "",
    -1,
    Ibgeks_methods,
    NULL,
    NULL,
    NULL,
    NULL
};


PyMODINIT_FUNC PyInit_Ibgeks_mod(void)
{
    return PyModule_Create(&Ibgeks_mod);
}
