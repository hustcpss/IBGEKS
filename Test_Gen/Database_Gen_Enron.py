#coding=utf-8

import sys
import pymongo
import random
import string
import numpy as np
import pdb

keywords_space = []

def Setup_DB(test_db_name):
		global myclient,mydb,mydata,mytask_search,mytask_derive,myrawinput
		myclient = pymongo.MongoClient("mongodb://localhost:27017/")
		mydb = myclient[test_db_name]
		myrawdb = myclient[""]
		myrawinput = myrawdb["id_keywords"]
		mydata = mydb["id_keywords"]
		mytask_search = mydb["search"]
		mytask_derive = mydb["derive"]
		mydata.drop() 
		mytask_search.drop()
		mytask_derive.drop()

def Write_seq_search():
		global mytask_search,keywords_space,keywords_num_min
		print('data_scale      ' , data_scale)
		print('keywords_space  ' , len(keywords_space))
		search_list = keywords_space
		mytask_search.insert_one({"search_set":search_list})

def Write_data(data_scale):
		global mydata,myrawinput,keywords_space
		insert_list = []
		cnt = 0
		bt = 0
		kid = 0
		for x in myrawinput.find():
			keywords_list = []
			for raw_key in x["keywords_set"]:
				if raw_key[1] > 0: # the tf-idf only split the every time format data
					keywords_list.append(str(hash(raw_key[0])))
					keywords_space.append(str(hash(raw_key[0])))
			if len(keywords_list) == 0:
				bt+= 1
			else:
				insert_list.append({"fileid":'F'+str(cnt),"keywords_set":keywords_list})
				cnt = cnt + 1
				if cnt != 0 and cnt% 1000 == 0:
					mydata.insert_many(insert_list)
					insert_list = []
				if cnt == data_scale:
					break
		print('broke file', bt)
		if len(insert_list) > 0:
			mydata.insert_many(insert_list)
		keywords_space = list(set(keywords_space))
def Write_seq_derive(data_scale):
		global mytask_derive,mydata,keywords_space
		sample_list = ['F'+str(i) for i in range(data_scale)]
		derive_list = sample_list
		mytask_derive.insert({"derive_set":derive_list})

if __name__ == "__main__":
		test_db_name = str(sys.argv[1])
		data_scale = int(sys.argv[2])
		Setup_DB(test_db_name)
		Write_data(data_scale)
		Write_seq_derive(data_scale)
		Write_seq_search()
		








