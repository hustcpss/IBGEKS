import json
import os
import sys
import time
import Paeks20_mod
import Paeks17_mod
import Peks_mod
import SAPeks_mod
import Ibgeks_mod
import pdb


group_sender_name_instance_map = dict() # group||senders -> instance_id
group_sender_name_cnt = 0
name_map_group = dict()
name_map_group_rev = dict()


PAEKS17_group_cipher = dict()
PAEKS17_rPub = 0
PAEKS17_rPri = 0

PAEKS20_group_cipher = dict()
PAEKS20_rPub = 0
PAEKS20_rPri = 0


group_name_list = list()
group_name_keyword = dict()

group_name_instance_map = dict()
group_name_instance_cnt = 0

IBGEKS_group_cipher = dict()
group_sender_name_gsk_map = dict()
IBGEKS_rPri = 0

PEKS_group_cipher = dict()
PEKS_rPub = 0
PEKS_rPri = 0

SAPeks_group_cipher = dict()
SAPeks_rPub = 0
SAPeks_rPri = 0

def process_file(file_path):
	global group_name_instance_cnt, group_sender_name_cnt
	global PAEKS17_rPub,PAEKS17_rPri,IBGEKS_rPri,PEKS_rPub, PEKS_rPri,PAEKS20_rPub, PAEKS20_rPri, SAPeks_rPri, SAPeks_rPub
	global group_sender_name_instance_map, name_map_group, group_name_list,group_name_instance_map
	global PAEKS17_group_cipher,PAEKS20_group_cipher,IBGEKS_group_cipher,group_sender_name_gsk_map,PEKS_group_cipher, SAPeks_group_cipher
	global group_name_keyword

	with open(file_path, 'r', encoding='ASCII') as file:
		content = file.read()
		file_dict = json.loads(content)

		group_name = hash(file_dict['Group'])

		if group_name not in group_name_list:

			#Ibgeks and peks for group-level so ini at this stage
			group_name_list.append(group_name)
			group_name_instance_cnt = group_name_instance_cnt + 1
			group_name_keyword[group_name] = dict()

			group_name_instance_map[group_name] = group_name_instance_cnt


			PEKS_group_cipher[group_name] = []
			PAEKS17_group_cipher[group_name] = []
			PAEKS20_group_cipher[group_name] = []
			IBGEKS_group_cipher[group_name] = []
			SAPeks_group_cipher[group_name] = []

			Ibgeks_mod.setup(group_name_instance_cnt)
			Peks_mod.setup(group_name_instance_cnt)
			SAPeks_mod.setup(group_name_instance_cnt)

			Ibgeks_mod.importkey(group_name_instance_cnt,IBGEKS_rPri)
			Peks_mod.importkey(group_name_instance_cnt,PEKS_rPub,PEKS_rPri)
			SAPeks_mod.importkey(group_name_instance_cnt,SAPeks_rPub,SAPeks_rPri)

		#get the group-level instanceid
		group_instanceid = group_name_instance_map[group_name]


		group_sender_name = hash(file_dict['Group']+file_dict['From'])
		if group_sender_name not in group_sender_name_instance_map:

			group_sender_name_cnt = group_sender_name_cnt+1
			group_sender_name_instance_map[group_sender_name] = group_sender_name_cnt
			
			Paeks17_mod.setup(group_sender_name_cnt)
			Paeks20_mod.setup(group_sender_name_cnt)


			Paeks17_mod.importkey(group_sender_name_cnt,PAEKS17_rPub,PAEKS17_rPri)
			Paeks20_mod.importkey(group_sender_name_cnt,PAEKS20_rPub,PAEKS20_rPri)

			#join sender

			Ibgeks_mod_tt = time.time()

			gsk = Ibgeks_mod.join(group_instanceid,str(group_sender_name))

			Ibgeks_mod_td = time.time()

			group_sender_name_gsk_map[group_sender_name] = gsk


			# inverted index
			name_map_group[group_sender_name_cnt] = group_instanceid



		groupsender_instanceid = group_sender_name_instance_map[group_sender_name]


		for subject_keyword in file_dict['Subject']:
			if subject_keyword not in group_name_keyword[group_name]:
				group_name_keyword[group_name][subject_keyword] = 0

			group_name_keyword[group_name][subject_keyword]+=1


		#PAEKS17 cipher

		Paeks17_mod_tt = time.time()

		Cipherlist = [Paeks17_mod.encrypt(groupsender_instanceid, i) for i in file_dict['Subject']]		

		Paeks17_mod_td = time.time()

		PAEKS17_group_cipher[group_name].extend(Cipherlist)

		#PAEKS20 cipher

		Paeks20_mod_tt = time.time()

		Cipherlist = [Paeks20_mod.encrypt(groupsender_instanceid, i) for i in file_dict['Subject']]

		Paeks20_mod_td = time.time()

		PAEKS20_group_cipher[group_name].extend(Cipherlist)

		#IBGEKS cipher

		Ibgeks_mod_tt = time.time()

		group_sender_name_str = str(group_sender_name)
		gsk = group_sender_name_gsk_map[group_sender_name]

		Cipherlist = [Ibgeks_mod.encrypt(group_instanceid, i , 
			group_sender_name_str, gsk)
			for i in file_dict['Subject']
		]

		Ibgeks_mod_td = time.time()

		IBGEKS_group_cipher[group_name].extend(Cipherlist)
		# PEKS cipher


		Peks_mod_tt = time.time()
		
		Cipherlist = [Peks_mod.encrypt(group_instanceid, i) for i in file_dict['Subject']]

		Peks_mod_td = time.time()

		PEKS_group_cipher[group_name].extend(Cipherlist)


		SAPeks_mod_tt = time.time()

		Cipherlist = [SAPeks_mod.encrypt(group_instanceid, i) for i in file_dict['Subject']]

		SAPeks_mod_td = time.time()

		SAPeks_group_cipher[group_name].extend(Cipherlist)


		return Peks_mod_td-Peks_mod_tt, Paeks17_mod_td - Paeks17_mod_tt, Paeks20_mod_td - Paeks20_mod_tt, Ibgeks_mod_td - Ibgeks_mod_tt, SAPeks_mod_td - SAPeks_mod_tt


def find_the_highest_keyword_in_group(group_name):

	global group_name_keyword

	d = group_name_keyword[group_name]
	l = list(sorted(d.items(), key=lambda item: item[1], reverse=True))
	return l[0][0]


def find_group_name_ins_from_group_name(name_map_group,group_ins):

	result = []
	for test in name_map_group:
		if name_map_group[test] == group_ins:
			result.append(test)

	return result

def get_name_map_group_rev():

	global name_map_group,name_map_group_rev

	for key,value in name_map_group.items():
		if value not in name_map_group_rev:
			name_map_group_rev[value] = []

		name_map_group_rev[value].append(key)

	# pdb.set_trace()

def find_the_cipher_ins(group_name):
	global group_sender_name_instance_map, group_name_list,group_name_instance_map, name_map_group_rev

	global PAEKS17_group_cipher,PAEKS20_group_cipher,IBGEKS_group_cipher,PEKS_group_cipher, SAPeks_group_cipher

	PEKS_cc = PEKS_group_cipher[group_name]
	PAEKS17_cc = PAEKS17_group_cipher[group_name]
	PAEKS20_cc = PAEKS20_group_cipher[group_name]
	IBGEKS_cc = IBGEKS_group_cipher[group_name]
	SAPeks_cc = SAPeks_group_cipher[group_name]

	PEKS_ins = [group_name_instance_map[group_name],]
	IBGEKS_ins = [group_name_instance_map[group_name]]
	SAPeks_ins = [group_name_instance_map[group_name]]

	ins_col = name_map_group_rev[PEKS_ins[0]]

	PAEKS17_ins = ins_col
	PAEKS20_ins = ins_col

	return [PEKS_cc,IBGEKS_cc,PAEKS17_cc,PAEKS20_cc,SAPeks_cc], [PEKS_ins,IBGEKS_ins,PAEKS17_ins,PAEKS20_ins,SAPeks_ins]

def test_each_instance_on_their_encrypted_data(keyword, cipher_col,ins_col):

	[PEKS_cc,IBGEKS_cc,PAEKS17_cc,PAEKS20_cc,SAPeks_cc], [PEKS_ins,IBGEKS_ins,PAEKS17_ins,PAEKS20_ins,SAPeks_ins] = cipher_col, ins_col

	Peks_minor = 0
	Peks_comm = 0
	Peks_mod_tt = time.time()
	for ins in PEKS_ins:
		tm = time.time()
		Tw = Peks_mod.trapdoor(ins, keyword)
		Peks_minor+= time.time() - tm
		Peks_comm += len(Tw)
		for  Ca, Cb in PEKS_cc:
			test_re = Peks_mod.test(ins,Tw,Ca,Cb)
	Peks_mod_td = time.time()

	SAPeks_minor = 0
	SAPeks_comm = 0
	SAPeks_mod_tt = time.time()
	for ins in SAPeks_ins:
		tm = time.time()
		Tw = SAPeks_mod.trapdoor(ins, keyword)
		SAPeks_minor += time.time() - tm
		SAPeks_comm += len(Tw) 
		for Ca, Cb in SAPeks_cc:
			test_re = SAPeks_mod.test(ins,Tw,Ca,Cb)
	SAPeks_mod_td = time.time()

	Ibgeks_minor = 0

	Ibgeks_comm = 0

	Ibgeks_mod_tt = time.time()

	for ins in IBGEKS_ins:

		tm = time.time()

		Tw = Ibgeks_mod.trapdoor(ins,keyword)

		Ibgeks_minor+= time.time() - tm

		Ibgeks_comm += len(Tw)

		for Ca,Cb in IBGEKS_cc:

			test_re = Ibgeks_mod.test(ins,Tw,Ca,Cb)

	Ibgeks_mod_td = time.time()

	Paeks17_minor = 0

	Paeks17_comm = 0

	Paeks17_mod_tt = time.time()

	for ins in PAEKS17_ins:

		tm = time.time()

		Tw = Paeks17_mod.trapdoor(ins,keyword)

		Paeks17_minor+= time.time()-tm

		Paeks17_comm+= len(Tw)

		for Ca,Cb in PAEKS17_cc:

			test_re = Paeks17_mod.test(ins,Tw,Ca,Cb)

	Paeks17_mod_td= time.time()

	Paeks20_minor = 0

	Paeks20_comm = 0

	Paeks20_mod_tt = time.time()

	for ins in PAEKS20_ins:

		tm = time.time()

		Tw = Paeks20_mod.trapdoor(ins,keyword)

		Paeks20_minor+= time.time() - tm

		Paeks20_comm += len(Tw)

		for Ca, Cb in PAEKS20_cc:

			test_re = Paeks20_mod.test(ins,Tw,Ca,Cb)

	Paeks20_mod_td = time.time()

	return [len(PAEKS17_cc),len(PAEKS17_ins)],[Peks_mod_td-Peks_mod_tt, Paeks17_mod_td - Paeks17_mod_tt, Paeks20_mod_td - Paeks20_mod_tt, Ibgeks_mod_td - Ibgeks_mod_tt, SAPeks_mod_td- SAPeks_mod_tt,  Peks_minor, Paeks17_minor, Paeks20_minor, Ibgeks_minor, SAPeks_minor],[Peks_comm,Ibgeks_comm,Paeks17_comm,Paeks20_comm, SAPeks_comm]

def search_group_name(group_name):

	keyword = find_the_highest_keyword_in_group(group_name)

	cipher_col,ins_col = find_the_cipher_ins(group_name)

	# pdb.set_trace()

	para,time_cost,com_cost = test_each_instance_on_their_encrypted_data(keyword,cipher_col,ins_col)

	delay = 0.023

	delay_time_cost = [i+delay for i in time_cost[0:5]]

	print(group_name,'\t',para[0],'\t',para[1],
		'\t',time_cost[0],'\t',time_cost[1],'\t',time_cost[2],'\t',time_cost[3],'\t',time_cost[4],
		'\t',time_cost[5],'\t',time_cost[6],'\t',time_cost[7],'\t',time_cost[8],'\t',time_cost[9],
		'\t',com_cost[0],'\t',com_cost[1],'\t',com_cost[2],'\t',com_cost[3],'\t',com_cost[4],
		'\t',delay_time_cost[0],'\t',delay_time_cost[1],'\t',delay_time_cost[2],'\t',delay_time_cost[3],'\t',delay_time_cost[4])


def process_files_in_folder(folder_path):
	global PAEKS17_rPub,PAEKS17_rPri,IBGEKS_rPri,PEKS_rPub, PEKS_rPri,PAEKS20_rPub, PAEKS20_rPri,SAPeks_rPri,SAPeks_rPub
	global group_name_list


	Paeks17_mod.setup(0)
	PAEKS17_rPub,PAEKS17_rPri = Paeks17_mod.exportkey(0)

	Paeks20_mod.setup(0)
	PAEKS20_rPub, PAEKS20_rPri = Paeks20_mod.exportkey(0)

	Ibgeks_mod.setup(0)
	IBGEKS_rPri = Ibgeks_mod.exportkey(0)

	Peks_mod.setup(0)
	PEKS_rPub, PEKS_rPri = Peks_mod.exportkey(0)

	SAPeks_mod.setup(0)
	SAPeks_rPub,SAPeks_rPri = SAPeks_mod.exportkey(0)


	print('---------------I am creating ciphertext in group--------------------')
	print('test:\tPEKS\tPAEKS17\tPAEKS20\tIBGEKS\tSA-PEKS')


	for root, dirs, files in os.walk(folder_path):

		Peks_mod_enc_time = 0
		Paeks17_mod_enc_time = 0
		Paeks20_mod_enc_time = 0
		Ibgeks_mod_enc_time = 0
		SAPeks_mod_enc_time = 0

		Ibgeks_mod_join_time = 0
		for file_name in files:
			file_path = os.path.join(root, file_name)
			ft_peks,ft_paeks17,ft_paeks20,ft_ibgeks,ft_sapeks = process_file(file_path)
			Peks_mod_enc_time = Peks_mod_enc_time+ft_peks
			Paeks17_mod_enc_time = Paeks17_mod_enc_time+ ft_paeks17
			Paeks20_mod_enc_time = Paeks20_mod_enc_time+ ft_paeks20
			Ibgeks_mod_enc_time = Ibgeks_mod_enc_time + ft_ibgeks
			SAPeks_mod_enc_time = SAPeks_mod_enc_time + ft_sapeks
		print(root,'\t',Peks_mod_enc_time,'\t',Paeks17_mod_enc_time,'\t',Paeks20_mod_enc_time,'\t',Ibgeks_mod_enc_time,'\t',SAPeks_mod_enc_time)

	get_name_map_group_rev()

	print('---------------I am searching the keyword in group--------------------')
	print('test:\tcipherts_len\tsender_num\tPEKS\tPAEKS17\tPAEKS20\tIBGEKS\tSA-PEKS\tPEKS-T\tPAEKS17-T\tPAEKS20-T\tIBGEKS-T\tSA-PEKS-T')

	for group_name in group_name_list:
		search_group_name(group_name)


if __name__ == '__main__':

	folder_path = str(sys.argv[1])
	process_files_in_folder(folder_path)
