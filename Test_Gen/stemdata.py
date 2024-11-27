import portstemmer
import os
import pdb
if __name__ == '__main__':
    rootdir = '../maildir'
    outputdir = './stem/'
    ls = os.listdir(rootdir)
    all_documents = ['all_documents']
    for i in range(0, len(ls)):
        path = os.path.join(rootdir, ls[i])
        for k in range(0,len(all_documents)):
            path = os.path.join(path,all_documents[k])
            if os.path.exists(path) == False:
                continue
            #pdb.set_trace()
            lspath = os.listdir(path) 
            for j in range(0,len(lspath)):
                filename = os.path.join(path,lspath[j])
                print(filename)
                if os.path.isfile(filename):
                    portstemmer.get_PorterStemmer(filename,outputdir+str(ls[i])+str(all_documents[k])+str(lspath[j])+'stem')
	
