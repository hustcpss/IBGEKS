import os
import re
import nltk
import json
import pdb
from nltk.tokenize import RegexpTokenizer
from nltk.corpus import stopwords

def analysis(root,file_path):
    
    print(file_path)
    data = []
    with open(file_path, 'r', encoding='ASCII') as file:
        content = file.read()
        data = json.loads(content)
        data['Subject'] = [data['Subject'][2]]

    with open(file_path,'w', encoding = 'ASCII') as file:
        json.dump(data,file)



def process_files_in_folder(folder_path):
    # 遍历文件夹中的所有文件
    for root, dirs, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            analysis(root,file_path)

if __name__ == "__main__":

    folder_path = "./rawdata"  # 替换为实际文件夹路径
    process_files_in_folder(folder_path)
