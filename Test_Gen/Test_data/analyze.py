import os
import re
import nltk
import json
from nltk.tokenize import RegexpTokenizer
from nltk.corpus import stopwords

def analysis(root,file_path):
    
    cnt = 0
    cnt_1 = 0
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()
        data = json.loads(content)
        cnt += len(data['Subject'])
        cnt_1 += len(data['From'])

    return cnt


def process_files_in_folder(folder_path):
    # 遍历文件夹中的所有文件
    for root, dirs, files in os.walk(folder_path):
        pair = 0
        for file_name in files:
            file_path = os.path.join(root, file_name)
            pair += analysis(root,file_path)

        print(root,'\t',pair)

if __name__ == "__main__":

    folder_path = "./rawdata"  # 替换为实际文件夹路径
    process_files_in_folder(folder_path)
