import os
import re
import nltk
import json
from nltk.tokenize import RegexpTokenizer
from nltk.corpus import stopwords


def is_json(data):
    try:
        json.loads(data)
        return True
    except ValueError as e:
        return False

def extract_and_replace(root,file_path):

    stop_words = set(stopwords.words('english'))

    print(file_path)


    with open(file_path, 'r', encoding='ASCII') as file:
        content = file.read()

    if is_json(content):
        return

    keyword_match = re.search(r'Date: (.+)', content)

    if keyword_match:
        from_content = file_path
        subject_content = keyword_match.group(1).strip()

        tokenizer = RegexpTokenizer(r'\w+')
        tokens = tokenizer.tokenize(subject_content)


        filtered_words = [token.lower() for token in tokens if token.lower() not in stop_words]

        group = root

        data = {"Group": group, "From": from_content, "Subject": filtered_words}

        with open(file_path, 'w', encoding='ASCII') as new_file:
            json.dump(data, new_file)
    else:
        os.remove(file_path)



def process_files_in_folder(folder_path):
    # 遍历文件夹中的所有文件
    for root, dirs, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            extract_and_replace(root,file_path)

if __name__ == "__main__":

    # nltk.download('stopwords')
    # nltk.download('punkt')

    folder_path = "./rawdata"  # 替换为实际文件夹路径
    process_files_in_folder(folder_path)
