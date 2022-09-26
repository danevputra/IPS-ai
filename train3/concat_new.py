import csv
import sys
import pandas as pd

csv.field_size_limit(sys.maxsize)

def clean_sqli_data(data):
    
    for i in range(len(data)):
        
        data[i]=data[i].replace('\n', '')
        data[i]=data[i].replace('%20', ' ')
        data[i]=data[i].replace('=', ' = ')
        data[i]=data[i].replace('((', ' (( ')
        data[i]=data[i].replace('))', ' )) ')
        data[i]=data[i].replace('(', ' ( ')
        data[i]=data[i].replace(')', ' ) ')
        data[i]=data[i].replace('>', ' > ')
        data[i]=data[i].replace('/>', ' / > ')
        data[i]=data[i].replace('<', ' < ')
        data[i]=data[i].replace('|', ' | ')
        data[i]=data[i].replace('||', ' | | ')
        data[i]=data[i].replace('&', ' & ')
        data[i]=data[i].replace('&&', ' & & ')
        data[i]=data[i].replace(';', ' ; ')
        data[i]=data[i].replace('../', ' . . / ')
        data[i]=data[i].replace('\\..', ' \\ . . ')
        data[i]=data[i].replace(':/', ' : / ')
        data[i]=data[i].replace(':\\', ' : \\ ')
        data[i]=data[i].replace('/', ' / ')
        data[i]=data[i].replace('://', ' : / / ')
        data[i]=data[i].replace(':\\', ' : \\ ')
        data[i]=data[i].replace('\\', ' \\ ')
        data[i]=data[i].replace('\\\\&', ' \\ \\ & ')
        data[i]=data[i].replace('{{', ' { { ')
        data[i]=data[i].replace('{{[', ' { { [ ')
        data[i]=data[i].replace('[', ' [ ')
        data[i]=data[i].replace(']', ' ] ')
        data[i]=data[i].replace('{', ' { ')
        data[i]=data[i].replace('{%', ' { % ')
        data[i]=data[i].replace('{$', ' { $ ')
        data[i]=data[i].replace('}', ' } ')
        data[i]=data[i].replace('.', ' . ')
        data[i]=data[i].replace(',', ' ')
    
    return data

threshold = 1
below = 0
equal = 0
file_name = "sqli3.csv"

benign_data=[]
attack_data=[]

reader = pd.read_csv(file_name,encoding='utf-8')
reader = reader.reset_index()
for index, row in reader.iterrows():
    val = row['Label']
    isi = row['Sentence']
    if (val < threshold) and (below<25000) and (isi!=""):
        below += 1
        benign_data.append(isi)
    elif val == threshold and (equal<18362) and (isi!=""):
        equal += 1
        attack_data.append(isi)

path='user-agents.txt'

crlf_dataset=[]
f = open(path, "r", encoding='utf8')
for x in f:
    crlf_dataset.append(x)

crlf_dataset=clean_sqli_data(crlf_dataset)

for k in crlf_dataset:
    benign_data.append(k)

print(f"{below:,} below")
print(f"{equal:,} equal")
print("benign : ", str(len(benign_data)))
print("attack : ", str(len(attack_data)))

value = []

for i in benign_data :
    value.append((i,0))

for j in attack_data :
    value.append((j,1))

df=pd.DataFrame(value,columns=['Sentence','Label'])
df.drop_duplicates(subset=['Sentence'])
df.to_csv('sqli4.csv', index=False, encoding='utf-8')