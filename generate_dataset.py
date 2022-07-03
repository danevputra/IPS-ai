# import required packages
import pandas as pd
import os
import math
import nltk
nltk.download('stopwords')
from nltk.corpus import stopwords 

# preprocess sql data to have same format for all files

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
    
    return data

#crlf_dataset
path='dataset/crlf.txt'

crlf_dataset=[]
f = open(path, "r", encoding='utf8')
for x in f:
    crlf_dataset.append(x)

crlf_dataset=clean_sqli_data(crlf_dataset)

#log4j_dataset
path='dataset/log4j.txt'

log4j_dataset=[]
f = open(path, "r", encoding='utf8')
for x in f:
    log4j_dataset.append(x)

log4j_dataset=clean_sqli_data(log4j_dataset)

#path_transversal
path='dataset/path_transversal.txt'

path_transversal_dataset=[]
f = open(path, "r", encoding='utf8')
for x in f:
    path_transversal_dataset.append(x)

path_transversal_dataset=clean_sqli_data(path_transversal_dataset)

#ssrf
path='dataset/ssrf.txt'

ssrf_dataset=[]
f = open(path, "r", encoding='utf8')
for x in f:
    ssrf_dataset.append(x)

ssrf_dataset=clean_sqli_data(ssrf_dataset)

#ssti
path='dataset/ssti.txt'

ssti_dataset=[]
f = open(path, "r", encoding='utf8')
for x in f:
    ssti_dataset.append(x)

ssti_dataset=clean_sqli_data(ssti_dataset)

#xss
path='dataset/xss.txt'

xss_dataset=[]
f = open(path, "r", encoding='utf8')
for x in f:
    xss_dataset.append(x)

xss_dataset=clean_sqli_data(xss_dataset)

#big_dataset
path='dataset/new_dataset_conv.txt'

big_dataset=[]
f = open(path, "r", encoding='utf8')
for x in f:
    big_dataset.append(x)

big_dataset=clean_sqli_data(big_dataset)

#os command injection
path='dataset/os_command_injection.txt'

os_command_injection =[]
f = open(path, "r", encoding='utf8')
for x in f:
    os_command_injection.append(x)

os_command_injection=clean_sqli_data(os_command_injection)

#sqli.txt
path='dataset/sqli.txt'

sql_lines_fuzzing=[]
f = open(path, "r")
for x in f:
    sql_lines_fuzzing.append(x)

sql_lines_fuzzing=clean_sqli_data(sql_lines_fuzzing)
# print(sql_lines_fuzzing[:15])

path='dataset/camoufl4g3.txt'

# read data from file

sql_lines_camoufl4g3=[]
f = open(path, "r")
for x in f:
    sql_lines_camoufl4g3.append(x)

# print(sql_lines_camoufl4g3[:15])

sql_lines_camoufl4g3=clean_sqli_data(sql_lines_camoufl4g3)

# print(sql_lines_camoufl4g3[:15]) # data after cleaning

path='dataset/libinjection-bypasses.txt'

# read data from file

sql_lines_bypasses=[]
f = open(path, "r")
for x in f:
    sql_lines_bypasses.append(x)

# print(sql_lines_bypasses[:5])# before cleaning
# print(len(sql_lines_bypasses))

sql_lines_bypasses=clean_sqli_data(sql_lines_bypasses)

# print(sql_lines_bypasses[:5])

# if don't want &(*)* sign in beginning of each sentence then run next code else don't

for i in range(len(sql_lines_bypasses)):
    sentence=sql_lines_bypasses[i]
    sql_lines_bypasses[i]=sentence.split(':')[1]

# print(sql_lines_bypasses[:5])

path='dataset/sqli2.txt'

# read data from file

sql_lines_owasp=[]
f = open(path, "r")
for x in f:
    sql_lines_owasp.append(x)

# print(len(sql_lines_owasp))

sql_lines_owasp=clean_sqli_data(sql_lines_owasp)
# print(sql_lines_owasp[0:15])

path='dataset/Generic-SQLi.txt'
# read data from file

sql_lines_Generic=[]
f = open(path, "r")
for x in f:
    sql_lines_Generic.append(x)

# print(len(sql_lines_Generic))

sql_lines_Generic=clean_sqli_data(sql_lines_Generic)

# print(sql_lines_Generic[:15])

stop_words = set(stopwords.words('english')) 

def fun_remove_stop_words(posts):

    filtered=''
    
    for x in posts.split(' '):
        if x not in stop_words:
            filtered+=' '+x
    
    return filtered

path='dataset/'
file='plain.txt'

#read benign data

df = pd.read_csv(os.path.join(path,file), sep='Aw3s0meSc0t7', names=['benign'], header=None, engine='python')
df.head()

plain_text=df['benign'].values  # get sentences
# print(plain_text[:5])
plain_text=plain_text[:-22]
# print(len(plain_text))

# convert from list to string

data=''
for x in plain_text:
    data+=" " + x

# print(type(data))

data=fun_remove_stop_words(data)  # remove stop words
data=data.split('.')              # split sentences

# seperate words inside tags

for i in range(len(data)):
    data[i]=data[i].replace('<', ' <')
    data[i]=data[i].replace('>', '> ')
    data[i]=data[i].replace('=', ' = ')

# print(data[:5])

# print("Benign records: %2i" %len(data))

# read self created benign data

# read self created benign data

path='dataset/benign_for_training.txt'
benign_data=[]
f = open(path, "r", encoding="utf8")
for x in f:
    benign_data.append(x)

# read self created sqli data

path='dataset/sqli_for_training.txt'
sqli_data=[]
f = open(path, "r", encoding="utf8")
for x in f:
    sqli_data.append(x)

# print(len(benign_data))

benign_sentence=[]
for i in benign_data:
    sentences=i.split('.')
    
    for sentence in sentences:
        benign_sentence.append(sentence)

sqli_data = clean_sqli_data(sqli_data)
benign_sentence = clean_sqli_data(benign_sentence)

# print("total benign data : " ,len(benign_sentence)+len(data))

# print(f"SQL fuzzing : {len(sql_lines_fuzzing)}  camoufl4gs : {len(sql_lines_camoufl4g3)} parsed : {len(sql_lines_bypasses)} owasp : {len(sql_lines_owasp)} generic : {len(sql_lines_Generic)}")

all_sqli_sentence=sql_lines_owasp+sql_lines_bypasses+sql_lines_camoufl4g3+sql_lines_fuzzing+sql_lines_Generic+xss_dataset+os_command_injection+crlf_dataset+log4j_dataset+path_transversal_dataset+ssrf_dataset+ssti_dataset+big_dataset

# replace numeric values by a keyword 'numeric'
def optional_numeric_to_numeric(all_sqli_sentence):
    
    for i in range(len(all_sqli_sentence)):
        

        all_sqli_sentence[i]=all_sqli_sentence[i].replace('1 ', 'numeric')
        all_sqli_sentence[i]=all_sqli_sentence[i].replace(' 1', 'numeric')
        all_sqli_sentence[i]=all_sqli_sentence[i].replace("'1 ", "'numeric ")
        all_sqli_sentence[i]=all_sqli_sentence[i].replace(" 1'", " numeric'")
        all_sqli_sentence[i]=all_sqli_sentence[i].replace('1,', 'numeric,')
        all_sqli_sentence[i]=all_sqli_sentence[i].replace("1\ ", 'numeric')
        all_sqli_sentence[i]=all_sqli_sentence[i].replace("‘1", '‘numeric')
        all_sqli_sentence[i]=all_sqli_sentence[i].replace(" 2 ", " numeric ")
        all_sqli_sentence[i]=all_sqli_sentence[i].replace(' 3 ', ' numeric ')
        all_sqli_sentence[i]=all_sqli_sentence[i].replace(' 3--', ' numeric--')
        all_sqli_sentence[i]=all_sqli_sentence[i].replace(" 4 ", ' numeric ')
        all_sqli_sentence[i]=all_sqli_sentence[i].replace(" 5 ", ' numeric ')
        all_sqli_sentence[i]=all_sqli_sentence[i].replace(' 6 ', ' numeric ')
        all_sqli_sentence[i]=all_sqli_sentence[i].replace(" 7 ", ' numeric ')
        all_sqli_sentence[i]=all_sqli_sentence[i].replace(" 8 ", ' numeric ')
        all_sqli_sentence[i]=all_sqli_sentence[i].replace('1234', ' numeric ')
        all_sqli_sentence[i]=all_sqli_sentence[i].replace("22", ' numeric ')
        all_sqli_sentence[i]=all_sqli_sentence[i].replace(" 8 ", ' numeric ')
        all_sqli_sentence[i]=all_sqli_sentence[i].replace(" 200 ", ' numeric ')
        all_sqli_sentence[i]=all_sqli_sentence[i].replace("23 ", ' numeric ')
        all_sqli_sentence[i]=all_sqli_sentence[i].replace('"1', '"numeric')
        all_sqli_sentence[i]=all_sqli_sentence[i].replace('1"', '"numeric')
        all_sqli_sentence[i]=all_sqli_sentence[i].replace("7659", 'numeric')
        all_sqli_sentence[i]=all_sqli_sentence[i].replace(" 37 ", ' numeric ')
        all_sqli_sentence[i]=all_sqli_sentence[i].replace(" 45 ", ' numeric ')
    
    return all_sqli_sentence

print("data serangan : " + str(len(all_sqli_sentence+sqli_data)))
print("data benign : "+str(len(data+benign_sentence)))

# give labels to sql data

values=[]
for i in all_sqli_sentence:
    values.append((i,1))

# give labels to benign data

for i in data:
    values.append((i,0))

print(len(all_sqli_sentence)+len(data))

print(len(values))

for i in benign_sentence:
    if benign_sentence!="" :
        values.append((i,0))

for i in sqli_data:
    if sqli_data!="":
        values.append((i,1))

print(len(values))
print(values[1])

print("Serangan : "+ str(len(all_sqli_sentence)+len(sqli_data)))
print("Benign : "+ str(len(data)+len(benign_sentence)))

# convert to dataframe

df=pd.DataFrame(values,columns=['Sentence','Label'])
# print(df.head())

df.drop_duplicates(subset=['Sentence'])
df.to_csv('sqli.csv', index=False, encoding='utf-16')