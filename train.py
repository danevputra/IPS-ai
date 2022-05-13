# import required packages

import glob
import time
import pandas as pd
# from xml.dom import minidom
from nltk import ngrams
from nltk.tokenize import sent_tokenize
import nltk
nltk.download('punkt')
nltk.download('stopwords')
nltk.download('wordnet')
from nltk.stem import PorterStemmer
from nltk.stem import PorterStemmer
from nltk.tokenize import sent_tokenize, word_tokenize
from nltk.stem import WordNetLemmatizer
from nltk.corpus import stopwords 
from nltk.tokenize import word_tokenize
import keras
import os

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
        # data[i]=data[i].replace('.', ' . ')
    
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

# print("total benign data : " ,len(benign_sentence)+len(data))

# print(f"SQL fuzzing : {len(sql_lines_fuzzing)}  camoufl4gs : {len(sql_lines_camoufl4g3)} parsed : {len(sql_lines_bypasses)} owasp : {len(sql_lines_owasp)} generic : {len(sql_lines_Generic)}")

all_sqli_sentence=sql_lines_owasp+sql_lines_bypasses+sql_lines_camoufl4g3+sql_lines_fuzzing+sql_lines_Generic+xss_dataset+os_command_injection+crlf_dataset+log4j_dataset+path_transversal_dataset+ssrf_dataset+ssti_dataset

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

print("data serangan : " + str(len(all_sqli_sentence)))
print("data benign : "+str(len(data)))


import pandas as pd

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
    values.append((i,0))

for i in sqli_data:
    values.append((i,1))

print(len(values))
print(values[1])

print("Serangan : "+ str(len(all_sqli_sentence)+len(sqli_data)))
print("Benign : "+ str(len(data)+len(benign_sentence)))

# convert to dataframe

df=pd.DataFrame(values,columns=['Sentence','Label'])
# print(df.head())

df.to_csv('sqli.csv', index=False, encoding='utf-16')
df=pd.read_csv('sqli.csv',encoding='utf-16')

# vectorization of data

from sklearn.feature_extraction.text import CountVectorizer
vectorizer = CountVectorizer( min_df=2, max_df=0.7, max_features=4096, stop_words=stopwords.words('english'))
posts = vectorizer.fit_transform(df['Sentence'].values.astype('U')).toarray()

print(posts.shape)

posts.shape=(23040,64,64,1)

X=posts
y=df['Label']

from sklearn.model_selection import train_test_split

# split train test data

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

trainX=X_train.copy()
trainX.shape=(X_train.shape[0],trainX.shape[1]*trainX.shape[2])
testX=X_test.copy()
testX.shape=(testX.shape[0],testX.shape[1]*testX.shape[2])


# ### NAIVE BAYES
# from sklearn.naive_bayes import GaussianNB
# gnb = GaussianNB()
# gnb.fit(trainX, y_train)
# pred_gnb = gnb.predict(testX)

# ### SVM
# from sklearn.svm import SVC
# clf = SVC(gamma='auto')
# clf.fit(trainX, y_train)
# pred_svm=clf.predict(testX)

# ### NEAREST NEIGHBOR
# from sklearn.neighbors import KNeighborsClassifier

# neigh = KNeighborsClassifier(n_neighbors=3)
# neigh.fit(trainX, y_train)

# pred_knn = neigh.predict(testX)

# ### DECISION TREE
# from sklearn import tree

# dt = tree.DecisionTreeClassifier()
# dt = dt.fit(trainX, y_train)

# pred_dt = dt.predict(testX)

# print(X_train.shape)

import tensorflow as tf
from keras.models import Sequential
from keras import layers
from keras.preprocessing.text import Tokenizer
from keras.wrappers.scikit_learn import KerasClassifier

model=tf.keras.models.Sequential([
    
    tf.keras.layers.Conv2D(64, (3,3), activation=tf.nn.relu, input_shape=(64,64,1)),
    tf.keras.layers.MaxPooling2D(2,2),
    
    tf.keras.layers.Conv2D(128,(3,3), activation=tf.nn.relu),
    tf.keras.layers.MaxPooling2D(2,2),
    
    tf.keras.layers.Conv2D(256,(3,3), activation='relu'),
    tf.keras.layers.MaxPooling2D(2,2),
    
    tf.keras.layers.Flatten(),
    tf.keras.layers.Dense(256, activation='relu'),
    tf.keras.layers.Dense(128,activation='relu'),
    tf.keras.layers.Dense(64, activation=tf.nn.relu),
    tf.keras.layers.Dense(1, activation='sigmoid')
])



model.compile(loss='binary_crossentropy', 
              optimizer='adam', 
              metrics=['accuracy'])
print(model.summary())

classifier_nn = model.fit(X_train,y_train,
                    epochs=60,
                    verbose=True,
                    validation_data=(X_test, y_test),
                    batch_size=128)

import matplotlib.pyplot as plt
plt.xlabel("Epochs Number")
plt.ylabel("Loss Magnitude")
plt.plot(classifier_nn.history['loss'])
plt.show()

pred=model.predict(X_test)

for i in range(len(pred)):
    if pred[i]>0.5:
        pred[i]=1
    elif pred[i]<=0.5:
        pred[i]=0

from sklearn.metrics import accuracy_score

print(accuracy_score(y_test,pred))

for i,j in zip(y_test,pred):
    # print(i==j)
    if i==j :
        temp = 0

from keras.models import load_model
import pickle

model.save('my_model_cnn.h5')
with open('vectorizer_cnn', 'wb') as fin:
    pickle.dump(vectorizer, fin)

def accuracy_function(tp,tn,fp,fn):
    
    accuracy = (tp+tn) / (tp+tn+fp+fn)
    
    return accuracy

def precision_function(tp,fp):
    
    precision = tp / (tp+fp)
    
    return precision

def recall_function(tp,fn):
    
    recall=tp / (tp+fn)
    
    return recall



def confusion_matrix(truth,predicted):
    
    true_positive = 0
    true_negative = 0
    false_positive = 0
    false_negative = 0
    
    for true,pred in zip(truth,predicted):
        
        if true == 1:
            if pred == true:
                true_positive += 1
            elif pred != true:
                false_negative += 1

        elif true == 0:
            if pred == true:
                true_negative += 1
            elif pred != true:
                false_positive += 1
            
    accuracy=accuracy_function(true_positive, true_negative, false_positive, false_negative)
    precision=precision_function(true_positive, false_positive)
    recall=recall_function(true_positive, false_negative)
    
    return (accuracy, precision, recall, true_positive, true_negative, false_positive, false_negative)

accuracy,precision,recall, true_positive, true_negative, false_positive, false_negative=confusion_matrix(y_test,pred)
print(" For CNN \n Accuracy : {0} \n Precision : {1} \n Recall : {2} \n true_positive : {3} \n true_negative : {4} \n false_positive : {5} \n false_negative : {6}".format(accuracy, precision, recall, true_positive, true_negative, false_positive, false_negative))

# accuracy,precision,recall, true_positive, true_negative, false_positive, false_negative=confusion_matrix(y_test,pred_gnb)
# print(" For Naive Bayes \n Accuracy : {0} \n Precision : {1} \n Recall : {2} \n true_positive : {3} \n true_negative : {4} \n false_positive : {5} \n false_negative : {6}".format(accuracy, precision, recall, true_positive, true_negative, false_positive, false_negative))

# accuracy,precision,recall, true_positive, true_negative, false_positive, false_negative=confusion_matrix(y_test,pred_svm)
# print(" For SVM Tree \n Accuracy : {0} \n Precision : {1} \n Recall : {2} \n true_positive : {3} \n true_negative : {4} \n false_positive : {5} \n false_negative : {6}".format(accuracy, precision, recall, true_positive, true_negative, false_positive, false_negative))

# accuracy,precision,recall, true_positive, true_negative, false_positive, false_negative=confusion_matrix(y_test,pred_knn)
# print(" For KNN Tree \n Accuracy : {0} \n Precision : {1} \n Recall : {2} \n true_positive : {3} \n true_negative : {4} \n false_positive : {5} \n false_negative : {6}".format(accuracy, precision, recall, true_positive, true_negative, false_positive, false_negative))

# accuracy,precision,recall, true_positive, true_negative, false_positive, false_negative=confusion_matrix(y_test,pred_dt)
# print(" For Decision Tree \n Accuracy : {0} \n Precision : {1} \n Recall : {2} \n true_positive : {3} \n true_negative : {4} \n false_positive : {5} \n false_negative : {6}".format(accuracy, precision, recall, true_positive, true_negative, false_positive, false_negative))