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
import math
import sys
import numpy as np
np.set_printoptions(threshold=sys.maxsize)
from keras_visualizer import visualizer 

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

df=pd.read_csv('sqli.csv',encoding='utf-16')

# vectorization of data

from sklearn.feature_extraction.text import CountVectorizer
vectorizer = CountVectorizer( min_df=2, max_df=0.7, max_features=4096, stop_words=stopwords.words('english'))
posts = vectorizer.fit_transform(df['Sentence'].values.astype('U')).toarray()

print("vocabulary : ", vectorizer.vocabulary_)

print("\n\n\n\n\n")

print(pd.read_csv('sqli.csv',encoding='utf-16', nrows=100))
print(posts[100])