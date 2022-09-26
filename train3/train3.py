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
import numpy as np
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
        data[i]=data[i].replace('“', ' ')
        data[i]=data[i].replace('”', ' ')
        # data[i]=data[i].replace('.', ' . ')
    
    return data

df=pd.read_csv('sqli4.csv',encoding='utf-8')

# vectorization of data

from sklearn.feature_extraction.text import CountVectorizer
vectorizer = CountVectorizer( min_df=2, max_df=0.7, max_features=4096, stop_words=stopwords.words('english'))
posts = vectorizer.fit_transform(df['Sentence'].values.astype('U')).toarray()

print(posts.shape)

# print(posts)

posts.shape=(36724,64,64,1)

X=posts
y=df['Label']

from sklearn.model_selection import train_test_split

# split train test data

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

import tensorflow as tf
from keras.models import Sequential
from keras import layers, callbacks
from keras.preprocessing.text import Tokenizer
from keras.wrappers.scikit_learn import KerasClassifier

callback = tf.keras.callbacks.EarlyStopping(monitor='val_loss', patience=5, mode='auto', baseline=None, restore_best_weights=True)

model=tf.keras.models.Sequential([
    tf.keras.layers.Conv2D(16, (4,4), activation=tf.nn.relu, input_shape=(64,64,1)),
    tf.keras.layers.MaxPooling2D(2,2),
    # tf.keras.layers.BatchNormalization(),
    # tf.keras.layers.Dropout(0.5),

    tf.keras.layers.Conv2D(6, (2,2), activation=tf.nn.relu),
    tf.keras.layers.MaxPooling2D(2,2),
    # tf.keras.layers.BatchNormalization(),
    # tf.keras.layers.Dropout(0.5),

    tf.keras.layers.Flatten(),
    # tf.keras.layers.Dense(8, activation=tf.nn.relu),
    tf.keras.layers.Dense(4, activation=tf.nn.relu),
    # tf.keras.layers.Dense(2, activation=tf.nn.relu),
    tf.keras.layers.Dropout(0.2),
    tf.keras.layers.Dense(1, activation='sigmoid')
])

# model.compile(loss='binary_crossentropy', 
#               optimizer='adam', 
#               metrics=['accuracy'])
# print(model.summary())

# visualizer(model, format='png', view=True)

learning_rate = 0.0001
model.compile(loss='binary_crossentropy',
              optimizer=tf.keras.optimizers.Adam(learning_rate), 
              metrics=['accuracy'])
print(model.summary())

BATCH_SIZE = 32
num_x_train = len(X_train)
print("num train" + str(num_x_train))

classifier_nn = model.fit(X_train,y_train,
                    epochs=500,
                    verbose=True,
                    validation_data=(X_test, y_test),
                    steps_per_epoch=math.ceil(num_x_train/BATCH_SIZE),
                    callbacks=[callback]
                    )

import matplotlib.pyplot as plt
plt.plot(classifier_nn.history['loss'])
plt.plot(classifier_nn.history['val_loss'])
plt.title('model loss')
plt.ylabel('loss')
plt.xlabel('epoch')
plt.legend(['train', 'val'], loc='upper left')
plt.show()

plt.plot(classifier_nn.history['accuracy'])
plt.plot(classifier_nn.history['val_accuracy'])
plt.title('model accuracy')
plt.ylabel('accuracy')
plt.xlabel('epoch')
plt.legend(['train', 'val'], loc='upper left')
plt.show()

pred=model.predict(X_test)

for i in range(len(pred)):
    if pred[i]>0.5:
        pred[i]=1
    elif pred[i]<=0.5:
        pred[i]=0

#accuracy
from sklearn.metrics import accuracy_score
print("\naccuracy : ")
print(accuracy_score(y_test,pred))
print("\n")

#confusion matrix
from sklearn.metrics import confusion_matrix
print("conf matrix : ")
print(confusion_matrix(y_test,pred))
print("\n")

# Recall
from sklearn.metrics import recall_score
print("recall : ")
print(recall_score(y_test,pred, average=None))
print("\n")

# Precision
from sklearn.metrics import precision_score
print("precision : ")
print(precision_score(y_test,pred, average=None))
print("\n")

#f1 score
from sklearn.metrics import f1_score
print("f1 score : ")
print(f1_score(y_test,pred, average=None))
print("\n")

for i,j in zip(y_test,pred):
    # print(i==j)
    if i==j :
        temp = 0

from keras.models import load_model
import pickle

model.save('my_model_cnn.h5')
with open('vectorizer_cnn', 'wb') as fin:
    pickle.dump(vectorizer, fin)
