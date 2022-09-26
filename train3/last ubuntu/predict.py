import keras
from keras.models import load_model
import pickle

mymodel = load_model('my_model_cnn.h5')
myvectorizer = pickle.load(open("vectorizer_cnn", 'rb'))

def clean_data(input_val):

    input_val=input_val.replace('\n', '')
    input_val=input_val.replace('%20', ' ')
    input_val=input_val.replace('=', ' = ')
    input_val=input_val.replace('((', ' (( ')
    input_val=input_val.replace('))', ' )) ')
    input_val=input_val.replace('(', ' ( ')
    input_val=input_val.replace(')', ' ) ')
    input_val=input_val.replace('1 ', 'numeric')
    input_val=input_val.replace(' 1', 'numeric')
    input_val=input_val.replace("'1 ", "'numeric ")
    input_val=input_val.replace(" 1'", " numeric'")
    input_val=input_val.replace('1,', 'numeric,')
    input_val=input_val.replace(" 2 ", " numeric ")
    input_val=input_val.replace(' 3 ', ' numeric ')
    input_val=input_val.replace(' 3--', ' numeric--')
    input_val=input_val.replace(" 4 ", ' numeric ')
    input_val=input_val.replace(" 5 ", ' numeric ')
    input_val=input_val.replace(' 6 ', ' numeric ')
    input_val=input_val.replace(" 7 ", ' numeric ')
    input_val=input_val.replace(" 8 ", ' numeric ')
    input_val=input_val.replace('1234', ' numeric ')
    input_val=input_val.replace("22", ' numeric ')
    input_val=input_val.replace(" 8 ", ' numeric ')
    input_val=input_val.replace(" 200 ", ' numeric ')
    input_val=input_val.replace("23 ", ' numeric ')
    input_val=input_val.replace('"1', '"numeric')
    input_val=input_val.replace('1"', '"numeric')
    input_val=input_val.replace("7659", 'numeric')
    input_val=input_val.replace(" 37 ", ' numeric ')
    input_val=input_val.replace(" 45 ", ' numeric ')

    return input_val

def predict_sqli_attack():
    
    repeat=True
    
    beautify=''
    for i in range(20):
        beautify+= "="

    print(beautify) 
    input_val=input("Give me some data to work on : ")
    print(beautify)

    
    if input_val== '0':
        repeat=False
    
    

    input_val=clean_data(input_val)
    input_val=[input_val]



    input_val=myvectorizer.transform(input_val).toarray()
    
    input_val.shape=(1,64,64,1)

    result=mymodel.predict(input_val)


    print(beautify)
    
    
    if repeat == True:
        
        if result>0.5:
            print("ALERT :::: an attack has occurred, detector confidence : " + str(result))


        elif result<=0.5:
            print("It seems to be safe, confidence : " + str(result))
            
        print(beautify)
            
        predict_sqli_attack()
            
    elif repeat == False:
        print( " Good Bye ")

predict_sqli_attack()