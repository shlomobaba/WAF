import tensorflow as tf
from tensorflow import keras
from keras.models import Sequential
from keras import layers
from keras.preprocessing.text import Tokenizer
from keras.wrappers.scikit_learn import KerasClassifier
import keras.preprocessing.sequence
from keras.utils import pad_sequences
import numpy as np
import pickle
import random
from urllib.parse import unquote
import re
import pandas

def addSpaces(line):
    spacedLine = re.sub(r'([^\w])', r'\1 ', line)
    return spacedLine
def createDataSet():
    sentences=[]
    labels=[]
    with open("OS-Command-Fuzzing.txt","r") as fMalicous:
        Lines = fMalicous.readlines()
        for line in Lines:
            sentences+=[addSpaces(unquote(line))]
            labels+=[1]
    dataset = pandas.read_csv("messages.csv")
    sentences += list(dataset["v2"])
    labels+= [0] * len((list(dataset["v2"])))
    seed_value = random.randint(1, 1000)
    random.seed(seed_value)
    combined = list(zip(sentences, labels))
    random.shuffle(combined)
    sentences, labels = zip(*combined)
    return (sentences,labels)
def main():
    sentences,labels=createDataSet()
    x_train=sentences[0:int(len(sentences)*0.8)]
    y_train=labels[0:int(len(labels)*0.8)]
    x_test=sentences[int(len(sentences)*0.8)+1:]
    y_test=labels[int(len(labels)*0.8)+1:]
    num_words = 100000
    oov_token = '<UNK>'
    pad_type = 'post'
    trunc_type = 'post'
    # Tokenize our training data
    tokenizer = Tokenizer(num_words=num_words, oov_token=oov_token)
    tokenizer.fit_on_texts(x_train)
    # Get our training data word index
    _word_index = tokenizer.word_index
    word_index = {k:(v+1) for k,v in _word_index.items()}
    word_index["<PAD>"] = 0
    word_index["<START>"] = 1
    with open('tokenizerOs.pickle', 'wb') as handle:
        pickle.dump(tokenizer, handle, protocol=pickle.HIGHEST_PROTOCOL)

    # Encode training data sentences into sequences
    train_sequences = tokenizer.texts_to_sequences(x_train)
    
    test_sequences = tokenizer.texts_to_sequences(x_test)
    # Get max training sequence length
    maxlen = max([len(x) for x in train_sequences])

    # Pad the training sequences
    train_padded =pad_sequences(train_sequences,value=word_index["<PAD>"], padding="post",maxlen=maxlen)
    test_padded = pad_sequences(test_sequences,value=word_index["<PAD>"],padding="post", maxlen=maxlen)
    xss_model = Sequential()
    xss_model.add(keras.layers.Embedding(input_dim=100000, output_dim=128))
    xss_model.add(keras.layers.GlobalAveragePooling1D())
    xss_model.add(keras.layers.Dense(32, activation="relu"))
    xss_model.add(keras.layers.Dense(units=1, activation='sigmoid'))
    xss_model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
    xss_model.fit(np.array(train_padded), np.array(y_train), epochs=10, batch_size=128, validation_data=(np.array(test_padded),np.array(y_test)), verbose=1)

    xss_model.summary()
    xss_model.save("osModel.h5")
if __name__=="__main__":
    main()