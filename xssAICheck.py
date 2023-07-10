import sys

from tensorflow import keras
from keras.models import Sequential
from keras import layers
from keras.preprocessing.text import Tokenizer
from keras.wrappers.scikit_learn import KerasClassifier
import keras.preprocessing.sequence
from keras.utils import pad_sequences
import re
import numpy as np
import pickle
MAX_LEN=250
def addSpacesToRequest(userRequest):
    splittedRequest=(re.compile(r"""([<]|[>])""")).split(userRequest)
    spacedRequest=" ".join(splittedRequest)
    return spacedRequest
def loadWordIndex():
    global tokenizer
    global word_index
    with open('tokenizer.pickle', 'rb') as handle:
        tokenizer = pickle.load(handle)
        _word_index = tokenizer.word_index
        word_index = {k: (v + 3) for k, v in _word_index.items()}
        word_index["<PAD>"] = 0
        word_index["<START>"] = 1
        word_index["<"] = 2
        word_index[">"] = 3

def parseUserRequest(userRequest):
    global tokenizer
    global word_index
    userRequest = tokenizer.texts_to_sequences([userRequest])
    userRequest = pad_sequences(userRequest, value=word_index["<PAD>"], padding="post", maxlen=MAX_LEN)
    return userRequest
def checkForXSS(userRequest):
    global tokenizer
    global word_index
    userRequest=addSpacesToRequest(userRequest)
    loadWordIndex()
    userRequest = parseUserRequest(userRequest)
    xssAI = keras.models.load_model("model.h5")
    predictions=xssAI.predict(userRequest)
    print(str(predictions[0][0]))
    if(predictions[0][0]>0.5):
        return True
    return False


if __name__=="__main__":
    globals()[sys.argv[1]](sys.argv[2])