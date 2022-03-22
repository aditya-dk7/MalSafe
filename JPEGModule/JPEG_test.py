import JPEGModule.feature_extractor as fe
import pickle
import os
x=os.path.join(os.getcwd(),'JPEGModule','RandomForestClassifier.pickle.dat')
rfc = pickle.load(open(x, "rb"))
def check_JPG_malicious(file_name):
    pfe=fe.JPEG(file_name)
    x=pfe.decode()
    list_features=[]
    list_features.append(x[:10])
    if(rfc.predict(list_features))==0:
        return "Image is not malicious"
    else:
        return "Image is malicious"