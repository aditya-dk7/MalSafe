import pickle
import pandas as pd
import os
import URLModule.URLFeatureExtraction as ufe
x=os.path.join(os.getcwd(),'URLModule','XGBoostClassifier.pickle.dat')
xgb = pickle.load(open(x, "rb"))
def check_URL_malicious(url):
    list_test = []
    list_test.append(ufe.featureExtractions(url))
    feature_names = ['Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection',
                     'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic',
                     'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over', 'Right_Click', 'Web_Forwards']

    legitimate = pd.DataFrame(list_test, columns=feature_names)
    url_predict = xgb.predict(legitimate)
    url_predict[0]
    if (url_predict[0] == 0):
        return "Yes"
    else:
        return "No"