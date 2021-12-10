import joblib
import pickle
import os
from util import mainPE
clf = joblib.load('/home/dk7/projectsCap/MalSafe/PEModule/savedmodel/model_jlib.pkl')
features = pickle.loads(open('/home/dk7/projectsCap/MalSafe/PEModule/savedmodel/model_jlib_features.pkl', mode='rb').read())
data = mainPE.extractAllPeinfo('/home/dk7/projectsCap/MalSafe/PEModule/exe/NonMalicious/Firefox.exe')
pe_features = map(lambda x: data[x], features)
x = list(pe_features)
res = clf.predict([x])[0]
print('The file is %s' % (['malicious', 'legitimate'][res]))