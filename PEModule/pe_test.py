import joblib
import pickle
import os
import argparse
import pefile
from util import mainPE


def predictMalicious(filePath):
    picklePth = os.path.join(os.getcwd(), 'PEModule', 'model_jlib_fi.pkl')
    pickleFeaturePth = os.path.join(os.getcwd(),'PEModule','model_jlib_features_fi.pkl')
    clf = joblib.load(picklePth)
    features = pickle.loads(open(pickleFeaturePth, mode='rb').read())
    data = mainPE.extractAllPeinfo(filePath)
    pe_features = map(lambda x: data[x], features)
    x = list(pe_features)
    res = clf.predict([x])[0]
    return 'The file is %s' % (['malicious', 'legitimate'][res])

def main():
     parser = argparse.ArgumentParser(description='Predicts whether file is malicious or not using PE Information')
     parser.add_argument('-f', '--file', help='The file to predict malicious or not', required=True)
     args = parser.parse_args()
     try:
         pefile.PE(args.file)
         print("\n[*] Running Machine Learning")
         result = predictMalicious(args.file)
         print(result)
     except pefile.PEFormatError:
         print("[-]The file does not contain PE Information.")
     
if __name__ == '__main__':
    main()



