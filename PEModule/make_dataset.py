import pandas as pd
import mainPE
import hashlib
import os
import argparse

def checkPath(path, isLegitimate, datasetPath):
    if os.path.exists(path):
        if os.path.isdir(path):
            print('[*] Directory detected')
            for root, dirs, files in os.walk(path):
                for file in files:
                    makeDataset(os.path.join(root, file), isLegitimate, datasetPath)
                for dir in dirs:
                    checkPath(os.path.join(root, dir), isLegitimate, datasetPath)    
        else:
            print('[*] File detected')
            makeDataset(path, isLegitimate, datasetPath)
    else:
        print('[-] File/Directory does not exist')

def makeDataset(filePath,  isLegitimate = False, datasetPath = 'peInformationDataset.csv'):
    print('[*] Extracting information from {}'.format(filePath))
    filePEInformation = mainPE.extractAllPeinfo(filePath)
    if filePEInformation is not None:
        newPEInformation = {}
        newPEInformation['Name'] = os.path.basename(filePath)
        newPEInformation['md5'] = hashlib.md5(open(filePath, 'rb').read()).hexdigest()
        newPEInformation.update(filePEInformation)
        if isLegitimate == True:
            newPEInformation['legitimate'] = 1
        else:
            newPEInformation['legitimate'] = 0
        peInformation = pd.DataFrame(newPEInformation, index=[0])
        if not os.path.exists(datasetPath):
            peInformation.to_csv(datasetPath, mode = 'a', index=False, sep='|', header=True)
        else:
            peInformation.to_csv(datasetPath, mode = 'a', index=False, sep='|', header=False)
    else:
        print('[-] Error extracting information, possibly does not contain a PE header')
        print('[-] Skipping {}'.format(filePath))
        
def main():
    parser = argparse.ArgumentParser(description='Extracts information from a given file or directory')
    parser.add_argument('-f', '--file', help='The file to extract information from', required=True)
    parser.add_argument('-l', '--legitimate', help='Is the file legitimate?', action='store_true')
    parser.add_argument('-d', '--dataset', help='The dataset to create/append the information to', required=False, default='peInformationDataset.csv')
    parser.add_argument('-r', '--recursive', help='Recursively extract information from a directory', action='store_true')
    args = parser.parse_args()
    if not args.dataset.endswith('.csv'):
        print('[-] Dataset must be a csv file')
        exit(1)
    checkPath(args.file, args.legitimate, args.dataset)
    print('[*] Done')
    
if __name__ == '__main__':
    main()
