import os
import argparse

def main():
    parser = argparse.ArgumentParser(description='Predicts whether file/url is malicious or not using Machine Learning')
    parser.add_argument('-f', '--file', help='The file to predict malicious or not')
    parser.add_argument('-u', '--url', help='The url to predict malicious or not')
    args = parser.parse_args()
    

if __name__ == '__main__':
    main()