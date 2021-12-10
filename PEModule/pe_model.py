import pandas as pd
import numpy as np
import pickle
from sklearn.naive_bayes import GaussianNB
from sklearn import tree
import sklearn.ensemble as ske
from sklearn.model_selection import train_test_split
from sklearn.feature_selection import SelectFromModel
import joblib

malwareDataset = pd.read_csv('/home/dk7/projectsCap/MalSafe/PEModule/datasets/MalwareData.csv', sep='|')
data = malwareDataset.drop(['Name', 'md5', 'legitimate'], axis=1).values
target = malwareDataset['legitimate'].values

print("[*] There are",data.shape[1], "features in provided dataset. Selecting Only important features.")
FeatSelect = ske.ExtraTreesClassifier().fit(data, target)
Model = SelectFromModel(FeatSelect, prefit=True)
data_new = Model.transform(data)
nb_features = data_new.shape[1]

X_train, X_test, y_train, y_test = train_test_split(data_new, target ,test_size=0.2)
features = []
print('%i features identified as important:' % nb_features)
for f in sorted(np.argsort(FeatSelect.feature_importances_)[::-1][:nb_features]):
    features.append(malwareDataset.columns[2+f])
print(features)

algorithms = {
        "DecisionTree": tree.DecisionTreeClassifier(max_depth=10),
        "RandomForest": ske.RandomForestClassifier(n_estimators=50),
        "GradientBoosting": ske.GradientBoostingClassifier(n_estimators=50),
        "AdaBoost": ske.AdaBoostClassifier(n_estimators=100),
        "GNB": GaussianNB()
    }

results = {}
for algo in algorithms:
    clf = algorithms[algo]
    clf.fit(X_train, y_train)
    score = clf.score(X_test, y_test)
    results[algo] = score

print(results)

best_algorithm = max(results, key=results.get)

joblib.dump(algorithms[best_algorithm] , '/home/dk7/projectsCap/MalSafe/PEModule/savedmodel/model_jlib.pkl')
open('/home/dk7/projectsCap/MalSafe/PEModule/savedmodel/model_jlib_features.pkl', 'wb').write(pickle.dumps(features))
