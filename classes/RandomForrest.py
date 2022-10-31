import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix, accuracy_score, classification_report
from sklearn.ensemble import RandomForestClassifier
import pickle
from classes.AnsiColorChanger import ColourChange
import platform
from sklearn.model_selection import KFold
from sklearn.model_selection import cross_val_score
from numpy import mean
from numpy import std

class RandomForrest:

    def __init__(self, master_dataset_location, output_loc):
        # get master dataset from the user specified location
        if platform.system().lower() == "darwin" or platform.system().lower() == "linux":

            self.master_dataset_location = master_dataset_location + r"/MasterDataset.csv"
        else:
            self.master_dataset_location = master_dataset_location + r"\MasterDataset.csv"
        # get the returned feature scaled data for model training.
        x_training, x_testing, y_training, y_testing = self.__dataset_feature_scaling(self.master_dataset_location)
        # run the model training, then return the needed data if visualisation is needed
        self.visual_data = self.classifier_model_creation(x_training, x_testing, y_training, y_testing, output_loc)



    def __dataset_feature_scaling(self, master_dataset_location):


        df = pd.read_csv(master_dataset_location, index_col=0)
        df.dropna(inplace=True, axis=1)
        x_rf_features = df.drop(['Malware'], axis=1)
        y_rf_features = df['Malware']

        # split the data into two sets for training and testing. Test size is 20% of the sample count.
        x_training, x_testing, y_training, y_testing = train_test_split(x_rf_features, y_rf_features, test_size=0.2)

        return x_training, x_testing, y_training, y_testing

    def classifier_model_creation(self,x_training, x_testing, y_training, y_testing, output_loc):


        rf = RandomForestClassifier(n_estimators=400)

        rf.fit(x_training, y_training)
        predictions = rf.predict(x_testing)

        print(confusion_matrix(y_testing, predictions))
        print(classification_report(y_testing, predictions))

        # malware identifier pickled for later use
        MALWARE_OBJECT_PICKLE_FILE = open(output_loc + r"/malware_classifier", 'wb')
        pickle.dump(rf, MALWARE_OBJECT_PICKLE_FILE)
        MALWARE_OBJECT_PICKLE_FILE.close()

        # read the pickled malware classifier for use
        MALWARE_OBJECT_PICKLE_FILE_LOADED = open(output_loc + r"/malware_classifier", 'rb')
        loadedmalwareiden = pickle.load(MALWARE_OBJECT_PICKLE_FILE_LOADED)
        y_prediction = loadedmalwareiden.predict(x_testing)




        print("==================================================")
        print("ACCURACY:")
        # get accuracy
        accuracyResults = accuracy_score(y_testing, y_prediction)
        print("\t",accuracyResults)
        print("==================================================")

        print("==================================================")
        # classification report
        print("CLASSIFICATION REPORT:")
        report = classification_report(y_testing, y_prediction)
        print("\t",report)
        print("==================================================")

        MALWARE_OBJECT_PICKLE_FILE_LOADED.close()

        color_change = ColourChange()
        print("The malware classifier was pickled and stored in: {}".format(color_change.red(output_loc)))


        visual_data = [y_prediction, y_testing]

        return visual_data

    def visual_data_return(self,):
            return self.visual_data



