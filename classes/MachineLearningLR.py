import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix, accuracy_score, classification_report, plot_confusion_matrix
from sklearn.linear_model import LogisticRegression
import pickle
from sklearn.model_selection import KFold
from sklearn.model_selection import cross_val_score
from numpy import mean
from numpy import std
from classes.AnsiColorChanger import ColourChange
import platform
from colorama import Fore, init, Style
init()


class MalwareIdentifier:

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

        # # IMPORT DATASET
        # dataset = pd.read_csv(master_dataset_location)
        # dataset = dataset.replace(np.nan, 0)
        # dataset = dataset.dropna()

        df = pd.read_csv(master_dataset_location, index_col=0).astype(float)
        df.dropna(inplace=True, axis=1)
        x = df.drop(['Malware'], axis=1)
        y = df['Malware']

        # # X = Independent variables. Our features of the executable
        # x = dataset.iloc[:, 1:89].values  # All rows and columns apart from last dependent variable
        # # Y = Dependent variable. Specifies if executable is malware or not. Either 0 or 1.
        # y = dataset.iloc[:, -1].values  # Dependent variable which states if row is malware or not
        # print(x)
        # split the data into two sets for training and testing. Test size is 20% of the sample count.
        x_training, x_testing, y_training, y_testing = train_test_split(x, y, test_size=0.2)

        # Instantiate standard scaler for standardization.
        scaler = StandardScaler()
        # fit the data and transform it for the model
        x_training = scaler.fit_transform(x_training)
        # only fit the testing, no transform due to cross over leakage skewing results
        x_testing = scaler.transform(x_testing)



        return x_training, x_testing, y_training, y_testing

    def classifier_model_creation(self,x_training, x_testing, y_training, y_testing, output_loc):

        # instantiate from AnsiColorChange class to make console text more readable
        color_change = ColourChange()
        # Create malware identifier based upon LogisticRegression model
        malware_identifier = LogisticRegression(max_iter=8000, C=5.0)

        # Train the identifier using the data
        malware_identifier.fit(x_training, y_training)





        # Predict New RESULT: for 1 prediction, include two [[]] as it expects 2 dimensional array
        # If predicting more than 1 record, then leave out the double [[]] since the data will already be wrapped
        # classifier_output_loc = classifier_output_loc + "/MALWARE_IDENTIFIER_MODEL"

        # malware identifier pickled for later use
        MALWARE_OBJECT_PICKLE_FILE = open(output_loc + r"/malware_classifier", 'wb')
        pickle.dump(malware_identifier, MALWARE_OBJECT_PICKLE_FILE)
        MALWARE_OBJECT_PICKLE_FILE.close()

        # read the pickled malware classifier for use
        MALWARE_OBJECT_PICKLE_FILE_LOADED = open(output_loc + r"/malware_classifier", 'rb')
        loadedmalwareiden = pickle.load(MALWARE_OBJECT_PICKLE_FILE_LOADED)
        y_prediction = loadedmalwareiden.predict(x_testing)

        # # PRINT OUT RESULTS ON CONSOLE
        # print("==================================================")
        # print("LEFT [PREDICTIONS] : RIGHT [TRUE VALUE]")
        # print(np.concatenate((y_prediction.reshape(len(y_prediction), 1), y_testing.reshape(len(y_testing), 1)), 1))
        # print("==================================================")

        # OLD CONFUSION MATRIX, NOT NEEDED
        # # Show confusion matrix to gauge the accuracy
        # print("==================================================")
        # print("CONFUSION MATRIX:")
        # confusionMatrixResults = confusion_matrix(y_testing, y_prediction)
        # print("\t",confusionMatrixResults)
        # print("==================================================")

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

        print("The malware classifier was pickled and stored in: {}".format(color_change.red(output_loc)))

        # k fold cross validation
        cv = KFold(n_splits=10, random_state=1, shuffle=True)
        # evaluate model
        scores = cross_val_score(malware_identifier, x_training, y_training, scoring='accuracy', cv=cv, n_jobs=-1)
        print(mean(scores))
        print(std(scores))

        visual_data = [y_prediction, y_testing]

        return visual_data

    def visual_data_return(self,):
            return self.visual_data

