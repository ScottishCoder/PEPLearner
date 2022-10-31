import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
from tensorflow.keras.models import Sequential
from tensorflow.keras.wrappers.scikit_learn import KerasClassifier
from tensorflow.keras.layers import Dense, Dropout
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, classification_report
import platform
from tensorflow.keras.wrappers import scikit_learn
from sklearn.model_selection import KFold
from sklearn.model_selection import cross_val_score
from numpy import mean
from numpy import std

class Deepnn:

    def __init__(self, master_dataset_location, output_loc, layer_count, neuron_count, epochCount):
        # check platform to append correct path style
        if platform.system().lower() == "darwin" or platform.system().lower() == "linux":

            self.master_dataset_location = master_dataset_location + r"/MasterDataset.csv"
        else:
            self.master_dataset_location = master_dataset_location + r"\MasterDataset.csv"

        # run the feature scaler and use min max to normalize the data
        x_train, x_test, y_train, y_test = self.__dataset_feature_scaling(self.master_dataset_location)

        # run the training component and create the model. Return data if user wants to visualise it.
        self.visual_data = self.classifier_model_creation(x_train, x_test, y_train, y_test, output_loc, layer_count, neuron_count, epochCount)


    def __dataset_feature_scaling(self, master_dataset_location):

        # Read from CSV
        dataset = pd.read_csv(master_dataset_location)
        dataset = dataset.replace(np.nan, 0)
        dataset = dataset.dropna()
        x = dataset.drop('Malware', axis=1).values
        y = dataset['Malware'].values
        # print(dataset.describe())


        x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=101)


        from sklearn.preprocessing import MinMaxScaler

        scaler = MinMaxScaler()

        x_train = scaler.fit_transform(x_train)

        x_test = scaler.transform(x_test)


        return x_train, x_test, y_train, y_test

    def classifier_model_creation(self,x_train, x_test, y_train, y_test, output_loc, layer_count, neuron_count, epochCount):

        model = Sequential()
        for i in range(int(layer_count)):
            model.add(Dense(neuron_count[i], activation='relu'))
            model.add(Dropout(0.5))

        model.add(Dense(1, activation='sigmoid'))
        model.compile(loss='binary_crossentropy', optimizer='adam')
        losses = model.fit(x=x_train, y=y_train, epochs=int(epochCount), validation_data=(x_test, y_test))


        print(model.summary())

        model.save(output_loc)
        predictions = (model.predict(x_test) > 0.5).astype("int32")

        print(classification_report(y_test, predictions))
        print(confusion_matrix(y_test, predictions))

        loss = pd.DataFrame(losses.history)
        print(losses)

        # print(model.evaluate())

        print('Would you like to visually see the loss and validation loss on a graph? This can be a good indicator for underfitting and overfitting. y or n')
        userdecision = input(": ")
        if userdecision == "y":
            loss.plot()
            plt.show()


        visual_data =  [predictions, y_test]



        return visual_data

    def visual_data_return(self,):
            return self.visual_data

# dnn = Deepnn("/Users/chris/Downloads/PEPLearner/classes", "/Users/chris/Downloads/PEPLearner","3",["15","25","30"],"50")
