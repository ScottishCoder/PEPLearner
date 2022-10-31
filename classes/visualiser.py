import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix, accuracy_score, classification_report, plot_confusion_matrix
from classes.AnsiColorChanger import ColourChange
import numpy as np

class Visualiser:

    def __init__(self, data):

        # Get the Y pred data
        y_prediction = data[0]
        # Get the unseen Y_testing data
        y_testing = data[1]

        self.color_change = ColourChange()

        # Run visual method
        self.visualisation_confus(y_prediction, y_testing)

    def visualisation_confus(self, y_prediction, y_testing):

        # Show confusion matrix to gauge the accuracy
        confusionMatrixResults = confusion_matrix(y_testing, y_prediction)
        # Create the labels for the graph
        confusion_labels = ["True Negative", "False Positive", "False Negative","True Positive"]
        # Reshape so that they will apply to a multi dimension array
        confusion_labels = np.asarray(confusion_labels).reshape(2,2)
        # Create the figure and apply 3 columns
        fig, axs = plt.subplots(ncols=3)
        # Shows the percentages of TN, FP, FN, TP relative to the size of the testing data
        sns.heatmap(confusionMatrixResults/np.sum(confusionMatrixResults), fmt='.2%', annot=True, ax=axs[0]).set_title('PERCENTAGES OF TEST DATA')
        # Shows the counts of TN, FP, FN, TP
        sns.heatmap(confusionMatrixResults, annot=True, fmt='', ax=axs[1]).set_title("TEST DATA COUNT")
        # Basic visual aid so you know you're each panel contains in reltion to TN, FP, FN and TP.
        sns.heatmap(confusionMatrixResults, fmt='', annot=confusion_labels, ax=axs[2]).set_title('VISUAL AID FOR LOCATING DATA')
        plt.show()


