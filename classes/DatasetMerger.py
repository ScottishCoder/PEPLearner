import pandas as pd  # Gives access to Dataframe objects required for saving data and organising it
from sklearn.utils import shuffle

class DatasetMerger:

    def __init__(self, dataset_one_path, dataset_two_path, output_location, doc_type):
        self.dataset_one_path = dataset_one_path
        self.dataset_two_path = dataset_two_path
        self.output_location = output_location
        self.doc_type = doc_type

        self.__merge_documents(self.dataset_one_path, self.dataset_two_path, self.output_location)

    def __merge_documents(self, dataset_one_path, dataset_two_path, output_loc):

        dataset_one = pd.read_csv(dataset_one_path).reset_index(drop=True)
        dataset_two = pd.read_csv(dataset_two_path).reset_index(drop=True)

        datasets = [dataset_one, dataset_two]

        df_re_indexed = pd.concat(datasets, ignore_index=True)
        df_re_indexed.rename({"Unnamed: 0":"a"}, axis="columns", inplace=True)
        df_re_indexed.drop(["a"], axis=1, inplace=True)

        df = shuffle(df_re_indexed)

        df.reset_index(inplace=True, drop=True)

        if self.doc_type == "csv":
            print(self.output_location)
            df.to_csv(output_loc + r"/MasterDataset.csv", header=True)
        elif self.doc_type == "excel":
            df.to_excel(output_loc + r"/MasterDataset.xlsx", header=True)
        else:
            print("An error occurred at the format specification")









