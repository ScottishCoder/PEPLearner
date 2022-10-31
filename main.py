from classes.EXE_Path_Hunter import  EXE_Path_Hunter  # My own custom class. Designed to get all exe paths
from classes.PE_Extractor import PE_Extractor  # My own custom class. Designed to extract raw exe data and parse it
from classes.EXE_Formatter import EXE_Formatter  # My own custom class. Designed to format the parsed data from PE_Extr
from classes.DatasetMerger import DatasetMerger
from classes.MachineLearningLR import MalwareIdentifier
from classes.AnsiColorChanger import ColourChange
from classes.visualiser import Visualiser
from classes.Deepneuralnetwork import Deepnn
from classes.RandomForrest import RandomForrest
from classes.DecisionTree import DecisionTreeC
import os  # Gives OS level functionality, like getting basename of files, etc.
import platform
platname = platform.system()

# /Users/chris/Desktop/malware
# /Users/chris/Desktop/benign
# /Users/chris/Desktop/dataset

# MAIN PROGRAM STARTS #
if __name__ == "__main__":

    colour_changer = ColourChange()
    # Will store absolute path for both Datasets to reference further in program.
    output_path_storage = []
    continuation = True

    # MAIN PROGRAM WHILE LOOP
    while continuation:

        print('Welcome to Troys malware data formatter for machine learning training and testing')
        print(colour_changer.red("INSTRUCTIONS: PLEASE READ CAREFULLY!"))
        print(colour_changer.red("==================== MANUAL ===================="))
        print(colour_changer.yellow('\t You will create 2 datasets, 1 for benign executables and 1 for malware executables.'))
        print(colour_changer.yellow('\t You can decide which to do first. The order does not matter.'))
        print(colour_changer.yellow('\t After creating the first dataset repeat this process for the second.'))
        print(colour_changer.yellow('\t Once both datasets have been constructed, both datasets will be merged into a master dataset.'))
        print(colour_changer.yellow(
            '\t Only the CSV format is supported for now. Do not choose Excel or it will exit. This will be added later on'))
        print(colour_changer.yellow('\t You will provide a location for the storage of the Master Dataset.'))
        print(colour_changer.yellow('\t You can then decide to exit or continue and apply Logistic Regression Machine Learning or Deep Learning (DNN).'))
        print(colour_changer.red("================================================"))
        print(colour_changer.yellow("Hit the enter key to continue"))
        input()

        print(colour_changer.yellow("Follow these options:"))
        print(colour_changer.green("\t 1. Only utilise Machine Learning aspect of program?"))
        print(colour_changer.green("\t 2. Create the datasets and then decide if you want to use them to create a ML model?"))
        choice = input("\t Enter number: ")
        if choice == "1":
            print(colour_changer.green("\t Please enter the location where the Master Dataset resides"))
            # Will contain the location of the master dataset after user enters into input
            master_doc_output_loc = input("\t : ")
            print(colour_changer.yellow("\t Please provide a location to store the new machine learning model"))
            print(colour_changer.yellow('\t Do you want to use Supervised or Unsupervised?'))
            print(colour_changer.green("\t\t1. Supervised"))
            print(colour_changer.green("\t\t2. Unsupervised (Coming soon)"))
            modelType = input("\t\tModel type: ")
            if modelType == "1":
                print(colour_changer.yellow("\tDo you want to use:"))
                print(colour_changer.green("\t\t1. Logistic Regression (LR)"))
                print(colour_changer.green('\t\t2. Deep Learning (DNN)'))
                print(colour_changer.green('\t\t3. Random Forrest (RF)'))
                print(colour_changer.green('\t\t4. Decision Tree (DT)'))

                modelSelect = input("\t\tModel Select: ")
                if modelSelect == "1":
                    print(colour_changer.yellow(
                        "\tWhere do you want to store the model of your newly created machine learning classifier?"))
                    location = input("\t\t: ")
                    classifier = MalwareIdentifier(master_doc_output_loc, location)
                    print(colour_changer.yellow('\tWould you like to visualise the results? '))
                    if input("\t\ty or n: ") == "y":
                        graph = Visualiser(classifier.visual_data_return())

                elif modelSelect == "2":
                        print(colour_changer.yellow(
                            "\tWhere do you want to store the model of your newly created Deep Learning classifier?"))
                        location = input("\t\t: ")
                        print(colour_changer.yellow("\tHow many layers do you want to use?"))
                        hiddenLayerCount = input("\t\t Layer Count: ")
                        allNeuronCount = []
                        print(colour_changer.yellow("\tHow many epochs? "))
                        epochCount = input("\t\tEpoch Count: ")
                        print(colour_changer.yellow("\tHow many neurons per layer? "))
                        for i in range(int(hiddenLayerCount)):
                            print('\tLayer: {} add neurons: '.format(colour_changer.red(str(i))))
                            neuroncount = input("\t\t: ")
                            allNeuronCount.append(neuroncount)

                        print(colour_changer.yellow("\tDoes this look ok to you?"))
                        print("\t\tModel output location: ", colour_changer.red(location))
                        print('\t\tHidden Layer Count: ', colour_changer.red(hiddenLayerCount))
                        for i in range(len(allNeuronCount)):
                            print("\t\tLayer {} has {} Neurons applied".format(colour_changer.red(str(i)), colour_changer.red(allNeuronCount[i])))

                        confirm = input('\tconfirm (y or n): ')

                        if confirm == "y":

                            classifier = Deepnn(master_doc_output_loc, location, hiddenLayerCount, allNeuronCount, epochCount)
                            print(colour_changer.yellow('\tWould you like to visualise the results of the confusion matrix? '))
                            if input("\ty or n: ") == "y":
                                graph = Visualiser(classifier.visual_data_return())
                                exit()
                        else:
                            exit()

                elif modelSelect == "3":

                    print(colour_changer.yellow(
                        "\tWhere do you want to store the model of your newly created machine learning classifier?"))
                    location = input("\t\t: ")
                    classifier = RandomForrest(master_doc_output_loc, location)
                    print(colour_changer.yellow('\tWould you like to visualise the results? '))
                    if input("\t\ty or n: ") == "y":
                        graph = Visualiser(classifier.visual_data_return())

                elif modelSelect == "4":

                    print(colour_changer.yellow(
                        "\tWhere do you want to store the model of your newly created DT machine learning classifier?"))
                    location = input("\t\t: ")
                    classifier = DecisionTreeC(master_doc_output_loc, location)
                    print(colour_changer.yellow('\tWould you like to visualise the results? '))
                    if input("\t\ty or n: ") == "y":
                        graph = Visualiser(classifier.visual_data_return())

                else:
                    print(colour_changer.red('Only 4 Options exist. Restart the program and choose from one the 4'))
                    exit()


            else:
                print(colour_changer.red('Restart the application. Unsupervised has not been added yet'))
                exit()
            print(colour_changer.red("DEVELOPED AS PART OF A MASTERS FOR THE UNIVERSITY OF THE WEST OF SCOTLAND"))
            print(colour_changer.red("Developer: Christopher Troy"))
            exit()
        else:
            pass

        # stores user choice if recursion is needed or not
        print(colour_changer.green("Recursion Choice (y or n):"))
        recursion_choice = input(": ")
        # path to root directory containing all executable
        print(colour_changer.green("Path to executables:"))
        path_to_root = input(": ")
        # Format type, So either excel or csv
        print(colour_changer.green("Format Type (csv or (excel << coming soon)):"))
        format_type = input(": ")
        # desired output location to store dataset/s
        print(colour_changer.green("Output dataset to which directory:"))
        output_path = input(": ")
        output_path_storage.append(output_path)
        # dataset type be it benign or malware based
        print(colour_changer.green("Benign or Malware (b or m):"))
        dataset_type = input(": ")
        # Using custom exe path hunter class. Has two methods, one for recursion and one without

        print(colour_changer.yellow("Are these details correct: "))
        print("\t Recursion: {}".format(colour_changer.red(recursion_choice)))
        print("\t Path to Executables: {}".format(colour_changer.red(path_to_root)))
        print("\t Format Type: {}".format(colour_changer.red(format_type)))
        print("\t Output Path for dataset: {}".format(colour_changer.red(output_path)))
        print("\t Dataset Type: {}".format(colour_changer.red(dataset_type)))
        validate = input("Correct (y or n): ").lower()
        if validate == "y" or validate == "yes":
            finder = EXE_Path_Hunter()
            if recursion_choice == "yes" or recursion_choice == "Yes" or recursion_choice == "y":
                exe_file_paths = finder.recursive_search(path_to_root)
                # required for formatting purposes, so that data can be merged into the one under same headers
                pe_data_list = []
                # Running a for loop to get all paths inside the root directory the user has chosen
                for path in exe_file_paths:
                    # Get the filename for indexing purposes and visualisation at a later point. This will get (filename.exe)
                    file_name_id = os.path.basename(path)
                    # print(file_name_id)
                    # for every path to an exe, instantiate the PE_Extractor class for that specific executable
                    extracted_pe_data = PE_Extractor(path, file_name_id)
                    # Append the PE_Extractor object containing our path to a list
                    pe_data_list.append(extracted_pe_data)

                """
                Instantiate, new object from PE_formatter class. It takes our compiled list of:
                1. PE_Extractor objects, all targeting chosen EXE with path passed into parameter
                2. The chosen output path the user wants the files to go
                3. The chosen format type, be it CSV OR Excel
                """
                pe_formatter = EXE_Formatter(pe_data_list, output_path, format_type, dataset_type)
                pe_formatter.format_to_dataframe()

            # Same process applies if using no recursion. Only this time targeting one and only one root folder.
            elif recursion_choice == "no" or recursion_choice == "No" or recursion_choice == "n":
                exe_file_paths = finder.non_recursive_search(path_to_root)
                pe_data_list = []
                for path in exe_file_paths:
                    file_name_id = os.path.basename(path)
                    extracted_pe_data = PE_Extractor(path, file_name_id)
                    pe_data_list.append(extracted_pe_data)

                pe_formatter = EXE_Formatter(pe_data_list, output_path, format_type, dataset_type)
                pe_formatter.format_to_dataframe()

            else:
                print(colour_changer.red("\tYou done goofed! You didn't enter the correct data. Restart the program!"))
                exit()

            print(colour_changer.yellow('\tIt is now time to create the next dataset!, follow the same process as before.'))
            print(colour_changer.red("\tHave you already created both datasets?"))

            user_progress = input("(y or n): ")
            if user_progress == "n" or user_progress == "No" or user_progress == "NO" or user_progress == "N":
                continue
            elif user_progress == "y" or user_progress == "Yes" or user_progress == "yes" or user_progress == "YES":
                continuation = False
        else:
            continue


    # From here datasets will be merged

    # clear console system of previously parsed data
    os.system('cls')
    print(colour_changer.yellow("GREAT JOB! We now have two datasets ready to go! But first we need to merge them into the one document"))
    # counting path. There should be only 2 checks, if 3 it means script ran again and 3 paths were added to list.
    # This is a bad design, and it's being left in purely for time constraint reasons.
    count_check = 0
    path_one = ""
    path_two = ""
    print(colour_changer.green("What format were the datasets? csv or excel"))
    master_doc_format_Type = input(": ")
    for path in output_path_storage:
        # print(output_path_storage)
        if count_check == 0 and platname.lower() == "darwin" or count_check == 0 and platname.lower() == "linux":
            if master_doc_format_Type == "csv":
                path_one = path + r"/malware_executables_dataset.csv"
            elif master_doc_format_Type == "excel":
                path_one = path + r"/malware_executables_dataset.xlsx"
        elif count_check == 1 and platname.lower() == "darwin" or count_check == 1 and platname.lower() == "linux":
            if master_doc_format_Type == "csv":
                path_two = path + r"/benign_executables_dataset.csv"
            elif master_doc_format_Type == "excel":
                path_two = path + r"/benign_executables_dataset.xlsx"
        elif count_check == 0 and platname.lower() == "windows":
            if master_doc_format_Type == "csv":
                path_one = path + r"\malware_executables_dataset.csv"
            elif master_doc_format_Type == "excel":
                path_one = path + r"\malware_executables_dataset.xlsx"
        elif count_check == 1 and platname.lower() == "windows":
            if master_doc_format_Type == "csv":
                path_two = path + r"\benign_executables_dataset.csv"
            elif master_doc_format_Type == "excel":
                path_two = path + r"\benign_executables_dataset.xlsx"
        elif count_check > 1:
            print(colour_changer.red("An error occurred. Detected more than two paths in the paths list"))
            exit()
        count_check += 1

    while True:
        print(colour_changer.green("\tPlease provide an output location for the master document"))
        master_doc_output_loc = input('\t\tOutput Location: ')
        print(colour_changer.green("\tPlease provide a format, be it csv or excel"))
        master_dataset_format_Type = input("\t\tFormat type (csv or excel): ")
        print(colour_changer.yellow("\tBefore proceeding, does this look right to you?"))
        print("\t\tDataset One Path: {}".format(colour_changer.red(path_one)))
        print("\t\tDataset Two Path: {}".format(colour_changer.red(path_two)))
        print("\t\tYour chosen output locations for the master dataset: {}".format(colour_changer.red(master_doc_output_loc)))
        print("\t\tYour chosen format type for the master dataset: {}".format(colour_changer.red(master_dataset_format_Type)))
        print(colour_changer.red("\t\tFinalised?"))
        finalised = input("\t(y or n): ")
        if finalised == "y":
            # Run the Dataset Merger class. No need to instantiate, directly calling it is fine.
            DatasetMerger(path_one, path_two,master_doc_output_loc, master_dataset_format_Type)
            break
        else:
            continue

    # reset system once again to clear the console of clutter
    os.system('cls')
    print(colour_changer.yellow("Excellent! you have created a master dataset and now it's time to use it."))
    print(colour_changer.yellow("If you want to test the dataset out using Machine Learning, continue"))
    print("If you want to stop here, just type {} or leave blank and hit {} key to continue".format(colour_changer.red("exit"), colour_changer.red("enter")))
    decision = input('Decision: ')
    if decision == "exit":
        exit()
    else:
        print(colour_changer.yellow("\tSo you decided to stay! Great! Let's use that dataset with Machine Learning/Deep learning to create our malware identifier"))
        print(colour_changer.green('\tDo you want to use Supervised or Unsupervised?'))
        print(colour_changer.green("\t\t1. Supervised"))
        print(colour_changer.green("\t\t2. Unsupervised"))
        modelType = input("\t\tModel Type: ")
        if input("1 or 2: ") == "1":
            print(colour_changer.yellow("\tDo you want to use:"))
            print(colour_changer.green("\t\t1. Machine Learning"))
            print(colour_changer.green('\t\t2. Deep learning'))
            print(colour_changer.green('\t\t3. Deep learning'))
            print(colour_changer.green('\t\t4. Deep learning'))
            modelSelect = input("\t\tModel Select: ")
            if modelSelect == "1":
                print(colour_changer.yellow("\tWhere do you want to store the model of your newly created machine learning classifier?"))
                location = input("Location: ")
                classifier = MalwareIdentifier(master_doc_output_loc, location)
                print(colour_changer.yellow('\tWould you like to visualise the results? '))
                if input("(y or n): ") == "y":
                    graph = Visualiser(classifier.visual_data_return())
                else:
                    pass
            elif modelSelect == "2":
                while True:
                    print(colour_changer.yellow(
                        "\tWhere do you want to store the model of your newly created Deep Learning classifier?"))
                    location = input(": ")
                    print(colour_changer.yellow("\tHow many layers do you want to use? "))
                    hiddenLayerCount = input("\t\tLayer Count: ")
                    allNeuronCount = []
                    print(colour_changer.yellow("\tHow many epochs? "))
                    epochCount = input("\t\tEpoch Count: ")
                    print(colour_changer.yellow("\tHow many neurons per layer? "))
                    for i in range(int(hiddenLayerCount)):
                        print('\tLayer: {} add neurons'.format(colour_changer.red(str(i))))
                        neuroncount = input("\t\tNeuron Count: ")
                        allNeuronCount.append(neuroncount)

                    print(colour_changer.yellow("\tDoes this look ok to you?"))
                    print("\t\tModel output location: ", colour_changer.red(location))
                    print('\t\tHidden Layer Count: ', colour_changer.red(hiddenLayerCount))
                    for i in range(len(allNeuronCount)):
                        print("\t\tLayer {} Neuron Count: {}".format(colour_changer.red(str(i)),
                                                                 colour_changer.red(allNeuronCount[i])))

                    confirm = input('\t\t(y or n): ')

                    if confirm == "y":

                        classifier = Deepnn(master_doc_output_loc, location, hiddenLayerCount, allNeuronCount,
                                            epochCount)
                        print(colour_changer.yellow('\tWould you like to visualise the results? '))
                        if input("\t\ty or n: ") == "y":
                            graph = Visualiser(classifier.visual_data_return())
                        else:
                            pass
                    else:
                        # Jump back to start avoiding the break if confirm not met
                        continue

                    break
            elif modelSelect == "3":
                print(colour_changer.yellow(
                    "\tWhere do you want to store the model of your newly created machine learning classifier?"))
                location = input("\t\t: ")
                classifier = RandomForrestClassifier(master_doc_output_loc, location)
                print(colour_changer.yellow('\tWould you like to visualise the results? '))
                if input("\t\ty or n: ") == "y":
                    graph = Visualiser(classifier.visual_data_return())
            elif modelSelect == "4":
                print(colour_changer.yellow(
                    "\tWhere do you want to store the model of your newly created DT machine learning classifier?"))
                location = input("\t\t: ")
                classifier = DecisionTreeC(master_doc_output_loc, location)
                print(colour_changer.yellow('\tWould you like to visualise the results? '))
                if input("\t\ty or n: ") == "y":
                    graph = Visualiser(classifier.visual_data_return())
            else:
                print(colour_changer.red('Only 4 Options exist. Restart the program and choose from one the 4'))
                exit()

    print(colour_changer.red("DEVELOPED AS PART OF A MASTERS FOR THE UNIVERSITY OF THE WEST OF SCOTLAND"))
    print(colour_changer.red("Developer: Christopher Troy"))
