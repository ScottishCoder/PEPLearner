import glob


class EXE_Path_Hunter:

    def recursive_search(self, path):
        data = glob.glob(path + '/**/*.exe', recursive=True)
        return data

    def non_recursive_search(self, path):
        data = glob.glob(path + '/*.exe')
        return data


