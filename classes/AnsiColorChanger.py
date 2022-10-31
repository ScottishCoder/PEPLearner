from colorama import Fore, init, Style
init()

class ColourChange():

    def red(self, text):
        text = Style.BRIGHT + Fore.RED + text + Fore.RESET + Style.RESET_ALL
        return text

    def blue(self, text):
        text = Style.BRIGHT + Fore.BLUE + text + Fore.RESET + Style.RESET_ALL
        return text

    def cyan(self, text):
        text = Style.BRIGHT + Fore.CYAN + text + Fore.RESET + Style.RESET_ALL
        return text

    def magenta(self, text):
        text = Style.BRIGHT + Fore.MAGENTA + text + Fore.RESET + Style.RESET_ALL
        return text

    def green(self, text):
        text = Style.BRIGHT + Fore.GREEN + text + Fore.RESET + Style.RESET_ALL
        return text

    def white(self, text):
        text =  Style.BRIGHT + Fore.WHITE + text + Fore.RESET + Style.RESET_ALL
        return text

    def yellow(self, text):
        text = Style.BRIGHT + Fore.YELLOW + text + Fore.RESET + Style.RESET_ALL
        return text
