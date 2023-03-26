from gato.cli import (RED_DASH, GREEN_PLUS, GREEN_EXCLAIM, RED_EXCLAIM,
                      BRIGHT_DASH, YELLOW_EXCLAIM, SPLASH, YELLOW_DASH)


from colorama import Style, Fore


class Singleton (type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(
                *args, **kwargs
            )
        return cls._instances[cls]


class Output(metaclass=Singleton):

    def __init__(self, silent: bool, color: bool):
        self.silent = silent
        self.color = color

        self.red_dash = RED_DASH if color else '[-]'
        self.red_explain = RED_EXCLAIM if color else '[!]'
        self.green_plus = GREEN_PLUS if color else '[+]'
        self.green_exclaim = GREEN_EXCLAIM if color else '[!]'
        self.bright_dash = BRIGHT_DASH if color else '-'
        self.yellow_exclaim = YELLOW_EXCLAIM if color else "[!]"
        self.yellow_dash = YELLOW_DASH if color else "[-]"

    @classmethod
    def splash(cls):
        """Prints the Gato mascot.
        """
        if not Output().silent:
            print(SPLASH)

    @classmethod
    def error(cls, message: str):
        """Prints error text.

        Args:
            message (str): Message to format.
        """
        print(f"{Output().red_dash} {message}")

    @classmethod
    def info(cls, message: str):
        """Prints info text, this adds a green [+] to the message.

        Args:
            message (str): The message to print.
        """
        print(f"{Output().green_plus} {message}")

    @classmethod
    def tabbed(cls, message: str):
        """Prints a tabbed message with a bright '-'

        Args:
            message (str): The message to print.
        """
        print(f"    {Output().bright_dash} {message}")

    @classmethod
    def header(cls, message: str):
        """Prints a message surrounded by '---'

        Args:
            message (str): The message to print.
        """
        print(
            f"{cls.bright('---')}"
            f" {message} "
            f"{cls.bright('---')}"
        )

    @classmethod
    def result(cls, message: str):
        """Prints a result, this is something good that the tool found.

        Args:
            message (str): The message to print.
        """
        print(f"{Output().green_plus} {message}")

    @classmethod
    def owned(cls, message: str):
        """Prints a result, this is means that the tool has found a likely
        vector to own something.

        Args:
            message (str): The message to print.
        """
        print(f"{Output().green_exclaim} {message}")

    @classmethod
    def inform(cls, message: str):
        """Used to inform a user.

        Args:
            message (str): The message to print.
        """

        print(f"{Output().yellow_dash} {message}")

    @classmethod
    def warn(cls, message: str):
        """Used to let the user know something that they should not, but
        unlikely to lead to an exploit.
        """
        print(f"{Output().yellow_exclaim} {message}")

    @classmethod
    def bright(cls, toformat: str):
        """Highlights the text and returns it.

        Args:
            toformat (str): Message to format.

        Returns:
            (str): Highlighted text.
        """

        if cls not in cls._instances or Output().color:
            return f'{Style.BRIGHT}{toformat}{Style.RESET_ALL}'
        else:
            return toformat

    @classmethod
    def yellow(cls, toformat: str):
        """Makes the text yellow and returns it.

        Args:
            toformat (str): Message to format.

        Returns:
            (str)): Formatted message.
        """
        if cls not in cls._instances or Output().color:
            return f'{Fore.YELLOW}{toformat}{Style.RESET_ALL}'
        else:
            return toformat

    @classmethod
    def green(cls, toformat: str):
        """Makes the text green and returns it.

        Args:
            toformat (str): Message to format.

        Returns:
            (str)): Formatted message.
        """
        if cls not in cls._instances or Output().color:
            return f'{Fore.GREEN}{toformat}{Style.RESET_ALL}'
        else:
            return toformat
