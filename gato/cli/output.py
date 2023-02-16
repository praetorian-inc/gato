from gato.cli import RED_DASH, GREEN_PLUS, GREEN_EXCLAIM, BRIGHT_DASH, YELLOW_EXCLAIM
from gato.cli import SPLASH


class Output:
    def __init__(self, silent: bool, color: bool):
        self.silent = silent

        self.red_dash = RED_DASH if color else '[-]'
        self.green_plus = GREEN_PLUS if color else '[+]'
        self.green_exclaim = GREEN_EXCLAIM if color else '[!]'
        self.bright_dash = BRIGHT_DASH if color else '-'
        self.yellow_exclaim = YELLOW_EXCLAIM if color else "[-]"

    def splash(self):
        if not self.silent:
            print(SPLASH)

    def error(self, message: str, parser=None):
        if parser:
            parser.error(f"{self.red_dash} {message}")
        else:
            print(f"{self.red_dash} {message}")

    def info(self, message: str):
        if not self.silent:
            print(f"{self.green_plus} {message}")

    def tabbed(self, message: str):
        if not self.silent:
            print(f"    {self.bright_dash} {message}")

    def result(self, message: str):
        print(f"{self.green_exclaim} {message}")

    def warn(self, message: str):
        print(f"{self.yellow_exclaim} {message}")
