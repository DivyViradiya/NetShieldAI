import logging
import os
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Define Custom Level
SUCCESS_LEVEL = 25
logging.addLevelName(SUCCESS_LEVEL, 'SUCCESS')

# Add helper method to Logger class
def success(self, message, *args, **kwargs):
    if self.isEnabledFor(SUCCESS_LEVEL):
        self._log(SUCCESS_LEVEL, message, args, **kwargs)
logging.Logger.success = success

class ColoredFormatter(logging.Formatter):
    """Custom formatting with colors and tags for different log levels."""
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.BLUE + Style.BRIGHT,
        'SUCCESS': Fore.GREEN + Style.BRIGHT,
        'WARNING': Fore.YELLOW + Style.BRIGHT,
        'ERROR': Fore.RED + Style.BRIGHT,
        'CRITICAL': Fore.MAGENTA + Style.BRIGHT,
    }

    TAGS = {
        'DEBUG': '[D]',
        'INFO': '[*]',
        'SUCCESS': '[+]',
        'WARNING': '[!]',
        'ERROR': '[!]',
        'CRITICAL': '[!]',
    }

    def format(self, record):
        log_color = self.COLORS.get(record.levelname, Fore.WHITE)
        tag = self.TAGS.get(record.levelname, f"[{record.levelname}]")
        
        colored_tag = f"{log_color}{tag}{Style.RESET_ALL}"
        
        # Adding color to the timestamp
        timestamp = f"{Fore.WHITE}{Style.DIM}%(asctime)s{Style.RESET_ALL}"
        module_name = f"{Fore.GREEN}[%(module)s]{Style.RESET_ALL}"
        
        # Format string (no extra brackets around colored_tag)
        format_str = f"[{timestamp}] {colored_tag} {module_name} %(message)s"
        
        formatter = logging.Formatter(format_str, datefmt='%Y-%m-%d %H:%M:%S')
        return formatter.format(record)


def setup_logger():
    """Sets up and returns the main NetShieldAI logger."""
    logger = logging.getLogger('NetShieldAI')
    
    # Only configure if no handlers are present to avoid duplicate logs
    if not logger.handlers:
        logger.setLevel(logging.DEBUG)
        logger.propagate = False  # Prevent propagation to root logger to avoid duplicate logs
        
        # Console Handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)  # Change to DEBUG for more verbosity
        ch.setFormatter(ColoredFormatter())
        logger.addHandler(ch)
        
        # File Handler (.logs/app_runtime.log)
        log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.logs')
        os.makedirs(log_dir, exist_ok=True)
        fh = logging.FileHandler(os.path.join(log_dir, 'app_runtime.log'), encoding='utf-8')
        fh.setLevel(logging.DEBUG)
        
        # Standard formatter for file (no colors)
        file_formatter = logging.Formatter(
            '[%(asctime)s] [%(levelname)-8s] [%(module)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        fh.setFormatter(file_formatter)
        logger.addHandler(fh)

        # Suppress overly verbose libraries
        logging.getLogger('werkzeug').setLevel(logging.ERROR)
        logging.getLogger('pyngrok').setLevel(logging.WARNING)
        
    return logger

# Single instance to be imported across the application
logger = setup_logger()
