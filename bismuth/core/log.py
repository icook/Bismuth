import logging, sys
from logging.handlers import RotatingFileHandler



def filter_status(record):
    """"
    Only displays log messages about status info
    or ERROR level
    """
    if ("Status:" in str(record.msg)) or (record.levelname == 'ERROR'):
        return 1
    else:
        return 0

BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)

#The background is set with 40 plus the number of the color, and the foreground with 30

#These are the sequences need to get colored ouput
RESET_SEQ = "\033[0m"
COLOR_SEQ = "\033[1;%dm"
BOLD_SEQ = "\033[1m"

def formatter_message(message, use_color = True):
    if use_color:
        message = message.replace("$RESET", RESET_SEQ).replace("$BOLD", BOLD_SEQ)
    else:
        message = message.replace("$RESET", "").replace("$BOLD", "")
    return message

COLORS = {
    'WARNING': YELLOW,
    'INFO': WHITE,
    'DEBUG': BLUE,
    'CRITICAL': YELLOW,
    'ERROR': RED
}

class ColoredFormatter(logging.Formatter):
    def __init__(self, msg, use_color = True):
        logging.Formatter.__init__(self, msg)
        self.use_color = use_color

    def format(self, record):
        levelname = record.levelname
        if self.use_color and levelname in COLORS:
            levelname_color = COLOR_SEQ % (30 + COLORS[levelname]) + levelname + RESET_SEQ
            record.levelname = levelname_color
        return logging.Formatter.format(self, record)



def log(logFile, level_input="WARNING", terminal_output=False):
    if level_input == "NOTSET":
        level = logging.NOTSET
    if level_input == "DEBUG":
        level = logging.DEBUG
    if level_input == "INFO":
        level = logging.INFO
    if level_input == "WARNING":
        level = logging.WARNING
    if level_input == "ERROR":
        level = logging.ERROR
    if level_input == "CRITICAL":
        level = logging.CRITICAL

    log_formatter = logging.Formatter('%(asctime)s %(levelname)s %(funcName)s(%(lineno)d) %(message)s')
    my_handler = RotatingFileHandler(logFile, mode='a', maxBytes=5 * 1024 * 1024, backupCount=2, encoding=None, delay=0)
    my_handler.setFormatter(log_formatter)
    my_handler.setLevel(level)
    app_log = logging.getLogger('root')
    app_log.setLevel(level)
    app_log.addHandler(my_handler)

    # This part is what goes on console.
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    # TODO: We could have 2 level in the config, one for screen and one for files.
    print ("Logging level: {} ({})".format(level_input,level))
    if terminal_output != True:
        ch.addFilter(filter_status)
        # No need for complete func and line info here.
        formatter = logging.Formatter('%(asctime)s %(message)s')
    else:
        FORMAT = "[$BOLD%(name)-10s$RESET][%(levelname)-18s]  %(message)s ($BOLD%(filename)s$RESET:%(lineno)d)"
        COLOR_FORMAT = formatter_message(FORMAT, True)
        formatter = ColoredFormatter(COLOR_FORMAT)
    ch.setFormatter(formatter)
    app_log.addHandler(ch) 

    return app_log
