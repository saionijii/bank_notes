import os

def very_bad_func():
    os.system("rm -rf /")  # Уязвимость: выполнение системных команд
