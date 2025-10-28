import pickle

def insecure_load(data):
    return pickle.loads(data)  # HIGH: небезопасная десериализация
