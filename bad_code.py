import subprocess

subprocess.Popen("os.system('rm -rf /')")  # HIGH: использование os.system с переменной/подстановкой
