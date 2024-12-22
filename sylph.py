#!/usr/bin/env python3
from colorama import *
import os

init(autoreset=True)


def banner():
	print(f"""{Fore.BLACK} {Style.BRIGHT}
 ___  _  _  __    ____  _   _ 
/ __)( \/ )(  )  (  _ \( )_( )
\__ \ \  /  )(__  )___/ ) _ ( 
(___/ (__) (____)(__)  (_) (_)
                        intframework
                        {Style.RESET_ALL}
	""")
def __user__():
	banner()
	print("please export INTFRAMEWORK_PATH and run this script")
	os.system("cp modules/* $INTFRAMEWORK_PATH/modules/")
	os.system("chmod +x bin/*")
	os.system("cp bin/* $PREFIX/bin/")
	print(f"{Fore.GREEN}[+] Finished ...")
	print(f"{Fore.BLUE}[~] Example: use intframework::modules::exploits::android::Janus::exploit")
	print(f"{Fore.BLUE}[~] And run : run <--help>")
	print(f"{Fore.BLUE}[~] running your exploit...")
	print(Style.RESET_ALL)
if __name__ == "__main__":
	__user__()
