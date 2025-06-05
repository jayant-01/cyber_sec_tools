import subprocess

profile=input("enter username")
command=f"instaloader {profile}"
subprocess.run(command, shell=True)