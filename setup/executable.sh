#!/bin/bash
cd $HOME
echo "Making supersploit executable"
printf '#include <stdio.h>\nint main(){\nsystem("bash $HOME/.SuperSploit/start.sh");}' > supersploit.c

echo "Compiling executable"
gcc supersploit.c -o supersploit

echo "Moving  supersploit to /bin folder"
sudo mv supersploit /bin/supersploit && rm supersploit.c

echo "Making desktop file and app drawer icon"
printf "[Desktop Entry]\nName=supersploit\nComment=Exploit Management framework\nExec=/bin/supersploit\nIcon=/usr/share/icons/locolor/16x16/apps/logo1.png\nTerminal=true\nType=Application\nCategories=Exploitation Tools" > supersploit.desktop
sudo cp supersploit.desktop /usr/share/applications/

echo "Moving icon"
sudo cp $HOME/.SuperSploit/.data/.assets/logo1.png /usr/share/icons/locolor/16x16/apps/

echo "Changing permissions for executable file"
sudo chmod +x /bin/supersploit

echo "Cleaning up"
# sudo rm supersploit.desktop supersploit.c
cd $HOME/.SuperSploit

python3 setup.py
