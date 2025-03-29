#!/bin/bash
#header----------------------------------------------------------------------------------------
# scriptname:					install_virtualbox_on_linux
# scriptversion:				v1.0
# script description:		This script installs VirtualBox automatically on your Linux system.
# creator:						Timon Bachmann
# creator (sysuser):		timon
# create datetime:			2024.04.06 11:23:46
# permissions:				
#script----------------------------------------------------------------------------------------

echo "--------------------------------------------------------------------------------------"

installMode=""
while [ "$installMode" != "v" ] && [ "$installMode" != "e" ]; do
	read -p "-> Do you want to install VirtualBox (v) or just extension packs (e)? [v/e] " installMode
	installMode=$(echo "$installMode" | tr '[:upper:]' '[:lower:]') # Convert to lowercase
done

case $installMode in
	v)
		installMode="virtualbox"
		;;
	e)
		installMode="extension"
		;;
	*)
		exit
		;;
esac

while true; do
case $installMode in
	virtualbox) # install VirtualBox
		# check if VirtualBox is already installed
		if dpkg-query -l | grep -q virtualbox; then # Check if VirtualBox package is installed
			answer="" # Redefine the variable 'answer' as empty
			while [ "$answer" != "y" ] && [ "$answer" != "n" ]; do # Loop until a valid answer is provided
				read -p "-> VirtualBox is already installed. Are you sure you want to reinstall VirtualBox? [Y/n] " answer
				answer=$(echo "$answer" | tr '[:upper:]' '[:lower:]') # Convert the answer to lowercase
			done
			if [ "$answer" == "n" ]; then # If the answer is 'n' (no), exit the script
				exit
			fi
		fi


		# Checking if Secure Boot is enabled
		if [ "$(sudo mokutil --sb-state | cut -d' ' -f2)" != "disabled" ]; then # If Secure Boot is not disabled
			echo "Secure Boot has been detected as $(sudo mokutil --sb-state | cut -d' ' -f2) on this device."

			answer="" # Redefining the variable 'answer' as empty
			while true; do
				if [ "$answer" != "no" ]; then # If the next loop returns "No", this branch won't execute
					read -p "-> Are you sure Secure Boot has been disabled on this device? [yes/no] " answer
					answer=$(echo "$answer" | tr '[:upper:]' '[:lower:]') # Convert to lowercase
				fi

				case $answer in
					yes|y)
						answer="" # Redefining the variable 'answer' as empty
						while [ "$answer" != "sure" ] && [ "$answer" != "no" ]; do
							read -p "-> Are you sure you want to continue despite Secure Boot being activated? [sure/no] " answer
							answer=$(echo "$answer" | tr '[:upper:]' '[:lower:]') # Convert to lowercase
						done

						if [ "$answer" == "sure" ]; then
							break
						else
							answer="no" # Redefining the variable 'answer' to "no".
						fi
						;;
					no|n) # Instructions to disable Secure Boot are provided
						echo "--------------------------------------------------------------------------------------"
						echo "Instructions to Disable Secure Boot:"
						echo
						echo "   1. Restart your computer and press the corresponding key during startup"
						echo "      to access the UEFI or BIOS menu. The exact key may vary depending"
						echo "      on the manufacturer, but common keys include 'F2', 'Del', 'Esc', or 'F10'."
						echo
						echo "   2. Navigate to the security settings or Secure Boot options in the UEFI/BIOS menu."
						echo
						echo "   3. Find the option that enables or disables Secure Boot. Select the option"
						echo "      and change the status from 'Enabled' to 'Disabled' or 'Off'."
						echo
						echo "   4. Confirm the changes and save them in the UEFI/BIOS menu."
						echo
						echo "   5. Restart the computer to apply the changes."
						echo "--------------------------------------------------------------------------------------"

						shutdown="" # Redefining the variable 'shutdown' as empty
						while [ "$shutdown" != "shutdown" ] && [ "$shutdown" != "no" ]; do
							read -p "-> Should the device be shut down? [shutdown/no] " shutdown
							shutdown=$(echo "$shutdown" | tr '[:upper:]' '[:lower:]') # Convert to lowercase
						done
						if [ "$shutdown" == "shutdown" ]; then
							sudo shutdown
						fi
						break
						;;
				esac
			done
		fi # end check Secure Boot

		# install virtualbox-dkms
		sudo dpkg --configure -a
		sudo apt update
		sudo apt install --reinstall virtualbox-dkms -y

		# check kernel module
		sudo modprobe vboxdrv

		# install virtualbox
		sudo apt install --reinstall virtualbox -y

		echo "--------------------------------------------------------------------------------------"
		echo "-> VirtualBox and virtualbox-dkms are now installed."
		answer="" # Redefining the variable 'answer' as empty
		while [ "$answer" != "y" ] && [ "$answer" != "n" ]; do
			read -p "-> Do you want to install extensions? If not, the script will terminate. [Y/n] " answer
			answer=$(echo "$answer" | tr '[:upper:]' '[:lower:]') # Convert to lowercase
		done
		if [ "$answer" == "y" ]; then
			installMode="extension"
		else
			exit
		fi
		;; # end install VirtualBox

	extension) # install extension packs
		VBOX_VERSION=$(VBoxManage --version | cut -d '_' -f1)
		if [ -z "$VBOX_VERSION" ]; then # check if 
			echo "-> The VBOX version cannot be read. The script has ended."
			exit
		fi
		
		echo "--------------------------------------------------------------------------------------"
		echo "-> You can install the following Extension-Packs ($VBOX_VERSION):"
		echo
		echo "      0) I'm done, please terminate the script" 
		echo "      1) USB 2.0 and 3.0 extensions"
		echo
		echo "--------------------------------------------------------------------------------------"
		read -p "-> Which package do you want to install? [0-1] " installPack

		case $installPack in
			0) # script terminated
				exit
				;;
			1)	# Install USB 2.0 and 3.0 extensions
				wget https://download.virtualbox.org/virtualbox/$VBOX_VERSION/Oracle_VM_VirtualBox_Extension_Pack-$VBOX_VERSION.vbox-extpack	# Downloading the Extension Packs
				sudo VBoxManage extpack install Oracle_VM_VirtualBox_Extension_Pack-$VBOX_VERSION.vbox-extpack	# Installing the Extension Packs
				rm Oracle_VM_VirtualBox_Extension_Pack-$VBOX_VERSION.vbox-extpack	# Cleanup: Deleting the downloaded Extension Packs
				;; # end install USB 2.0 and 3.0 extensions
		esac
		;; # end install extension packs
esac
done