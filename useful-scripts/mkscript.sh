#!/bin/bash

#header----------------------------------------------------------------------------------------

# scriptname:            mkscript
# scriptversion:         1.0.0
# script description:    this script make basic scripts with inidividuel headers and permission
# creater:               Timon Bachmann
# create datetime:       2023.12.01 22:00:00

#script----------------------------------------------------------------------------------------

# ask for script version
echo "-> Option minimal:  Create a new file with a small header (without description) in the current directory."
echo "-> Option short:    Create a new file with a small header in the current directory and assign file permission."
echo "-> Option long:     Create a new file with a full header, choose a custom directory and assign file permission."
while true; do # the check-loop begins
	read -p "Choose an option for how the new script should be created [minimal/short/long]# " scriptform
	case "$scriptform" in
		minimal|short|long)
			break # exit the loop								
			;;
		*)
			echo "-> Invalid choice. Please enter 'minimal', 'short', or 'long'."
			;;
	esac
done # the check-loop end


#questions for file-----------------------------------------------------------------------------

# ask for scriptname & path variable
read -p "-> What should the new script be called? (without suffix)# " scriptname
read -p "-> Which version is this script? # " scriptversion
	
if [ "$scriptform" = "long" ]; then # The custum path begins
	while true; do # the "YesNo"-Loop begins
		read -p "-> The file has a different path? [Y/n]# " differentstoragepath
		case "$differentstoragepath" in
			[YyNn]*)
				break # exit the loop								
				;;
			*)
				echo "-> Invalid choise. Please enter 'Y'/'y' for yes or 'N'/'n' for no"
				;;
		esac
	done # the "YesNo"-Loop end
	if [ "$differentstoragepath" = "Y" ] || [ "$differentstoragepath" = "y" ]; then
		while true; do # The "define costum storage path"-loop begins
			read -p "-> What is the custom storage path?# " costumstoragepath
			if [ -d "$costumstoragepath" ]; then
				break  # the path exists, exit the loop
			else
				echo "-> The specified storage path does not exist: $costumstoragepath"
				while true; do #The "wrong choice"-loop begins
					read -p "-> Do you want to abort the script or provide the storage path again? [Abort/Retry]# " choice
					case "$choice" in
						["Abort"]*)
							echo "-> Script aborted."
							exit 1
							;;
						["Retry"]*)
							break  # re-enter the path
							;;
						*)
							echo "-> Invalid choice. Please enter 'Abort' or 'Retry'."
							;;
					esac
				done # The "wrong choise"-loop begins
			fi
		done # The "define custom storage path"-loop end
	fi
fi # The costum path end

# ask for general file contents variable
while true; do # The check-loop beginns
	read -p "-> What's your first name?# " createrfirstname	
	if [ -n "$createrfirstname" ]; then
		break # exit the loop
	fi
done # The check-loop end
while true; do # The check-loop beginns	
	read -p "-> What's your last name?# " createrlastname
	if [ -n "$createrlastname" ]; then
		break #exit the loop
	fi
done # The check-loop end

if [ "$scriptform" = "long" ]; then
	# ask for long format file contents variable
	read -p "-> What is the description of the script? What is the purpose of the script?# " scriptdescription
fi

#questions for permission----------------------------------------------------------------------

if [ "$scriptform" = "long" ] || [ "$scriptform" = "short" ]; then
	while true; do # the "YesNo"-Loop begins
		read -p "-> Do you want to grant permission for this file? [Y/n]# " grantpermissons
		case "$grantpermissons" in
			[YyNn]*)
				break # exit the loop								
				;;
			*)
				echo "-> Invalid choise. Please enter 'Y'/'y' for yes or 'N'/'n' for no"
				;;
		esac
	done # the "YesNo"-Loop end
	if [ "$grantpermissons" = "Y" ] || [ "$grantpermissons" = "y" ]; then # grant permission begins
		while true; do # the "permission"-loop begins
			echo "-> Explanation: Select one of these permission values for user, group and other."          
			echo "-> 0: --- (no permissons)"
			echo "-> 1: --x (execute-only)"
			echo "-> 2: -w- (write-only)"
			echo "-> 3: -wx (write & execute)"
			echo "-> 4: r-- (read-only)"
			echo "-> 5: r-x (read & execute)"
			echo "-> 6: rw- (read & write)"
			echo "-> 7: rwx (full permisson)"
			read -p "-> What permission do you want to give to user | group | other? [ugo]# " permission
			userpermission=$((${permission:0:1}))
			grouppermission=$((${permission:1:1}))
			otherpermission=$((${permission:2:1}))
			case "$userpermission" in
				[0-7]*)
					case "$grouppermission" in
						[0-7]*)
							case "$otherpermission" in
								[0-7]*)
									break # Exit the loop
									;;
								*)
									echo "-> Invalid choice for 'other'. Please enter a number between 0 and 7."
									;;
							esac
							;;
						*)
							echo "-> Invalid choice for 'group'. Please enter a number between 0 and 7."
							;;
					esac
					;;
				*)
					echo "-> Invalid choice for 'user'. Please enter a number between 0 and 7."
					;;
			esac
			sleep 1
		done # The permission loop ends
	fi
fi
#questions for ending----------------------------------------------------------------------

# ask whether the file should be opened after creation
while true; do # The "YesNo" loop begins
	read -p "-> Should the file be opened after creation? [Y/n]# " openaftercreation
		case $openaftercreation in
			[YyNn]*)
				break # Exit the loop								
				;;
			*)
				echo "-> Invalid choice. Please enter 'Y'/'y' for yes or 'N'/'n' for no"
				;;
		esac
done # The "YesNo" loop ends

if [ "$openaftercreation" = "Y" ] || [ "$openaftercreation" = "y" ]; then
	read -p "-> What should the file be opened with? [vim/nano/cat]# " whicheditor
fi


# define fix variables
filename=$scriptname\.sh
partingline="#----------------------------------------------------------------------------------------------"
partinglineheader="#header----------------------------------------------------------------------------------------"
partinglinescript="#script----------------------------------------------------------------------------------------"
currentdate=$(date +'%Y.%m.%d %H:%M:%S')

# define storagepath
if [ "$differentstoragepath" = "Y" ] || [ "$differentstoragepath" = "y" ]; then
	if [ -z "$costumstoragepath" ] || [ "$costumstoragepath" = "/" ]; then
		# If $costumstoragepath is empty or "/", create in the current directory
		destination=$costumstoragepath$filename
	else
		# Otherwise create in the specified directory
		destination=$costumstoragepath/$filename
	fi
else
	# If not, create in the current directory
	destination=$filename
fi

#run-------------------------------------------------------------------------------------------

# create new file
touch $destination

# insert text line into file
echo "#!/bin/bash" >> $destination 
echo $partinglineheader >> $destination
echo "# scriptname:            $scriptname" >> $destination
echo "# scriptversion:         $scriptversion" >> $destination
echo "# script description:    $scriptdescription" >> $destination
echo "# creator:               $createrfirstname $createrlastname" >> $destination
echo "# creator (sysuser):     $(whoami)" >> $destination
echo "# create datetime:       $currentdate" >> $destination
echo "# permissions:			   $permission" >> $destination
echo $partinglinescript >> $destination
echo "" >> $destination

#done-----------------------------------------------------------------------------------------

# creation completed
if [ $? -eq 0 ]; then
	echo "-> The file $filename was created successfully."
else
	echo "-> The file $filename wasn't created successfully."
fi	

if [ "$grantpermissons" = "Y" ] || [ "$grantpermissons" = "y" ]; then
	chmod $permission $destination
fi

# open the file with editor
if [ "$openaftercreation" = "Y" ] || [ "$openaftercreation" = "y" ]; then
    $whicheditor $destination
fi