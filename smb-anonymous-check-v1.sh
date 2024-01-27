#!/usr/bin/bash
# Author: Jason Brewer
# Enumerate Shares and testing for Anonymous access


function helper() {

	smbArt
	echo -e "Usage: \n"
	echo " -h	Help Menu"
	echo " -f 	File containing IPs"
	echo " -w	Write results to file"
	echo -e "
	Ex 1: ${0##*/} -f ips.txt\n
	Ex 2: ${0##*/} -f ips.txt -w outfile.txt\n"

}

function checkReqs() {

	smbArt
	runCmd=$(dpkg -s figlet 2>/dev/null) 
	getStatus=$?

	if [ $getStatus -ne 0 ]; then
	echo -e "\n[!] You must install figlet: sudo apt install figlet [!]\n"
	fi

}


function smbArt() {

	figlet "SMB CHECKER"

}


function delim() {

	printf '%50s\n' | tr ' ' '='

}

function runSMB() {
	
	smbArt
	declare -a shareArray

	while IFS= read -r ips; do 

	runCmd=$(smbclient -L \\\\$ips -N 2>/dev/null)
	getStatus=$?

	if [ $getStatus -eq 0 ]; then
	delim 
	echo -e "\n[+] Scanning: $ips [+]\n"
	delim 
	echo "$runCmd" 2>/dev/null | grep -v 'Reconnecting' | grep -v 'Unable'
	
	shares=$(echo "$runCmd" | grep -iv 'reconnecting' | grep -iv 'unable' | grep -iv 'tree' | grep -v "Sharename" | egrep -v '\---'  | awk '{print $1}')
	for share in $shares ; do 
		shareArray+=("$ips/$share")
	done
	fi

	delim 

done < $IPS

	for share in "${shareArray[@]}"; do
		echo -e "\n$share Contents\n"
		IFS='/' read -r ip shareName <<< "$share"
		smbclient \\\\$ip\\$shareName -N -c 'ls' 2>/dev/null
		echo -e '\n' 
		delim
	done

}

if [[ $1 == "-h" ]] || [[ $# -eq 0 ]]; then
	helper
	exit
fi

IPS=""
WRITEFILE=""

while getopts ":hf:w:" arg; do

	case $arg in 

	f) IPS=$OPTARG
		;;

	h) helper
		;;

	w) WRITEFILE=$OPTARG
		;;
	
	*)
		echo -e "\n[!] Error: Unsupported Flag $OPTARG" >&2
		exit 1
		;;
	esac
done

shift $((OPTIND-1))

if [[ -n $IPS ]] ; then
	if [[ -n $WRITEFILE ]]; then
		runSMB | tee -a $WRITEFILE
		echo -e "\n\n[+] Results saved to: $WRITEFILE\n"
	else
		runSMB
	fi
fi

