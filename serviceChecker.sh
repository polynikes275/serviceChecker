#!/usr/bin/bash
# Author: Jason Brewer (polynikes)
# Automate and enumerate common services with ease


function helper() {

	Art
	echo -e "Usage: \n"
	echo -e " -h\t	Help Menu"
	echo -e " -H-\t\tHelp with usage for all features: -H-http, -H-ffuf, etc.,"
	echo -e " -f\t	File containing IPs, domain names, service account names (svc-something), e.g., support.help : Required Flag for all, usernames"
	echo -e " -w\t	Write results to file"
	echo -e " -D\t	Domain Name"
	echo -e " -C\t	Domain Controller IP"
	echo -e " -T-asrep\tTest for Kerberos pre-authentication (ASREPRoasting attack)"
	echo -e " -S-smb\t\tScanning for smb anonymous access and listing shares"
	echo -e " -S-http\tCurl the website a return those with a status code of '200'"
	echo -e " -S-ffuf\tUse ffuf on the hosts that returned a status code of '200'"
	echo -e " -S-ldap\tScanning for anonymous bind"
	echo -e " -S-smtp\tConnect to smtp server and send innocuous email"
	echo -e " -S-snmp\tConnect to snmp device and dump information"
	echo -e " -S-ftp\t\tConnect to ftp server with anonymous access"
	echo -e " -S-rpc\t\tEnumerate RPC services"
	echo -e " -S-nfs\t\tConnect and enumerate NFS"
	echo -e " -S-vhosts\tSearch for virtual hosts (subdomains) on the provided domain"
	echo -e "
NOTE : To filter out services in Metasploit and saving to file do: services -S ldap -o filename <change out ldap for other services e.g., smb, ftp, telnet, smtp, etc.,\n
       The program automatically parses out the relevant information to run its commands\n
Ex : ${0##*/} -f ips.txt||domains.txt -C 10.10.10.10\n
Ex : ${0##*/} -f ips.txt -S-smb -w smb-artifcats.txt\n
Ex : ${0##*/} -f ips.txt -w outfile.txt\n"

}


function advHELP() {
	Art
	if [[ $HELP == '-ldap' ]]
		then
		echo -e "Usage: Help with using -S-ldap\n"
		echo -e "${0##*/} -f domain.txt -C dc-ip -S-ldap\n"
	fi
	
	if [[ $HELP == '-http' ]]
		then
		echo -e "Usage: Help with using -S-http\n"
		echo -e "${0##*/} -f https-hosts -S-http\n"
	fi

	if [[ $HELP == '-ffuf' ]]
		then
		echo -e "Usage: Help with using -S-fuff\n"
		echo -e "NOTE: Use the output when running the -S-http command as input\n"
		echo -e "${0##*/} -f http-200-status-hosts -S-fuff\n"
	fi

	if [[ $HELP == '-snmp' ]]
		then
		echo -e "Usage: Help with using -S-snmp\n"
		echo -e "${0##*/} -f snmp-hosts -S-snmp\n"
	fi

	if [[ $HELP == '-asrep' ]]
		then
		echo -e "Usage: Help with using -T-asrep\n"
		echo -e "${0##*/} -f list-of-service-accounts/user-names.txt -D something.local -C dc-ip\n"
	fi

	if [[ $HELP == '-rpc' ]]
		then
		echo -e "Usage: Help with using -S-rpc\n"
		echo -e "${0##*/} -S-rpc -f rpc-hosts.txt\n"
	fi				

	if [[ $HELP == '-smb' ]]
		then
		echo -e "Usage: Help with usign -S-smb\n"
		echo -e "${0##*/} -S-smb -f smb-hosts.tx\n"
	fi

	if [[ $HELP == '-smtp' ]]
		then 
		echo -e "Usage: Help with using -S-smtp\n"
		echo -e "${0##*/} -S-smtp -f smtp-hosts.txt\n"
	fi

	if [[ $HELP == '-nfs' ]]
		then 
		echo -e "Usage: Help with using -S-nfs\n"
		echo -e "${0##*/} -S-nfs -f nfs-hosts.txt\n"
	fi
	
	if [[ $HELP == '-ftp' ]]
		then 
		echo -e "Usage: Help with using -S-ftp\n"
		echo -e "${0##*/} -S-ftp -f ftp-hosts.txt\n"
	fi

	if [[ $HELP == '-vhosts' ]]
		then 
		echo -e "Usage: Help with using -S-vhosts\n"
		echo -e "NOTE-1: You will need to place the domain in /etc/hosts. echo "IP" domain | sudo tee -a /etc/hosts : you will need to do this with any virtual hosts as well\n"
		echo -e "NOTE-2: You may need to tweak ffuf's command parameter '-fs' in the program to return better results.\n"
		echo -e "${0##*/} -S-vhosts -D domain-name\n"
	fi
}

function checkReqs() {

	runCmd=$(dpkg -s figlet 2>/dev/null) 
	getStatus=$?

	if [ $getStatus -ne 0 ]; then
	echo -e "\n[!] You must install figlet: sudo apt install figlet [!]\n"
	exit
	fi

	runCmd=$(locate windapsearch.py 2>/dev/null)
	getStatus=$?

	if [ $getStatus -ne 0 ]; then
	echo -e "\n[!] You must git clone  windapsearch.py at: https://github.com/ropnop/windapsearch [!]\n"
	exit
	fi


}


function Art() {

	figlet "POLYNIKES"
	figlet "SERVICE CHECKER"

}


function delim() {

	printf '%50s\n' | tr ' ' '='

}

function smtp() {

	Art	
	while IFS= read -r ips; do 	

	# Change from and to to whomever you would like
	sendEmail -f jodie.head@us-cert.gov -t jodie.head@us-cert.gov -u "Test Email" -m "Team successfully connected to SMTP server and sent an email" -s $ips -o tls=no
	getStatus=$?

	if [ $getStatus -eq 0 ]; then
	delim
	echo -e "\n[+] Connecting and Sending email to: $ips [+]\n"
	delim
	else
		continue
	fi
	
	done < <(cat $IPS | awk -F',' '{print $1}'| cut -d'"' -f 2| grep -v host | uniq)  

}

function ftp_check() {

	Art
	while IFS= read -r ip; do
	delim
	echo "[+] Attempting to connect to FTP server at $ip"
	
	ftp -a "$ip"
	getStatus=$?
	
	if [[ "$getStatus" -eq 0 ]]; then
		echo "[+] Successfully connected to FTP server: $ip"
	    	delim
	else
	    	echo "[-] Failed to connect or perform operations on FTP server: $ip"
	    	delim
	fi
	
	sleep 2
	
    done < <(cat $IPS | awk -F',' '{print $1}' | cut -d'"' -f2 | grep -v host | uniq)
}

function nfs_check() {

	Art
	while IFS= read -r ip; do
	delim
	echo "[+] Attempting to connect to and enumerate NFS at: $ip"
	
	showmount -e "$ip"
	getStatus=$?
	
	if [[ "$getStatus" -eq 0 ]]; then
		echo "[+] Successfully connected to NFS at: $ip"
	    	delim
	else
	    	echo "[-] Failed to connect or perform operations on: $ip"
	    	delim
	fi
	
	sleep 2
	
    done < <(cat $IPS | awk -F',' '{print $1}' | cut -d'"' -f2 | grep -v host | uniq)
}

function rpc_check() {

	Art
	while IFS= read -r ip; do
	delim
	echo "[+] Attempting to connect to RPC services at $ip"
	
	enum4linux -a "$ip"
	getStatus=$?
	
	if [[ "$getStatus" -eq 0 ]]; then
		echo "[+] Successfully connected to RPC services at: $ip"
	    	delim
	else
	    	echo "[-] Failed to connect or perform operations on: $ip"
	    	delim
	fi
	
	sleep 2
	
    done < <(cat $IPS | awk -F',' '{print $1}' | cut -d'"' -f2 | grep -v host | uniq)
}

function snmp_check() {

	Art
	while IFS= read -r ip; do
	delim
	echo -e "\n[+] Attempting to dump snmp information on $ip with snmp-check\n"

	ipPortPair=$(cut -d':' -f1,2 | sed 's/:/  -p /')
	snmp-check $ipPortPair  -w
	getStatus=$?
	delim
	echo -e "\n[+] Attempting to dump snmp information on $ip with snmpwalk\n"
	snmpwalk -v2c -c public "$ip" .1 | egrep -Ei "string|ipaddress" 
	getStatus1=$?
	
	if [[ "$getStatus" -eq 0 ]] && [[ "$getStatus1" -eq 0 ]]; then
		echo -e "\n[+] Successfully connected to snmp service at: $ip\n"
	    	delim
	fi
	
	sleep 2
	
    done < <(cat $IPS | awk -F',' '{print $1":"$2}' | cut -d'"' -f2,3,4 | sed 's/":"/:/' | grep -v host | uniq)
}

function vhosts() {

	Art
	#while IFS= read -r ip; do
	delim
	echo -e "\n[+] Attempting to discover virtual hosts on $DOMAINNAME\n"

	ffuf -u "http://$DOMAINNAME" -H "Host: FUZZ.$DOMAINNAME" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -c -t 40 -fs 7069
	getStatus=$?
	delim
	
	if [[ "$getStatus" -eq 0 ]] 
		then
		echo -e "\n[+] Successfully discovered virutalhost(s) on: $DOMAINNAME\n"
		delim
	else
		continue
	fi
	
	sleep 2
	
    #done < <(cat $IPS | awk -F',' '{print $1}' | cut -d'"' -f2 | grep -v host | uniq)


}


function asrep() {

	Art
	while IFS= read -r p; do
	delim
	echo "[+] Performing ASREPRoasting Attack (Kerberos pre-authentication) on: $CONTROLLER"

	# This was for testing on a different machine	
	#timeout 20s impacket.GetNPUsers $DOMAINNAME/"$p" -request -no-pass -dc-ip "$CONTROLLER" 
	#getStatus1=$?
	getHash=$(timeout 1s impacket-GetNPUsers $DOMAINNAME/"$p" -request -no-pass -dc-ip "$CONTROLLER")
	
	if [[ "$getHash" == *'$krb5asrep'* ]]; then
		echo -e "[+] Successfully captured hashes for user: $p\n"
		echo "$getHash"
	    	delim
	else
	    	echo "[-] Failed to capture hashes for: $p"
	    	delim
	fi
	
	sleep 2
	
    done < <(cat $IPS | awk -F',' '{print $1}' | cut -d'"' -f2 | grep -v host | uniq)

}

function http() {

	Art
	while IFS= read -r hst ; do
	runCmd=$(curl -s -k -I http://$hst)
	if [[ "$runCmd" == *'200'* ]]; then
		echo -e "[+] Response Code 200 for this pairing: $hst\n"
		delim	
	else
		continue
	fi
	done < <(cat $IPS | awk -F"," '{print $1,$2}' | grep -v ^host | sed 's/"//g' | sed 's/ /:/g')

}

function runFuff() {

	Art
	declare -a ffufHosts 
	getHosts=$(cat $IPS | awk -F":" '{print $2":"$3}' | grep -v "^:" | sed 's/ //')
	for fhost in $getHosts; do
		ffufHosts+=("$fhost")
	done
	for fhost in "${ffufHosts[@]}"; do
		echo -e "\n[+] Fuzzing: $fhost\n";
		ffuf -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://$fhost/FUZZ -mc 200,301,302,403 -fs 10701 | grep -v "#" | grep -E "200|301|302|403";
	#runCmd=$(cat $IPS | awk -F":" '{print $2":"$3}' | grep -v "^:" | sed 's/ //' | while IFS= read -r hst; do ffuf -s -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://$hst/FUZZ -mc 200,301,302,403; done)
	#echo "$runCmd"
	getStatus=$?

	if [ $getStatus -eq 0 ]; then
		echo -e "\n[+] Succesfully fuzzed: $fhost\n"
		delim	
	fi
	done

}

function ldap() {

	Art	
	while IFS= read -r ip; do 	

	runCmd=$(windapsearch.py -d $ip --dc-ip $CONTROLLER -U --custom "objectClass=*")
	echo $runCmd >& /dev/null
	getStatus=$?

	if [ $getStatus -eq 0 ]; then
	delim
	echo -e "\n[+] Scanning: $ip [+]\n"
	delim
	windapsearch.py -d $ip --dc-ip $CONTROLLER -U --custom "objectClass=*"
	else
		echo -e "\n[-] Nothing discoverd for $ip [-]\n"
	fi

	done < <(cat $IPS | awk -F',' '{print $6}' | cut -d":" -f 2 | grep -v info | uniq) 
}

function runSMB() {
	
	Art
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

done < <(cat $IPS | awk -F',' '{print $1}'| cut -d'"' -f 2| grep -v host)

	for share in "${shareArray[@]}"; do
		echo -e "\n$share Contents\n"
		IFS='/' read -r ip shareName <<< "$share"
		smbclient \\\\$ip\\$shareName -N -c 'ls' 2>/dev/null
		echo -e '\n' 
		delim
	done

}

if [[ $1 == "-h" ]] || [[ $# -eq 0 ]]; then
	checkReqs
	helper
	exit

fi

IPS=""
WRITEFILE=""
FLAG=""
CONTROLLER=""
ASREPROASTING=""
DOMAINNAME=""
HELP=""

while getopts ":hH:f:w:C:D:T:S:" arg; do

	case $arg in 

	f) IPS=$OPTARG
		;;

	h) helper
		;;

	w) WRITEFILE=$OPTARG
		;;

	C) CONTROLLER=$OPTARG
		;;
	T) ASREPROASTING=$OPTARG
		;;
	D) DOMAINNAME=$OPTARG
		;;
	H) HELP=$OPTARG
		;;
	S) FLAG=$OPTARG
		;; 
	
	*)
		echo -e "\n[!] Error: Unsupported Flag $OPTARG" >&2
		exit 1
		;;
	esac
done

shift $((OPTIND-1))

if [[ $FLAG == '-smb' ]]
	then
	if [[ -n $IPS ]] ; then
		if [[ -n $WRITEFILE ]]; then
			runSMB | tee -a $WRITEFILE
			echo -e "\n\n[+] Results saved to: $WRITEFILE\n"

		else
			runSMB


		fi
	fi
fi

if [[ $FLAG == '-http' ]]
	then
	if [[ -n $IPS ]] ; then
		if [[ -n $WRITEFILE ]]; then
			http | tee -a $WRITEFILE
			echo -e "\n\n[+] Results saved to: $WRITEFILE\n"
		else
			http	
		fi
	fi
fi

if [[ $FLAG == '-ffuf' ]]
	then
	if [[ -n $IPS ]] ; then
		if [[ -n $WRITEFILE ]]; then
			runFuff | tee -a $WRITEFILE
			echo -e "\n\n[+] Results saved to: $WRITEFILE\n"
		else
			runFuff	
		fi
	fi
fi

if [[ $FLAG == '-ldap' ]]
	then
	if [[ -n $IPS ]] ; then
		if [[ -n $WRITEFILE ]]; then
			ldap | tee -a $WRITEFILE
			echo -e "\n\n[+] Results saved to: $WRITEFILE\n"
		else
			ldap		
		fi
	fi
fi

if [[ $FLAG == '-smtp' ]]
	then
	if [[ -n $IPS ]] ; then
		if [[ -n $WRITEFILE ]]; then
			smtp | tee -a $WRITEFILE
			echo -e "\n\n[+] Results saved to: $WRITEFILE\n"
		else
			smtp
		fi
	fi
fi

if [[ $FLAG == '-ftp' ]]
	then
	if [[ -n $IPS ]] ; then
		if [[ -n $WRITEFILE ]]; then
			ftp_check | tee -a $WRITEFILE
			echo -e "\n\n[+] Results saved to: $WRITEFILE\n"
		else
			ftp_check
		fi
	fi
fi

if [[ $FLAG == '-rpc' ]]
	then
	if [[ -n $IPS ]] ; then
		if [[ -n $WRITEFILE ]]; then
			rpc_check | tee -a $WRITEFILE
			echo -e "\n\n[+] Results saved to: $WRITEFILE\n"
		else
			rpc_check
		fi
	fi
fi

if [[ $FLAG == '-nfs' ]]
	then
	if [[ -n $IPS ]] ; then
		if [[ -n $WRITEFILE ]]; then
			nfs_check | tee -a $WRITEFILE
			echo -e "\n\n[+] Results saved to: $WRITEFILE\n"
		else
			nfs_check
		fi
	fi
fi

if [[ $FLAG == '-snmp' ]]
	then
	if [[ -n $IPS ]] ; then
		if [[ -n $WRITEFILE ]]; then
			snmp_check | tee -a $WRITEFILE
			echo -e "\n\n[+] Results saved to: $WRITEFILE\n"
		else
			snmp_check
		fi
	fi
fi

if [[ $FLAG == '-vhosts' ]]
	then
	if [[ -n $DOMAINNAME ]] ; then
		if [[ -n $WRITEFILE ]]; then
			vhosts | tee -a $WRITEFILE
			echo -e "\n\n[+] Results saved to: $WRITEFILE\n"
		else
			vhosts
		fi
	fi
fi

if [[ $ASREPROASTING == '-asrep' ]]
	then
	if [[ -n $IPS ]]; then
		if [[ -n $WRITEFILE ]]; then
			asrep | tee -a $WRITEFILE
			echo -e "\n\n[+] Results saved to: $WRITEFILE\n"
		else
			asrep
		fi
	fi
fi


if [[ $HELP ]];
	then
	advHELP
fi		

# Add this to your .zshrc file
## Create completion Function
#function tab-completion-servicechecker() {
#    local -a options
#    local state
#
#    # Define serviceChecker options
#    options=(
#        '(-h)-h[display help information]'
#        '-H-[help with usage for all features]:feature:(http ffuf smb ldap smtp snmp ftp rpc nfs vhosts)'
#        '-H-ffuf[Use ffuf on the hosts that returned a status code of 200]'
#        '-H-smb[Scanning for smb anonymous access and listing shares]'
#        '-H-ldap[Scanning for anonyous bind]'
#        '-H-smtp[Connect to smtp server and send innocuous email]'
#        '-H-ftp[Connect to ftp server with anonymous access]'
#        '-H-rpc[Enumerate RPC services]'
#        '-H-nfs[Connect and enumerate NFS]'
#        '-H-vhosts[Search for virtual hosts (subdomains) on the provided domain]'
#        '-f[file containing IPs, domain names, service account names]:file:_files'
#        '-w[write results to file]:output file:_files'
#        '-D[specify domain name]:domain name:_domains'
#        '-C[specify domain controller IP]:domain controller IP:_hosts'
#        '-T-asrep[test for Kerberos pre-authentication (ASREPRoasting attack)]'
#        '-S-smb[scanning for SMB anonymous access and listing shares]'
#        '-S-http[curl the website and return those with a status code of 200]'
#        '-S-ffuf[use ffuf on the hosts that returned a status code of 200]'
#        '-S-ldap[scanning for anonymous bind]'
#        '-S-smtp[connect to SMTP server and send innocuous email]'
#        '-S-snmp[connect to SNMP device and dump information]'
#        '-S-ftp[connect to FTP server with anonymous access]'
#        '-S-rpc[enumerate RPC services]'
#        '-S-nfs[connect and enumerate NFS]'
#        '-S-vhosts[Search for virtual hosts (subdomains)]'
#    )
#
#    # Place options into array for parsing
#    _arguments -s $options[@]
#}
#
## Bundle everything together
#compdef tab-completion-servicechecker serviceChecker.sh

