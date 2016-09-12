#!/bin/bash

TODO=.todo
HELP=.help

. ldap-scripts

SED=$(which sed)
TEMPLATEDIR="./templates"	

function check_requirements {
	if [ ! -f /etc/debian_version ]; then
		quit 1 "This script is for debian"
	fi
	WHO=$(whoami)
	if [ ! $WHO == "root" ]; then
		quit 1 "This script must be run as root"
	fi

	#apt-get install -y ldapscripts 1>/dev/null 
}

function indic {
	if [ ! -z "$1" ]; then
		echo -e "\e[34m"$1"\e[0m"
	fi
}

function tell {
	if [ ! -z "$1" ]; then
		echo -e "\e[33m"$1"\e[0m"
	fi
}

function confirm {
	if [ -z $AUTOMODE ]; then
		read -r -e -p $'\e[1m\e[31mContinue?\e[0m '
		if [[ ! $REPLY =~ ^[Yy]$ ]] && [ ! -z $REPLY ]
		then
		    quit 1
		fi
	fi
}

function ask {
	if [ -z $AUTOMODE ]; then
		DONE=false
		if [ ! -z "$2" ]; then
			OPT=" -i $2"
		else
			OPT=""
		fi
		until $DONE; do

		read -r -e -p "$1 " REPLY < /dev/tty 
		if [ ! -z "$REPLY" ]; then
			DONE=true
		fi
		done
	else
		if [ -z "$2" ]; then
			tell "The question below cant be answered : "
			tell "$1"
			exit 1;
		fi

		if [ "$2" == "0" ]; then
			REPLY="no"
		else
			REPLY=$2
		fi 

	fi
}


function quit {
	tell "$2"
	exit "$1"
}

function not_working {

	echo "*** Sorry, this functionnality isn't working yet"
	echo "***"
	sleep 1
	main_menu

}

if [ ! -z $1 ] && [ $1 == '-h' ]; then
	echo ""
	cat $HELP
	echo ""
	exit 0;
fi

if [ ! -z $1 ] && [ $1 == '-t' ]; then
	echo ""
	cat $TODO
	echo ""
	exit 0;
fi

if [ ! -z $1 ] && [ $1 == '-a' ]; then
	AUTOMODE=true
fi

if [ ! -z $1 ] && [ ! $1 == '-a' ]; then
	tell "Re-run with -a"
	exit 1;
fi

check_requirements
indic "LDAP (People directory) -- Directory management"

dNOW=$(date)
NOW=$(date +%s)
mNOW="auto-modified-on-"$NOW

SED=`which sed`

SLAPD_PACKAGE="slapd"
REQUIRED_PACKAGE="ldap-utils"
OPTIONAL_PACKAGE="ldapvi"

function check_fqdn {
echo ""
   tell "By default, Debian use the domain name of the host, currently '$(hostname -d)', as a top-level domain name. This top-level domain name will be the first DN recorded by LDAP. During this process Debian will create an administrator account named 'admin' and will ask you for a password. On the future, all databases that will need to be added to this top-level domain name, i.e. 'dc=example,dc=$(hostname -d)', will thus need the proper admin login and password mentioned before to be properly registered. Otherwise, LDAP will always complain that you do NOT have the right to add anything on domain '$(hostname -d)'."
echo ""
   tell "Note 1 : the admin account will be transformed in a DN for LDAP under the form 'cn=admin,dc=$(hostname -d)'"
   tell "Note 2 : If there is no domain, Debian will use the word 'nodomain' as a DN"
echo ""
   tell "Yes this is a little complicated... BUT THIS IS LDAP, what did you expect?!"
   tell "In summary, do NOT forget the password entered during LDAP installation (it will be a blue screen, you can't miss it...). And associate it with the username 'admin'"
   tell "Good luck"
echo ""
sleep 1
   ask "This is the domain of this host : '$(hostname -d)'. Do you want to change it?"
   if [ "$REPLY" == 'yes' ]; then
    	ask "Enter the wished domain of the server (org, com, etc) :"
   	DOMAIN="$REPLY"
   	ask "Is this correct (yes|retry|abort) : $(hostname).$DOMAIN"
   	CORRECT=$REPLY
   	until [ $CORRECT == "yes" ] || [ $CORRECT == 'abort' ]; do
   		ask "Enter the wished domain of the server (org, com, etc) :"
   		DOMAIN="$REPLY"
   		ask "Is this correct (yes|retry|abort) : $(hostname).$DOMAIN"
   		CORRECT=$REPLY
   	done
   	if [ $CORRECT == "yes" ]; then
		tell "/etc/hosts is updated"
		TMP=$(echo create_ldap_script tmp file | base64)
   		echo "127.0.0.1		$(hostname).$DOMAIN $(hostname)" | cat - /etc/hosts > /etc/.hosts_$TMP && mv /etc/.hosts_$TMP /etc/hosts
		tell "New fqdn = $(hostname --fqdn)"
		tell "Done"
    	fi
   fi

}
 


function change_user_password {

	not_working

	#NEW_PASSWORD=$(slappasswd)
	#ldapmodify -Y EXTERNAL -H ldapi:///
	ask "Database name: "
   	until [ "$REPLY" ]; do
		ask "Database name: "
	done
	DBNAME="$REPLY"
	ask "Username: "
   	until [ "$REPLY" ]; do
		ask "User DN: "
	done
	USERDN="$REPLY"
	ldappasswd -H ldapi:/// -x -D "$USERDN" -W -A -S 
}

function check_package {
	
	INSTALLED=$(which "$1")	
	if [ "$INSTALLED" ]; then
		echo 1
	else
		echo 0
	fi
}

function install {

		SLAPD=$(check_package $SLAPD_PACKAGE)
		if [ "$SLAPD" == 0 ]; then
			indic "Beginning installation of $SLAPD_PACKAGE"
			check_fqdn
			apt-get -y install $SLAPD_PACKAGE 2>/tmp/apt-errors.openldapscript
			APTERRORS=$(cat /tmp/apt-errors.openldapscript | grep -P '^E:')
			rm -f /tmp/apt-errors.openldapscript
			echo "$APTERRORS"
			[ ! -z "$APTERRORS" ] && echo "Some errors have been detected" && exit 1
			apt-get -y install $REQUIRED_PACKAGE
			[ ! -f "/etc/ldap/schema/cosine.ldiff" ] && ldapadd -Y EXTERNAL -H ldapi:/// -f "/etc/ldap/schema/cosine.ldif"
			[ ! -f "/etc/ldap/schema/nis.ldiff" ] && ldapadd -Y EXTERNAL -H ldapi:/// -f "/etc/ldap/schema/nis.ldif"
			[ ! -f "/etc/ldap/schema/inetorgperson.ldiff" ] && ldapadd -Y EXTERNAL -H ldapi:/// -f "/etc/ldap/schema/inetorgperson.ldif"
			tell "LDAP is installed"
		else
			tell "LDAP is already installed on this host"
		fi
}

function reinstall {

		SLAPD=$(check_package $SLAPD_PACKAGE)
		if [ "$SLAPD" == 1 ]; then
			tell "$SLAPD_PACKAGE will be removed"
			ask "Do you want to purge the old configuration?" 
			until [ "$REPLY" == 'yes' ] || [ "$REPLY" == 'no' ]; do
				ask "Do you want to purge the old configuration?" 
			done
			if [ "$REPLY" == 'no' ]; then
				tell "Configuration preserved"
				apt-get -y remove $SLAPD_PACKAGE
			else
				tell "Configuration dropped"
				apt-get -y purge $SLAPD_PACKAGE
			fi
			install
		else
			tell "LDAP is not installed on this host. Please use 'install LDAP' instead"
		fi
}

function new_entity {

	if [ "$1" == "folder" ]; then
		if [ -d "$2" ]; then
			mv "$2" "$2"-"$mNOW"
		fi
		mkdir -p "$2"
	elif [ "$1" == "file" ]; then
		if [ -f "$2" ]; then
			mv "$2" "$2"-"$mNOW"
		fi
		touch "$2"
	else
		tell "Error : entity $1 is incorrect"
	fi

}

function query {
	echo ""
}

function backup {
	echo ""
}

function new_toplevel {

	TOPDOMAINTEMPLATE="$TEMPLATEDIR/top-domain.ldif"
	TOPDOMAINFILE="$TEMPLATEDIR/.top-domain.ldif"
	
  	$SED -i "s#__DOMAIN__#$DBDOMAIN#g" "$TOPDOMAINFILE"
	rm $TOPDOMAINFILE

}

function new_database {

	/etc/init.d/slapd start


	PATTERN="^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9]))*\.([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$";
	PATTERN2="^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9]))*$";

	ask "Database name: "
	until [[ "$REPLY" =~ $PATTERN ]] || [[ "$REPLY" =~ $PATTERN2 ]]; do
		ask "Database name: "
	done

	DBRAW=$REPLY
	if [[ "$DBRAW" =~ $PATTERN ]]; then
		DBNAME=$(echo "$DBRAW" | sed "s/\..*//g")
		DBDOMAIN=$(echo "$DBRAW" | sed "s/.*\.//g")
	elif [[ "$DBRAW" =~ $PATTERN2 ]]; then 
		DBNAME="$DBRAW"
		ask "Database domain: "
		until [[ "$REPLY" =~ $PATTERN2 ]]; do
			ask "Database domain: "
		done
		DBDOMAIN=$REPLY
	fi

	DBFULLNAME="$DBNAME.$DBDOMAIN"
	DBDN="dc=$DBNAME,dc=$DBDOMAIN"
	DBFOLDER="ldap-$DBFULLNAME"
	ask "Admin: "
	DBADMIN="$REPLY"
	ask "Password: "
	DBADMINPASSWORD="$REPLY"
	DBADMINPASSENC=$(slappasswd -s "$DBADMINPASSWORD")
	ask "Description: "
	DBDESC="$REPLY"
	ask "Specify a path where the folder "$DBFOLDER" will be created (if a folder with the same name exist, it will be safely renamed): "
	
	until [ -d $REPLY ]; do
		ask "Specify a path where the folder "$DBFOLDER" will be created (if a folder with the same name exist, it will be safely renamed): "
	done

	DBPATH=$(realpath "$REPLY/$DBFOLDER")

	tell "Checking if domain $DBDOMAIN is already served by this host"
	DBDOMAINEXIST=$(ldapsearch -Y EXTERNAL -H ldapi:/// -b "dc=$DBDOMAIN" | grep "Success")

	if [ -z "$DBDOMAINEXIST" ]; then
		tell "Domain $DBDOMAIN must be created"	
	else
		tell "Yes it is"

		tell "Since the domain $DBDOMAIN is already served we will attach the new database $DBNAME to this service"
		tell "To continue the process, you need authoritative access on the '$DBDOMAIN' domain"
		tell "In clear, it means you need admin name and admin password for '$DBDOMAIN' domain"

		if [ "$DBDOMAIN" == $(hostname -d) ]; then
			tell "TIPS : if you just installed LDAP using this script menu, credential are:"
			tell "	-login : admin"
			tell "	-password : the one you entered during setup"
		fi

		ask "Do you know the credential of administrative account for domain $DBDOMAIN?"
		until [ "$REPLY" == 'yes' ] || [ "$REPLY" == 'no' ]; do
			ask "Do you know the credential of administrative account for domain $DBDOMAIN?"
		done
		if [ "$REPLY" == 'no' ]; then
			tell "[#TODO : This message needs to be more clear] If everything is a mess, SNAFU! You can just 'reconfigure' LDAP on this system (in debian fucking language, it means : move old databases in /var/backup or erase everything, depends on configuration). Previous databases present on this host might be either mooved or deleted by Debian, depends what you'll choose during recofniguration process. It's up to you bro..."
			ask "Would you like to 'reconfigure' ldap on this host (it's like starting with a fresh install)?"
			if [ "$REPLY" == 'yes' ]; then
				tell "OK. Please keep in note the password you will provide"
				tell "IMPORTANT : choose MDB as the database system you use (otherwise it wont work since this script is not perfect)"
				tell "TIPS : On the first screen say NO. Otherwise it might be ok if you say OK everywhere (double check MDB is selected)"
				confirm
				new_entity file $DBPATH/.dpkg_error
				dpkg-reconfigure slapd 2>$DBPATH/.dpkg_error
				DPKGRECONFFAILED=$(cat $DBPATH/.dpkg_error | grep -i "giving up")
				rm -f $DBPATH/.dpkg_error
				if [ ! -z "$DPKGRECONFFAILED" ];then
					tell "Errors detection"
					tell "Sorry, the configuration has failed. Nothing has been changed. If you still doesnt remember the login/pass of slapd, closing this script is your best option."
					ask "Exiting this script?"
					until [ "$REPLY" == 'yes' ] || [ "$REPLY" == 'no' ]; do
							ask "Exiting this script?"
					done
					if [ "$REPLY" == 'yes' ]; then
						tell "What you could try is to reinstall LDAP using this script. If things are not better, experience shows that you could also rm -rf every entries that ends with '.ldapdb' in /var/backups/ (command : rm -rf /var/backups/*.ldapdb). WARNING : this will definitely erase any previous LDAP database that has been saved by Debian on each reinstallation of LDAP on this host. Please ASK YOU SYSADMIN."
						exit 1
					fi
				fi
				sleep 2
				tell "Here we go..."
			fi
		fi

		ask "Admin name for top-level domain name '$DBDOMAIN' (login):"
		MASTERADMIN=$REPLY
		ask "Admin password for top-level domain name '$DBDOMAIN' (password):"
		MASTERADMINPASSWORD=$REPLY
		tell "Testing access"
		TESTACCESS=$(ldapsearch -D "cn=$MASTERADMIN,dc=$DBDOMAIN" -w "$MASTERADMINPASSWORD" 2>&1)
		[ ! -z "$(echo $TESTACCESS | grep 49)" ] && tell "Nop... Exiting." && exit 1;
		tell "OK"

	fi

	new_entity folder "$DBPATH"

	if [ -z "$DBDOMAINEXIST" ]; then

		DBCONFIGTEMPLATE="$TEMPLATEDIR/db.ldif"
		DBCONFIGFILE="$DBPATH/db.ldif"
		new_entity file "$DBCONFIGFILE"
		head_file "$DBCONFIGFILE" "$DBNAME" "Database Creation"
		transfert "$DBCONFIGTEMPLATE" "$DBCONFIGFILE"
  		$SED -i "s#__DN__#dc=$DBDOMAIN#g" "$DBCONFIGFILE"
  		$SED -i "s#__ADMIN__#$DBADMIN#g" "$DBCONFIGFILE"
  		$SED -i "s#__ADMINPASSWORD__#$DBADMINPASSENC#g" "$DBCONFIGFILE"
  		$SED -i "s#__DIRECTORY__#/var/lib/ldap/#g" "$DBCONFIGFILE"
	
		tell "TopLevel Domain $DBDOMAIN is being created"
		ldapadd -Y EXTERNAL -H ldapi:/// -f "$DBCONFIGFILE"

		DBDOMAININITTEMPLATE="$TEMPLATEDIR/top-level.ldif"
		DBDOMAININITFILE="$DBPATH/top-level.ldif"
		new_entity file "$DBDOMAININITFILE"
		echo "#LDAP Init file for $DBNAME" >> "$DBDOMAININITFILE"
		echo "#Created $(date)" >> "$DBDOMAININITFILE"
		transfert "$DBDOMAININITTEMPLATE" "$DBDOMAININITFILE"
	  	$SED -i "s#__DOMAIN__#$DBDOMAIN#g" "$DBDOMAININITFILE"
		tell "Top-Level Domain $DBDOMAIN is being initialized"
		
		new_entity file "$DBPATH/.ldapadd_error"
		ldapadd -x -D "cn=$DBADMIN,dc=$DBDOMAIN" -w "$DBADMINPASSWORD" -f "$DBDOMAININITFILE" 2>$DBPATH/.ldapadd_error
		tell "Errors detection..."
		LDAPADDCONFFAILED=$(cat $DBPATH/.ldapadd_error)
		rm -f $DBPATH/.ldapadd_error
		if [ ! -z "$LDAPADDCONFFAILED" ];then
			tell "Error: something failed due to the data you provided."
			tell "Check for any special characters, they have to be removed"
			tell "Exiting"
			exit 1
		fi
		tell "No errors found... done"
	fi

	DBINITTEMPLATE="$TEMPLATEDIR/init.ldif"
	DBINITFILE="$DBPATH/init.ldif"
	new_entity file "$DBINITFILE"
	head_file "$DBNAME" "$DBINITFILE" "Initialization"
	transfert "$DBINITTEMPLATE" "$DBINITFILE"
  	$SED -i "s#__DN__#$DBDN#g" "$DBINITFILE"
  	$SED -i "s#__NAME__#$DBNAME#g" "$DBINITFILE"
  	$SED -i "s#__SHORTDESC__#$DBFULLNAME#g" "$DBINITFILE"
  	$SED -i "s#__LONGDESC__#$DBDESC#g" "$DBINITFILE"
  	$SED -i "s#__ADMIN__#$DBADMIN#g" "$DBINITFILE"
  	$SED -i "s#__ADMINPASSWORD__#$DBADMINPASSENC#g" "$DBINITFILE"

	tell "Database $DBNAME is being initialized"
	if [ -z "$DBDOMAINEXIST" ]; then
		new_entity file $DBPATH/.ldapadd_error
		ldapadd -x -D "cn=$DBADMIN,dc=$DBDOMAIN" -w "$DBADMINPASSWORD" -f "$DBINITFILE" 2>$DBPATH/.ldapadd_error
		tell "Errors detection..."
		LDAPADDCONFFAILED=$(cat $DBPATH/.ldapadd_error)
		rm -f $DBPATH/.ldapadd_error
		tell "Errors detection... done"
		if [ ! -z "$LDAPADDCONFFAILED" ];then
			tell "Error: something failed due to the data you provided."
			tell "Check for any special characters, they have to be removed"
			tell "Exiting"
			exit 1
		fi
	else
		new_entity file $DBPATH/.ldapadd_error
		ldapadd -x -D "cn=$MASTERADMIN,dc=$DBDOMAIN" -w "$MASTERADMINPASSWORD" -f "$DBINITFILE" 2>$DBPATH/.ldapadd_error
		tell "Errors detection..."
		LDAPADDCONFFAILED=$(cat $DBPATH/.ldapadd_error)
		rm -f $DBPATH/.ldapadd_error
		tell "Errors detection... done"
		if [ ! -z "$LDAPADDCONFFAILED" ];then
			tell "Error: something failed due to the data you provided."
			tell "Check for any special characters, they have to be removed"
			tell "Exiting"
			exit 1
		fi
	fi

	echo ""

	tell "Applying permissions"
	last_db
	TEMPLATE="$TEMPLATEDIR/perms.ldif"
	FILE="$DBPATH/perms.ldif"
	new_entity file "$FILE"
	head_file "$DBNAME" "$FILE" "Permissions"
	transfert "$TEMPLATE" "$FILE"
  	$SED -i "s#__DBNUM__#$LASTDB#g" "$FILE"
  	$SED -i "s#__TO__#dn.children=\"dc=$DBDOMAIN\"#g" "$FILE"
  	#$SED -i "s#__USERDN__#cn=$DBADMIN,$DBDN#g" "$FILE"
  	$SED -i "s#__BY__#*#g" "$FILE"
  	$SED -i "s#__PERM__#write#g" "$FILE"
	ldapmodify  -Y EXTERNAL -H ldapi:/// -f "$FILE"

	METADIR=$DBPATH/.meta
	new_entity folder $METADIR
	tell "Meta directory has been created (location: $METADIR)"
	new_entity file $METADIR/config
	echo "#Metadata Configuration file for $DBFULLNAME" > $METADIR/config
	echo "#Created on $(date)" >> $METADIR/config
	echo "DB:$DBFULLNAME" >> $METADIR/config
	echo "ADMIN:$DBADMIN" >> $METADIR/config
	echo "PASSWORD:$DBADMINPASSWORD" >> $METADIR/config
  	echo "ENCPASSWORD:$DBADMINPASSENC" >> $METADIR/config
	echo "DN:$DBDN" >> $METADIR/config
	echo "DBNUM:$LASTDB" >> $METADIR/config
	tell "Meta directory has been populated with $DBFULLNAME metadata"

	echo ""

	tell "Cleaning memory..."
	METADIR=""
	PATTERN=""
	PATTERN2=""
	DBRAW=""
	TESTACCESS=""
	DBDOMAININITTEMPLATE=""
	DBDOMAININITFILE=""
	DBCONFIGTEMPLATE=""
	DBCONFIGFILE=""
	DBDOMAIN=""
	DBFULLNAME=""
	DBDN=""
	DBFOLDER=""
	DBNAME=""
	DBADMIN=""
	DBADMINPASSWORD=""
	DBADMINPASSENC=""
	DBDESC=""
	DBPATH=""
	DBDOMAINEXIST=""
	DPKGRECONFFAILED=""
	MASTERADMIN=""
	MASTERADMINPASSWORD=""
	DBINITTEMPLATE=""
	DBINITFILE=""
	LDAPADDCONFFAILED=""
	REPLY=""

	tell "Done"
}


function list_dn {

	if [ -d "$1" ]; then
		DBFOLDER="$1"
	else
		DBFOLDER=""
	fi

	SCOPE="(objectclass=organization)(objectclass=organizationalUnit)(objectclass=groupOfNames)"
	for var in "$@"
	do
		if [ ! -z "$var" ] && [ ! -d "$var" ]; then
			SCOPE="(objectclass=$var)$SCOPE"
		fi
	done

	PATTERN="^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9]))*\.([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$";
	PATTERN2="^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9]))*$";

	if [ ! -d "$DBFOLDER" ]; then
		ask "Please, provide the path of a LDAP database folder:"
		until [ -d $REPLY ];do
			ask "Please, provide the path of a LDAP database folder:"
		done
		UNITDBPATH=$(echo "$REPLY" | sed "s/\/$//")
	else
		UNITDBPATH=$DBFOLDER
	fi

	UNITMETADIR="$UNITDBPATH/.meta"
	UNITMETACONFIG="$UNITMETADIR/config"

	if [ ! -d "$DBFOLDER" ]; then
		tell "Looking for metadata"
	fi

	if [ -d "$UNITMETADIR" ]; then
				
		if [ -f "$UNITMETACONFIG" ]; then
			if [ ! -d "$DBFOLDER" ]; then
				tell "Config file has been found"
			fi
			UNITDBCONFIGFILE=$(cat "$UNITMETACONFIG")
			UNITDBFULLNAME=$(echo "$UNITDBCONFIGFILE" | grep -P "^DB:" | awk 'BEGIN {FS=":"};{print $2}')
			UNITDBADMIN=$(echo "$UNITDBCONFIGFILE" | grep -P "^ADMIN:" | awk 'BEGIN {FS=":"};{print $2}')
			UNITDBADMINPASSWORD=$(echo "$UNITDBCONFIGFILE" | grep -P "^PASSWORD:" | awk 'BEGIN {FS=":"};{print $2}')
		else
			tell "Config file has NOT been found"
			quit 1 "Package is damaged [#TODO: regenerate the file from user memory?]. Abort"
		fi
	else
		tell "Meta directory has NOT been found"
		quit 1 "Package is damaged. Abort"
	fi

	DBNAME=$(echo "$UNITDBFULLNAME" | sed "s/\..*//g")
	DBDOMAIN=$(echo "$UNITDBFULLNAME" | sed "s/.*\.//g")

	UNITDBTREE=$(ldapsearch -D "cn=$UNITDBADMIN,dc=$DBNAME,dc=$DBDOMAIN" -w "$UNITDBADMINPASSWORD" -b "dc=$DBNAME,dc=$DBDOMAIN" "(|$SCOPE)" | grep -P "^dn:" | sed "s/dn: //g" )

	UNITDBTREETMPFILE="$UNITMETADIR/.tree.tmp"
	new_entity file "$UNITDBTREETMPFILE"
	echo "$UNITDBTREE" >> "$UNITDBTREETMPFILE"

	while read p; do
		echo $p | awk -F ',' '{ 
			for (i=NF; i>1; i--){ 
				printf("%s/",$i);
			}
				printf("%s\n",$1); 
		}' 
	done < "$UNITDBTREETMPFILE" 2>/dev/null | xargs -i mkdir -p "$UNITMETADIR/{}" 2>/dev/null #TODO: BUG XARGS (see 2)

	tell "Available roots (schematic):"
	tree -U "$UNITMETADIR/dc=$DBDOMAIN" 2>/dev/null | sed "/.*director.*/ d" | sed "s#^$UNITMETADIR/##"
	rm -f "$UNITDBTREETMPFILE"
	rm -rf "$UNITMETADIR/dc=$DBDOMAIN"
}

function head_file {

	[ -z "$3" ] && 3="Configuration"
	echo "#LDAP "$2": "$3" file" >> "$1"
	echo "#Created $(date)" >> "$1"

}


function transfert {

	cat "$1" >> "$2"

}

function last_db {
	LASTDB=$(ldapsearch  -Y EXTERNAL -H ldapi:/// -b cn=config 'olcDatabase={0}mdb' 2>&1 | grep -P "{\d*?}mdb, config" | awk '/./{line=$0} END{print line}' | grep -oP "\d\d?\d?")
}

function adder {

	TITLE=$1
	LDIF=$2
	OBJECT=$3

	if [ ! -z "$4" ]; then
		FIRSTMEMBER="$4"
	fi

	EMPTY="(empty)"

	indic "New $TITLE configurator"
	list_dn

	DN=$(grep -P "^DN:" $UNITMETACONFIG | sed s/DN://)
	ADMIN=$(grep -P "^ADMIN:" $UNITMETACONFIG | sed s/ADMIN://)
	PASS=$(grep -P "^PASSWORD:" $UNITMETACONFIG | sed s/PASSWORD://)

	TMPFILE="$UNITMETADIR/.tmp"
	new_entity file "$TMPFILE"

	UNITTEMPLATEFILE="$TEMPLATEDIR/$LDIF.ldif"
	echo -e "Add new $TITLE (example: "$DBDOMAIN.$DBNAME".foo.bar):"
	echo -e "Terminate with $DBDOMAIN.$DBNAME.. or $DBDOMAIN.$DBNAME.\\"
	while read -e -p "$DBDOMAIN.$DBNAME." -r line
	do
		[ "$line" == '.' ] || [ "$line" == '\' ] && break
		[ -z "$line" ] && continue
	
		truncate -s 0 $TMPFILE
		
		echo "$line" | awk 'BEGIN {FS="."}; {
			entry=""
			for (i=1; i<=NF; i++){ 
				if($i ~ /^.*=/){
					entry=$i","entry
				}else{
					entry="'$OBJECT'="$i","entry
				}
				print entry
			}
		}' | xargs -i echo {} >> "$TMPFILE"

		NUMLINES="$(wc -l $TMPFILE | awk '{print $1}')"
		COUNTER="0"

		while read newdn; do
	
			((COUNTER++))

			GROUP=$(echo $newdn | sed -e 's/,$//')
			NAME=$(echo $newdn | awk -F ',' '{
				
				print $1
				
			}' | sed -e "s/^$OBJECT=//" | sed -e 's/,$//')

			if [ -f "$UNITDBPATH/$GROUP.ldif" ]; then
				truncate -s 0 "$UNITDBPATH/$GROUP.ldif"
			else
				touch "$UNITDBPATH/$GROUP.ldif"
			fi

			tell "Creation of $TITLE: $GROUP,$DN"

			#if [ "$OBJECT" == "cn" ]; then
			#	if [ -z "$FIRSTMEMBER" ]; then
			#		ask "First member DN (required): "
			#		FIRSTMEMBER="member: $REPLY"
			#	fi
			#fi

			head_file "$UNITDBPATH/$GROUP.ldif" "$DBNAME" "OU $GROUP Creation"
			transfert "$UNITTEMPLATEFILE" "$UNITDBPATH/$GROUP.ldif"

			sed -i "s#__UNIT__#$GROUP#g" "$UNITDBPATH/$GROUP.ldif"
			sed -i "s#__NAME__#$NAME#g" "$UNITDBPATH/$GROUP.ldif"
			sed -i "s#__DN__#$DN#g" "$UNITDBPATH/$GROUP.ldif"

			if [ "$OBJECT" == "cn" ]; then
				if [ -z "$FIRSTMEMBER" ] || [ "$FIRSTMEMBER" == "0" ]; then
					ask "First member DN (required): "
					FIRSTMEMBER="member: $(echo $REPLY | sed "s/$DN$//" | sed 's/,$//' )"
				fi
	
				sed -i "s#__FIRSTMEMBER__#$FIRSTMEMBER,$DN#g" "$UNITDBPATH/$GROUP.ldif"
				FIRSTMEMBER=0
			fi

			#ldapadd -D "cn=$ADMIN,$DN" -w "$PASS" -f "$UNITDBPATH/$GROUP.ldif" 1>/dev/null 2>&1
			ldapadd -D "cn=$ADMIN,$DN" -w "$PASS" -f "$UNITDBPATH/$GROUP.ldif" 

		done < "$TMPFILE"

	done

	rm -f "$TMPFILE"
	list_dn "$UNITDBPATH"
	main_menu

}

function add_unit {
	
	adder "organizational unit" "ou" "ou"

}

function add_group {
	
	adder "group" "group" "cn"

}

function addmembertogroup {

	DATABASE=""
	GROUPNAME=""
}

function add_user2group {

	ask "User DN? "
	USERDN=$REPLY
	ask "Group DN? "
	GROUPDN=$REPLY

	

}

function add_member {

	TITLE="member"
	LDIF="member"
	OBJECT="uid"

	EMPTY="(empty)"

	indic "New $TITLE configurator"
	list_dn "person"

	DN=$(grep -P "^DN:" $UNITMETACONFIG | sed s/DN://)
	ADMIN=$(grep -P "^ADMIN:" $UNITMETACONFIG | sed s/ADMIN://)
	PASS=$(grep -P "^PASSWORD:" $UNITMETACONFIG | sed s/PASSWORD://)

	TMPFILE="$UNITMETADIR/.tmp"
	new_entity file "$TMPFILE"

	UNITTEMPLATEFILE="$TEMPLATEDIR/$LDIF.ldif"
	echo -e "Add new $TITLE (example: "$DBDOMAIN.$DBNAME".foo.bar):"
	echo -e "Terminate with $DBDOMAIN.$DBNAME.. or $DBDOMAIN.$DBNAME.\\"
	while read -e -p "$DBDOMAIN.$DBNAME." -r line
	do
		[ "$line" == '.' ] || [ "$line" == '\' ] && break
		[ -z "$line" ] && continue
	
		#read -e -p "Description (optional): " -i "$EMPTY" DESCRIPTION < /dev/tty
		truncate -s 0 $TMPFILE
		
		echo "$line" | awk 'BEGIN {FS="."}; {
			entry=""
			for (i=1; i<=NF; i++){ 
				if($i ~ /^.*=/){
					entry=$i","entry
				}else{
					entry="'$OBJECT'="$i","entry
				}
				print entry
			}
		}' | xargs -i echo {} >> "$TMPFILE"

		while read newdn; do
	
			#ldapsearch -h localhost -b "$newdn,$DN" -x -v -D'cn=admin,dc=myroot,dc=local' -wyour_ldap_password '(&(objectClass=organizationalUnit))'

			if [ -z "$(echo $newdn | grep "^$OBJECT=" )" ]; then
				continue	
			fi

			GROUP=$(echo $newdn | sed -e 's/,$//')
			NAME=$(echo $newdn | awk -F ',' '{
				
				print $1
				
			}' | sed -e "s/^$OBJECT=//" | sed -e 's/,$//')

			if [ -f "$UNITDBPATH/$GROUP.ldif" ]; then
				truncate -s 0 "$UNITDBPATH/$GROUP.ldif"
			else
				touch "$UNITDBPATH/$GROUP.ldif"
			fi

			head_file "$UNITDBPATH/$GROUP.ldif" "$DBNAME" "OU $GROUP Creation"
			transfert "$UNITTEMPLATEFILE" "$UNITDBPATH/$GROUP.ldif"

			sed -i "s#__UNIT__#$GROUP#g" "$UNITDBPATH/$GROUP.ldif"
			sed -i "s#__DN__#$DN#g" "$UNITDBPATH/$GROUP.ldif"
			sed -i "s#__UID__#$NAME#g" "$UNITDBPATH/$GROUP.ldif"

			tell "Adding: $GROUP,$DN"
			ask "Complete Name: "
			sed -i "s#__CN__#$REPLY#g" "$UNITDBPATH/$GROUP.ldif"
			ask "Given Name: "
			sed -i "s#__GIVENNAME__#$REPLY#g" "$UNITDBPATH/$GROUP.ldif"
			ask "Surname: "
			sed -i "s#__SN__#$REPLY#g" "$UNITDBPATH/$GROUP.ldif"
			ask "Unique number identifier (uid number): "
			sed -i "s#__UIDNUMBER__#$REPLY#g" "$UNITDBPATH/$GROUP.ldif"
			ask "Group number identifier (gid number): "
			sed -i "s#__GIDNUMBER__#$REPLY#g" "$UNITDBPATH/$GROUP.ldif"
			ask "Home directory: "
			sed -i "s#__HOMEDIR__#$REPLY#g" "$UNITDBPATH/$GROUP.ldif"
			ask "Mail: "
			sed -i "s#__MAIL__#$REPLY#g" "$UNITDBPATH/$GROUP.ldif"
			ask "Login Shell: "
			sed -i "s#__SHELL__#$REPLY#g" "$UNITDBPATH/$GROUP.ldif"
			ask "Password: "
			sed -i "s#__PASSWORD__#$REPLY#g" "$UNITDBPATH/$GROUP.ldif"

			#ldapadd -D "cn=$ADMIN,$DN" -w "$PASS" -f "$UNITDBPATH/$GROUP.ldif" 1>/dev/null 2>&1
			ldapadd -D "cn=$ADMIN,$DN" -w "$PASS" -f "$UNITDBPATH/$GROUP.ldif" 

		done < "$TMPFILE"

	done

	rm -f "$TMPFILE"
	list_dn "$UNITDBPATH" "person"
	main_menu

}

function add_manager {

	not_working

}


function scripts {
    PS3='Please enter your choice: '
    options=("check user login" "back")
    select opt in "${options[@]}"
    do
	case $opt in
	    "check user login")
		ask "User dn : "
		USERDN="$REPLY"
		ask "User password : "
		USERPASS="$REPLY"
		check_user_login "$USERDN" "$USERPASS"
		;;
	    "back")
		main_menu
		break
		;;
	    *) 
		;;
	esac
    done
}

function add_user {
    PS3='Please enter your choice: '
    options=("member" "manager" "back")
    select opt in "${options[@]}"
    do
	case $opt in
	    "member")
		add_member ;;
	    "manager")
		add_manager
		;;
	    "back")
		add_entry
		break
		;;
	    *) 
		;;
	esac
    done
}

function backup_db {
	not_working	
}

function add_entry {
    PS3='Please enter your choice: '
    options=("user" "group" "unit" "user2group" "back")
    select opt in "${options[@]}"
    do
	case $opt in
	    "user")
		add_user
		;;
	    "group")
		add_group
		;;
	    "unit")
		add_unit
		;;
	    "user2group")
		add_user2group
		;;
	    "back")
		main_menu
		break
		;;
	    *) 
		;;
	esac
    done
}

function main_menu {
    PS3='Please enter your choice (type ENTER if you can not see the menu): '
    options=("install LDAP" "reinstall LDAP" "new database" "add entry" "visualize" "scripts" "change user password" "backup database" "quit")
    select opt in "${options[@]}"
    do
	case $opt in
	    "install LDAP")
		install
		;;
	    "reinstall LDAP")
		reinstall
		;;
	    "new database")
		new_database
		;;
	    "add entry")
		add_entry
		;;
	    "visualize")
		list_dn
		;;
	    "scripts")
		scripts
		;;
	    "change user password")
		change_user_password
		;;
	    "backup database")
		backup_db
		;;
	    "quit")
		quit 0 "Good Bye!"
		break
		;;
	    *) 
		;;
	esac
    done
}

main_menu
exit 0;
