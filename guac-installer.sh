#!/bin/env bash
######  NOTES  #######################################################
# Project Page: https://github.com/Zer0CoolX/guacamole-install-rhel-7
# Licence (GPL-3.0): https://github.com/Zer0CoolX/guacamole-install-rhel-7/blob/master/LICENSE
# Report Issues: https://github.com/Zer0CoolX/guacamole-install-rhel-7/wiki/How-to-Report-Issues-(Bugs,-Feature-Request-and-Help)
# Wiki: https://github.com/Zer0CoolX/guacamole-install-rhel-7/wiki
#
# WARNING: For use on RHEL/CentOS 7.x and up only.
#	-Use at your own risk!
#	-Use only for new installations of Guacamole!
# 	-Read all documentation (wiki) prior to using this script!
#	-Test prior to deploying on a production system!
#
######  PRE-RUN CHECKS  ##############################################
if ! [ "$(id -u)" = 0 ]; then echo "This script must be run as sudo or root, try again..."; exit 1; fi
if ! [ "$(getenforce)" = "Enforcing" ]; then echo "This script requires SELinux to be active and in \"Enforcing mode\""; exit 1; fi
if ! [ "$(uname -m)" = "x86_64" ]; then echo "This script will only run on 64 bit versions of RHEL/CentOS"; exit 1; fi

## No need to check and quit if firewalld not installed, we just force install it
## when we first update packages.
## # Check that firewalld is installed
## if ! rpm -q --quiet "firewalld"; then echo "This script requires firewalld to be installed on the system"; exit 1; fi

# Allow trap to work in functions
set -E

######################################################################
######  VARIABLES  ###################################################
#####################################################################

######  UNIVERSAL VARIABLES  #########################################
# USER CONFIGURABLE #
# Generic
#SCRIPT_BUILD="2022_07_13" # Scripts Date for last modified as "yyyy_mm_dd"
ADM_POC="Local Admin, admin@admin.com"  # Point of contact for the Guac server admin

# Versions
GUAC_STBL_VER="1.4.0" # Latest stable version of Guac from https://guacamole.apache.org/releases/
MYSQL_CON_VER="8.0.28" # Working stable release of MySQL Connecter J
MAVEN_VER="3.8.6" # Latest stable version of Apache Maven
APEREO_CAS_VER="6.5" # Used to do a git checkout
TOMCAT_VER="9.0.65"

# URL
GUAC_CAS_EXT_URL="https://apache.org/dyn/closer.lua/guacamole/${GUAC_STBL_VER}/binary/guacamole-auth-sso-${GUAC_STBL_VER}.tar.gz?action=download"

# Ports
GUAC_PORT="4822"
MYSQL_PORT="3306"

# Key Sizes
JKSTORE_KEY_SIZE_DEF="4096" # Default Java Keystore key-size
LE_KEY_SIZE_DEF="4096" # Default Let's Encrypt key-size
SSL_KEY_SIZE_DEF="4096" # Default Self-signed SSL key-size

# Default Credentials
MYSQL_PASSWD_DEF="guac_adm" # Default MySQL/MariaDB root password
DB_NAME_DEF="guac_db" # Defualt database name
DB_USER_DEF="guac_adm" # Defualt database user name
DB_PASSWD_DEF="guac_adm" # Defualt database password
JKS_GUAC_PASSWD_DEF="guac_adm" # Default Java Keystore password
JKS_CACERT_PASSWD_DEF="guac_adm" # Default CACert Java Keystore password, used with LDAPS

# Misc
GUACD_USER="guacd" # The user name and group of the user running the guacd service
TOMCAT_USER="tomcat" # The user name and group of the user running the guacd service
APEREOCAS_USER="apereo" # The user name and group of the cas
SERVICE_GROUP="guacamole"
DOMAIN_NAME_DEF="guacamole.mycompany" # Default domain name of server
GUAC_URIPATH_DEF="/" # Default URI for Guacamole
H_ERR=false # Defualt value of if an error has been triggered, should be false
LIBJPEG_EXCLUDE="exclude=libjpeg-turbo-[0-9]*,libjpeg-turbo-*.*.9[0-9]-*"
DEL_TMP_VAR=true # Default behavior to delete the temp var file used by error handler on completion. Set to false to keep the file to review last values
NAME_SERVERS_DEF="1.1.1.1 1.0.0.1 2606:4700:4700::1111 2606:4700:4700::1001" # OCSP resolver DNS name servers defaults !!Only used if the host does not have name servers in resolv.conf!!
GUAC_JDBC_SQL="select gu.*, ge.name from guacamole_user gu inner join guacamole_entity ge on gu.entity_id = ge.entity_id where ge.type='USER' and gu.disabled=0 and ge.name=?"
GUAC_JDBC_HEALTH_QUERY="SELECT 1"
GUAC_JDBC_DIALECT="org.hibernate.dialect.MySQLDialect"
GUAC_JDBC_DRIVER_CLASS="com.mysql.jdbc.Driver"

# Apereo Defaults
CAS_HOME="/etc/cas/config"
CAS_DB_NAME_DEF="cas_db"
CAS_SERVER_NAME_DEF="https://${DOMAIN_NAME_DEF}"
CAS_SERVER_PREFIX_DEF="https://${DOMAIN_NAME_DEF}/cas"
CAS_AUTHN_PAC4J_GOOGLE_ID_DEF="111111111--sgmxxxxxxxxxxxxxxxxxxxxx.apps.googleusercontent.com"
CAS_AUTHN_PAC4J_GOOGLE_SECRET_DEF="secret"
CAS_AUTHN_PAC4J_GOOGLE_SCOPE_DEF="EMAIL_AND_PROFILE"
CAS_SERVICEREGISTRY_JSON_LOCATION_DEF="file:${CAS_HOME}/services/"
CAS_SERVICE_NAME_DEF="GuacamoleRAS"
CAS_SERVICE_ID_DEF="10000001"
CAS_AUTHORIZATION_ENDPOINT_DEF="https://${DOMAIN_NAME_DEF}/cas"
CAS_REDIRECT_URI_DEF="https://${DOMAIN_NAME_DEF}/guacamole"
CAS_PREFIX_KEY_DEF="https://localhost:8443"
CAS_PREFIX_DEF="127.0.0.1"
CAS_DB_USER_DEF="db_user_cas"
CAS_DB_PASSWORD_DEF="cas_password"
CAS_INSTALL_PATH_DEF="/opt/cas"
CAS_PROPERTIES_PATH_DEF="${CAS_HOME}/application.properties"
CAS_LOG4J2_PATH_DEF="${CAS_HOME}/log4j2.xml"

# ONLY CHANGE IF NOT WORKING #
# URLS
# https://cdn.mysql.com//Downloads/Connector-J/mysql-connector-java-8.0.29-1.el7.noarch.rpm	# 2022-07-12
MYSQL_CON_URL="https://dev.mysql.com/get/Downloads/Connector-J/" #Direct URL for download
LIBJPEG_REPO="https://libjpeg-turbo.org/pmwiki/uploads/Downloads/libjpeg-turbo.repo"
TOMCAT_URL="https://dlcdn.apache.org/tomcat/tomcat-9/v${TOMCAT_VER}/bin/apache-tomcat-${TOMCAT_VER}.tar.gz"
TOMCAT_INSTALL_DIR="/usr/share"

# Dirs and File Names
LIB_DIR="/var/lib/guacamole/"
GUAC_CONF="guacamole.properties" # Guacamole configuration/properties file
GUACD_CONF="guacd.conf"		 # guacd daemon config
MYSQL_CON="mysql-connector-java-${MYSQL_CON_VER}"
TMP_VAR_FILE="guac_tmp_vars" # Temp file name used to store varaibles for the error handler

# Formats
Black=$(tput setaf 0)	#${Black}
Red=$(tput setaf 1)	#${Red}
Green=$(tput setaf 2)	#${Green}
Yellow=$(tput setaf 3)	#${Yellow}
Blue=$(tput setaf 4)	#${Blue}
Magenta=$(tput setaf 5)	#${Magenta}
Cyan=$(tput setaf 6)	#${Cyan}
White=$(tput setaf 7)	#${White}
Bold=$(tput bold)	#${Bold}
UndrLn=$(tput sgr 0 1)	#${UndrLn}
Rev=$(tput smso)	#${Rev}
Reset=$(tput sgr0)	#${Reset}
######  END UNIVERSAL VARIABLES  #####################################

######  INITIALIZE COMMON VARIABLES  #################################
# ONLY CHANGE IF NOT WORKING #
init_vars () {
# Get the release version of Guacamole from/for Git
GUAC_GIT_VER=$(curl -s https://raw.githubusercontent.com/apache/guacamole-server/master/configure.ac | grep 'AC_INIT([guacamole-server]*' | awk -F'[][]' -v n=2 '{ print $(2*n) }')
PWD=$(pwd) # Current directory

APEREO_GIT_URL="https://github.com/apereo/cas-overlay-template.git"

# Set full path/file name of file used to stored temp variables used by the error handler
VAR_FILE="${PWD}/${TMP_VAR_FILE}"
echo "-1" > "${VAR_FILE}" # create file with -1 to set not as background process

# Determine if OS is RHEL, CentOS or something else
if grep -q "CentOS" /etc/redhat-release; then
	OS_NAME="CentOS"
elif grep -q "Red Hat Enterprise" /etc/redhat-release; then
	OS_NAME="RHEL"
else
	echo "Unable to verify OS from /etc/redhat-release as CentOS or RHEL, this script is intended only for those distro's, exiting."
	exit 1
fi
OS_NAME_L="$(echo $OS_NAME | tr '[:upper:]' '[:lower:]')" # Set lower case rhel or centos for use in some URLs

# Outputs the major.minor.release number of the OS, Ex: 7.6.1810 and splits the 3 parts.
MAJOR_VER=$(cat /etc/redhat-release | grep -oP "[0-9]+" | sed -n 1p) # Return the leftmost digit representing major version
MINOR_VER=$(cat /etc/redhat-release | grep -oP "[0-9]+" | sed -n 2p) # Returns the middle digit representing minor version
# Placeholder in case this info is ever needed. RHEL does not have release number, only major.minor
# RELEASE_VER=`cat /etc/redhat-release | grep -oP "[0-9]+" | sed -n 3p` # Returns the rightmost digits representing release number

#Set arch used in some paths
MACHINE_ARCH=$(uname -m)
ARCH="64"

# Set nginx url for RHEL or CentOS
NGINX_URL="https://nginx.org/packages/$OS_NAME_L/$MAJOR_VER/$MACHINE_ARCH/"
}

######  SOURCE VARIABLES  ############################################
src_vars () {
# Check if selected source is Git or stable release, set variables based on selection
if [ $GUAC_SOURCE == "Git" ]; then
	GUAC_VER=${GUAC_GIT_VER}
	GUAC_URL="https://github.com/apache/"
	GUAC_SERVER="guacamole-server.git"
	GUAC_CLIENT="guacamole-client.git"
	MAVEN_MAJOR_VER=${MAVEN_VER:0:1}
	MAVEN_URL="https://dlcdn.apache.org/maven/maven-${MAVEN_MAJOR_VER}/${MAVEN_VER}/binaries/"
	MAVEN_FN="apache-maven-${MAVEN_VER}"
	MAVEN_BIN="${MAVEN_FN}-bin.tar.gz"
else # Stable release
	GUAC_VER=${GUAC_STBL_VER}
	GUAC_URL="https://apache.org/dyn/closer.cgi?action=download&filename=guacamole/${GUAC_VER}/"
	GUAC_SERVER="guacamole-server-${GUAC_VER}"
	GUAC_CLIENT="guacamole-${GUAC_VER}"
fi

# JDBC Extension file name
GUAC_JDBC="guacamole-auth-jdbc-${GUAC_VER}"

# LDAP extension file name
GUAC_LDAP="guacamole-auth-ldap-${GUAC_VER}"

# TOTP extension file name
GUAC_TOTP="guacamole-auth-totp-${GUAC_VER}"

# SSO extension filename
GUAC_SSO="guacamole-auth-sso-${GUAC_VER}"

# CAS extension file name
GUAC_CAS="guacamole-auth-sso-cas-${GUAC_VER}"

# QUICKCONNECT extension filename
GUAC_QC="guacamole-auth-quickconnect-${GUAC_VER}"

# Dirs and file names
CAS_INSTALL_DIR="/usr/local/src/" # CAS source directory dir
INSTALL_DIR="/usr/local/src/guacamole/${GUAC_VER}/" # Guacamole installation dir
FILENAME="${PWD}/guacamole-${GUAC_VER}_"$(date +"%d-%y-%b")"" # Script generated log filename
logfile="${FILENAME}.log" # Script generated log file full name
fwbkpfile="${FILENAME}.firewall.bkp" # Firewall backup file name
}

######################################################################
######  MENUS  #######################################################
######################################################################

######  SOURCE MENU  #################################################
src_menu () {
clear

echo -e "   ${Reset}${Bold}----====Gucamole + CAS Installation Script====----\n       ${Reset}Guacamole Remote Desktop Gateway\n"
echo -e "   ${Bold}***        Source Menu     ***\n"
echo "   OS: ${Yellow}${OS_NAME} ${MAJOR_VER}.${MINOR_VER} ${MACHINE_ARCH}${Reset}"
echo -e "   ${Bold}Stable Version: ${Yellow}${GUAC_STBL_VER}${Reset} || ${Bold}Git Version: ${Yellow}${GUAC_GIT_VER}${Reset}\n"

while true; do
	echo -n "${Green} Pick the desired source to install from (enter 'stable' or 'git', default is 'stable'): ${Yellow}"
	read GUAC_SOURCE
	case $GUAC_SOURCE in
		[Ss]table|"" ) GUAC_SOURCE="Stable"; break;;
		[Gg][Ii][Tt] ) GUAC_SOURCE="Git"; break;;
		* ) echo "${Green} Please enter 'stable' or 'git' to select source/version (without quotes)";;
	esac
done

tput sgr0
}

######  START EXECUTION  #############################################
init_vars
src_menu
src_vars

######  MENU HEADERS  ################################################
# Called by each menu and summary menu to display the dynamic header
menu_header () {
tput sgr0
clear

echo -e "   ${Reset}${Bold}----====Gucamole Installation Script====----\n       ${Reset}Guacamole Remote Desktop Gateway\n"
echo -e "   ${Bold}***     ${SUB_MENU_TITLE}     ***\n"
echo "   OS: ${Yellow}${OS_NAME} ${MAJOR_VER}.${MINOR_VER} ${MACHINE_ARCH}${Reset}"
echo -e "   ${Bold}Source/Version: ${Yellow}${GUAC_SOURCE} ${GUAC_VER}${Reset}\n"
}

######  DATABASE AND JKS MENU  #######################################
db_menu () {
SUB_MENU_TITLE="Database and JKS Menu"

menu_header

echo -n "${Green} Enter the Guacamole DB name (default ${DB_NAME_DEF}): ${Yellow}"
	read DB_NAME
	DB_NAME=${DB_NAME:-${DB_NAME_DEF}}
echo -n "${Green} Enter the Guacamole DB username (default ${DB_USER_DEF}): ${Yellow}"
	read DB_USER
	DB_USER=${DB_USER:-${DB_USER_DEF}}
echo -n "${Green} Enter the Java KeyStore key-size to use (default ${JKSTORE_KEY_SIZE_DEF}): ${Yellow}"
	read JKSTORE_KEY_SIZE
	JKSTORE_KEY_SIZE=${JKSTORE_KEY_SIZE:-${JKSTORE_KEY_SIZE_DEF}}
}

######  PASSWORDS MENU  ##############################################
pw_menu () {
SUB_MENU_TITLE="Passwords Menu"

menu_header

echo -n "${Green} Enter the root password for MariaDB (default guac_adm): ${Yellow}"
	read MYSQL_PASSWD
	MYSQL_PASSWD=${MYSQL_PASSWD:-${MYSQL_PASSWD_DEF}}
echo -n "${Green} Enter the Guacamole DB password (default guac_adm): ${Yellow}"
	read DB_PASSWD
	DB_PASSWD=${DB_PASSWD:-${DB_PASSWD_DEF}}
echo -n "${Green} Enter the Guacamole Java KeyStore password, must be 6 or more characters: (default guac_adm) ${Yellow}"
	read JKS_GUAC_PASSWD
	JKS_GUAC_PASSWD=${JKS_GUAC_PASSWD:-${JKS_GUAC_PASSWD_DEF}}
echo -n "${Green} Enter the CAS DB Password (default cas_password) : ${Yellow}"
	read CAS_DB_PASSWORD
	CAS_DB_PASSWORD=${CAS_DB_PASSWORD:-${CAS_DB_PASSWORD_DEF}}
}

######  SSL CERTIFICATE TYPE MENU  ###################################
ssl_cert_type_menu () {
SUB_MENU_TITLE="SSL Certificate Type Menu"

menu_header

echo "${Green} What kind of SSL certificate should be used (default 2)?${Yellow}"
PS3="${Green} Enter the number of the desired SSL certificate type: ${Yellow}"
options=("LetsEncrypt" "Self-signed" "None")
select opt in "${options[@]}"
do
	case $opt in
		"LetsEncrypt") SSL_CERT_TYPE="LetsEncrypt"; le_menu; break;;
		"Self-signed"|"") SSL_CERT_TYPE="Self-signed"; ss_menu; break;;
		"None")
			SSL_CERT_TYPE="None"
			OCSP_USE=false
			echo -e "\n\n${Red} No SSL certificate selected. This can be configured manually at a later time."
			sleep 3
			break;;
		* ) echo "${Green} ${REPLY} is not a valid option, enter the number representing your desired cert type.";;
		esac
done
}

######  LETSENCRYPT MENU  ############################################
le_menu () {
SUB_MENU_TITLE="LetsEncrypt Menu"

menu_header

echo -n "${Green} Enter a valid e-mail for let's encrypt certificate: ${Yellow}"
	read EMAIL_NAME
echo -n "${Green} Enter the Let's Encrypt key-size to use (default ${LE_KEY_SIZE_DEF}): ${Yellow}"
	read LE_KEY_SIZE
	LE_KEY_SIZE=${LE_KEY_SIZE:-${LE_KEY_SIZE_DEF}}

while true; do
	echo -n "${Green} Use OCSP Stapling (default yes): ${Yellow}"
	read yn
	case $yn in
		[Yy]*|"" ) OCSP_USE=true; break;;
		[Nn]* ) OCSP_USE=false; break;;
		* ) echo "${Green} Please enter yes or no. ${Yellow}";;
		esac
done
}

######  SELF-SIGNED SSL CERTIFICATE MENU  ############################
ss_menu () {
OCSP_USE=false
SUB_MENU_TITLE="Self-signed SSL Certificate Menu"

menu_header

echo -n "${Green} Enter the Self-Signed SSL key-size to use (default ${SSL_KEY_SIZE_DEF}): ${Yellow}"
	read SSL_KEY_SIZE
	SSL_KEY_SIZE=${SSL_KEY_SIZE:-${SSL_KEY_SIZE_DEF}}
}

######  NGINX OPTIONS MENU  ##########################################
nginx_menu () {
SUB_MENU_TITLE="Nginx Menu"

menu_header

# Server LAN IP
GUAC_LAN_IP_DEF=$(hostname -I | sed 's/ .*//')

echo -n "${Green} Enter the LAN IP of this server (default ${GUAC_LAN_IP_DEF}): ${Yellow}"
	read GUAC_LAN_IP
	GUAC_LAN_IP=${GUAC_LAN_IP:-${GUAC_LAN_IP_DEF}}
echo -n "${Green} Enter a valid hostname or public domain such as mydomain.com (default ${DOMAIN_NAME_DEF}): ${Yellow}"
	read DOMAIN_NAME
	DOMAIN_NAME=${DOMAIN_NAME:-${DOMAIN_NAME_DEF}}
	CAS_SERVER_NAME_DEF="https://${DOMAIN_NAME}"
	CAS_SERVER_PREFIX_DEF="https://${DOMAIN_NAME}/cas"
	CAS_AUTHORIZATION_ENDPOINT_DEF="https://${DOMAIN_NAME}/cas"
echo -n "${Green} Enter the URI path, starting and ending with / for example /guacamole/ (default ${GUAC_URIPATH_DEF}): ${Yellow}"
	read GUAC_URIPATH
	GUAC_URIPATH=${GUAC_URIPATH:-${GUAC_URIPATH_DEF}}
	CAS_REDIRECT_URI_DEF="https://${DOMAIN_NAME}"

# Only prompt if SSL will be used
if [ $SSL_CERT_TYPE != "None" ]; then
	while true; do
		echo -n "${Green} Use only >= 256-bit SSL ciphers (More secure, less compatible. default: yes)?: ${Yellow}"
		read yn
		case $yn in
			[Yy]*|"" ) NGINX_SEC=true; break;;
			[Nn]* ) NGINX_SEC=false; break;;
			* ) echo "${Green} Please enter yes or no. ${Yellow}";;
		esac
	done

	while true; do
		echo -n "${Green} Use Content-Security-Policy [CSP] (More secure, less compatible. default: yes)?: ${Yellow}"
		read yn
		case $yn in
			[Yy]*|"" ) USE_CSP=true; break;;
			[Nn]* ) USE_CSP=false; break;;
			* ) echo "${Green} Please enter yes or no. ${Yellow}";;
		esac
	done
else
	NGINX_SEC=false
	USE_CSP=false
fi
}

######  PRIMARY AUTHORIZATION EXTENSIONS MENU  #######################
prime_auth_ext_menu () {
SUB_MENU_TITLE="Primary Authentication Extensions Menu"

menu_header

INSTALL_LDAP=false
# Install QuickConnect by default
INSTALL_QC=true
INSTALL_APEREOCAS=true
SECURE_LDAP=false
INSTALL_RADIUS=false
INSTALL_CAS=false
INSTALL_OPENID=false

# Allows selection of an authentication method in addition to MariaDB/Database or just MariaDB
# which is used to store connection and user meta data for all other methods
echo "${Green} What Guacamole extension should be used as the primary user authentication method (default 1)?${Yellow}"
PS3="${Green} Enter the number of the desired authentication method: ${Yellow}"
# Removing non-working options from the menu until they are ready
# "RADIUS" "OpenID" "CAS"
options=("MariaDB Database" "LDAP(S)" "CAS")
COLUMNS=1
select opt in "${options[@]}"
do
	case $opt in
		"MariaDB Database"|"") PRIME_AUTH_TYPE="MariaDB"; break;;
		"LDAP(S)") PRIME_AUTH_TYPE="LDAP"; LDAP_ext_menu; break;;
		# "RADIUS") PRIME_AUTH_TYPE="RADIUS"; Radius_ext_menu; break;;
		# "OpenID") PRIME_AUTH_TYPE="OpenID"; OpenID_ext_menu; break;;
		"CAS") PRIME_AUTH_TYPE="CAS"; CAS_ext_menu; break;;
		* ) echo "${Green} ${REPLY} is not a valid option, enter the number representing the desired primary authentication method.";;
		esac
done

unset COLUMNS
}

######  2FA EXTENSIONS MENU  #########################################
secondary_auth_ext_menu () {
SUB_MENU_TITLE="2FA Extensions Menu"

menu_header

INSTALL_TOTP=false
INSTALL_DUO=false

# Allows optional selection of a Two Factor Authentication (2FA) method
echo "${Green} What Guacamole extension should be used as the 2FA authentication method (default 1)?${Yellow}"
PS3="${Green} Enter the number of the desired authentication method: ${Yellow}"
# Removing non-working options from the menu until they are ready
# "DUO"
options=("None" "TOTP")
COLUMNS=1
select opt in "${options[@]}"
do
	case $opt in
		"None"|"") TFA_TYPE="None"; break;;
		"TOTP") TFA_TYPE="TOTP"; TOTP_ext_menu; break;;
		# "DUO") TFA_TYPE="DUO"; Duo_ext_menu; break;;
		* ) echo "${Green} ${REPLY} is not a valid option, enter the number representing the desired 2FA method.";;
		esac
done

unset COLUMNS
}

######  LDAP MENU  ###################################################
LDAP_ext_menu () {
INSTALL_LDAP=true
SUB_MENU_TITLE="LDAP Extension Menu"

menu_header

# Allow selection of LDAPS
while true; do
	echo -n "${Green} Use LDAPS instead of LDAP (Requires having the cert from the server copied locally, default: no): ${Yellow}"
	read SECURE_LDAP
	case $SECURE_LDAP in
		[Yy]* ) SECURE_LDAP=true; break;;
		[Nn]*|"" ) SECURE_LDAP=false; break;;
		* ) echo "${Green} Please enter yes or no. ${Yellow}";;
	esac
done

# Check if LDAPS was selected
if [ $SECURE_LDAP = true ]; then
	echo -ne "\n${Green} Enter the LDAP Port (default 636): ${Yellow}"
		read LDAP_PORT
		LDAP_PORT=${LDAP_PORT:-636}

	# LDAPS Certificate placeholder values
	LDAPS_CERT_FN="mycert.cer"
	LDAPS_CERT_FULL="xNULLx"

	while [ ! -f ${LDAPS_CERT_FULL} ]; do
		echo -ne "\n${Green} Enter a valid filename of the .cer certificate file (Ex: mycert.cer): ${Yellow}"
			read LDAPS_CERT_FN
			LDAPS_CERT_FN=${LDAPS_CERT_FN:-${LDAPS_CERT_FN}}
		echo -n "${Green} Enter the full path of the dir containing the .cer certificate file (must end with / Ex: /home/me/): ${Yellow}"
			read LDAPS_CERT_DIR
			LDAPS_CERT_DIR=${LDAPS_CERT_DIR:-/home/}
			LDAPS_CERT_FULL=${LDAPS_CERT_DIR}${LDAPS_CERT_FN}
		if [ ! -f ${LDAPS_CERT_FULL} ]; then
			echo "${Red} The file/path: ${LDAPS_CERT_FULL} does not exist! Ensure the file is in the directory and try again..."
		fi
	done

	echo -ne "\n${Green} Set the password for the CACert Java Keystore, must be 6 or more characters (default ${JKS_CACERT_PASSWD_DEF}): ${Yellow}"
		read JKS_CACERT_PASSWD
		JKS_CACERT_PASSWD=${JKS_CACERT_PASSWD:-${JKS_CACERT_PASSWD_DEF}}
else # Use LDAP not LDAPS
	echo -ne "\n${Green} Enter the LDAP Port (default 389): ${Yellow}"
		read LDAP_PORT
		LDAP_PORT=${LDAP_PORT:-389}
fi

echo -ne "\n${Green} Enter the LDAP Server Hostname (use the FQDN, Ex: ldaphost.domain.com): ${Yellow}"
	read LDAP_HOSTNAME
	LDAP_HOSTNAME=${LDAP_HOSTNAME:-ldaphost.domain.com}
echo -n "${Green} Enter the LDAP User-Base-DN (Ex: dc=domain,dc=com): ${Yellow}"
	read LDAP_BASE_DN
	LDAP_BASE_DN=${LDAP_BASE_DN:-dc=domain,dc=com}
echo -n "${Green} Enter the LDAP Search-Bind-DN (Ex: cn=user,ou=Admins,dc=domain,dc=com): ${Yellow}"
	read LDAP_BIND_DN
	LDAP_BIND_DN=${LDAP_BIND_DN:-cn=user,ou=Admins,dc=domain,dc=com}
echo -n "${Green} Enter the LDAP Search-Bind-Password: ${Yellow}"
	read LDAP_BIND_PW
	LDAP_BIND_PW=${LDAP_BIND_PW:-password}
echo -n "${Green} Enter the LDAP Username-Attribute (default sAMAccountName): ${Yellow}"
	read LDAP_UNAME_ATTR
	LDAP_UNAME_ATTR=${LDAP_UNAME_ATTR:-sAMAccountName}

LDAP_SEARCH_FILTER_DEF="(objectClass=*)"
echo -n "${Green} Enter a custom LDAP user search filter (default \"${LDAP_SEARCH_FILTER_DEF}\"): ${Yellow}"
	read LDAP_SEARCH_FILTER
	LDAP_SEARCH_FILTER=${LDAP_SEARCH_FILTER:-${LDAP_SEARCH_FILTER_DEF}}
}

######  TOTP MENU  ###################################################
TOTP_ext_menu () {
INSTALL_TOTP=true
SUB_MENU_TITLE="TOTP Extension Menu"

menu_header

echo -n "${Green} Enter the TOTP issuer (default Apache Guacamole): ${Yellow}"
	read TOTP_ISSUER
	TOTP_ISSUER=${TOTP_ISSUER:-Apache Guacamole}
echo -n "${Green} Enter the number of digits to use for TOTP (default 6): ${Yellow}"
	read TOTP_DIGITS
	TOTP_DIGITS=${TOTP_DIGITS:-6}
echo -n "${Green} Enter the TOTP period in seconds (default 30): ${Yellow}"
	read TOTP_PER
	TOTP_PER=${TOTP_PER:-30}
echo -n "${Green} Enter the TOTP mode (default sha1): ${Yellow}"
	read TOTP_MODE
	TOTP_MODE=${TOTP_MODE:-sha1}
}

######  DUO MENU  ####################################################
Duo_ext_menu () {
INSTALL_DUO=false
SUB_MENU_TITLE="DUO Extension Menu"

menu_header

echo "${Red} Duo extension not currently available via this script."
sleep 3
}

######  RADIUS MENU  #################################################
Radius_ext_menu () {
INSTALL_RADIUS=false
SUB_MENU_TITLE="RADIUS Extension Menu"

menu_header

echo "${Red} RADIUS extension not currently available via this script."
sleep 3
}

######  CAS MENU  ####################################################
CAS_ext_menu () {
INSTALL_CAS=true
SUB_MENU_TITLE="CAS Extension Menu"

menu_header
        echo -n "${Green} Enter the CAS Authorization Endpoint (default ${CAS_AUTHORIZATION_ENDPOINT_DEF}): ${Yellow}"
        read CAS_AUTHORIZATION_ENDPOINT
        CAS_AUTHORIZATION_ENDPOINT=${CAS_AUTHORIZATION_ENDPOINT:-${CAS_AUTHORIZATION_ENDPOINT_DEF}}
        echo -n "${Green} Enter the redirect URI for CAS (default ${CAS_REDIRECT_URI_DEF}): ${Yellow}"
        read CAS_REDIRECT_URI
        CAS_REDIRECT_URI=${CAS_REDIRECT_URI:-${CAS_REDIRECT_URI_DEF}}
        echo -n "${Green} Enter the Apereo CAS DB Name (default ${CAS_DB_NAME_DEF}) : ${Yellow}"
        read CAS_DB_NAME
        CAS_DB_NAME=${CAS_DB_NAME:-${CAS_DB_NAME_DEF}}
        echo -n "${Green} Enter the Apereo CAS DB UserName (default ${CAS_DB_USER_DEF}) : ${Yellow}"
        read CAS_DB_USER
        CAS_DB_USER=${CAS_DB_USER:-${CAS_DB_USER_DEF}}
        echo -n "${Green} Enter the Apereo CAS Prefix Key (default ${CAS_PREFIX_KEY_DEF}) : ${Yellow}"
        read CAS_PREFIX_KEY
        CAS_PREFIX_KEY=${CAS_PREFIX_KEY:-${CAS_PREFIX_KEY_DEF}}
        echo -n "${Green} Enter the Apereo CAS Prefix (default ${CAS_PREFIX_DEF}) : ${Yellow}"
        read CAS_PREFIX
        CAS_PREFIX=${CAS_PREFIX:-${CAS_PREFIX_DEF}}
        echo -n "${Green} Enter the Apereo CAS Install PATH (default ${CAS_INSTALL_PATH_DEF}) : ${Yellow}"
        read CAS_INSTALL_PATH
        CAS_INSTALL_PATH=${CAS_INSTALL_PATH:-${CAS_INSTALL_PATH_DEF}}
        echo -n "${Green} Enter the Apereo CAS Properties path (default ${CAS_PROPERTIES_PATH_DEF}) : ${Yellow}"
        read CAS_PROPERTIES_PATH
        CAS_PROPERTIES_PATH=${CAS_PROPERTIES_PATH:-${CAS_PROPERTIES_PATH_DEF}}
        echo -n "${Green} Enter the Apereo CAS log4j2 properties path (default ${CAS_LOG4J2_PATH_DEF}) : ${Yellow}"
        read CAS_LOG4J2_PATH
        CAS_LOG4J2_PATH=${CAS_LOG4J2_PATH:-${CAS_LOG4J2_PATH_DEF}}
        echo -n "${Green} Enter the Apereo CAS server name (default ${CAS_SERVER_NAME_DEF}) : ${Yellow}"
	read CAS_SERVER_NAME
	CAS_SERVER_NAME=${CAS_SERVER_NAME:-${CAS_SERVER_NAME_DEF}}
        echo -n "${Green} Enter the Apereo CAS server prefix (default ${CAS_SERVER_PREFIX_DEF}) : ${Yellow}"
	read CAS_SERVER_PREFIX
	CAS_SERVER_PREFIX=${CAS_SERVER_PREFIX:-${CAS_SERVER_PREFIX_DEF}}
        echo -n "${Green} Enter the Apereo CAS Service registry location (default ${CAS_SERVICEREGISTRY_JSON_LOCATION_DEF}) : ${Yellow}"
	read CAS_SERVICEREGISTRY_JSON_LOCATION
	CAS_SERVICEREGISTRY_JSON_LOCATION=${CAS_SERVICEREGISTRY_JSON_LOCATION:-${CAS_SERVICEREGISTRY_JSON_LOCATION_DEF}}
        echo -n "${Green} Enter the Apereo CAS service name (default ${CAS_SERVICE_NAME_DEF}) : ${Yellow}"
	read CAS_SERVICE_NAME
	CAS_SERVICE_NAME=${CAS_SERVICE_NAME:-${CAS_SERVICE_NAME_DEF}}
        echo -n "${Green} Enter the Apereo CAS service ID (default ${CAS_SERVICE_ID_DEF}) : ${Yellow}"
	read CAS_SERVICE_ID
        CAS_SERVICE_ID=${CAS_SERVICE_ID:-${CAS_SERVICE_ID_DEF}}
        while true; do
		echo -n "${Green} Do you want to configure CAS with GOOGLE Credentials (yes/no): ${Yellow}"
		read CONFIGURE_GOOGLE
		case ${CONFIGURE_GOOGLE} in
			[Yy]* ) CONFIGURE_GOOGLE=true; GooglePAC4J_menu; break;; 
			[Nn]* ) CONFIGURE_GOOGLE=false break;;
			*|"" ) echo "${Green} Please enter yes or no. ${Yellow}";;
		esac
	done
}

######  GOOGLE PAC4J  MENU  #################################################
GooglePAC4J_menu () {
SUB_MENU_TITLE="Google PAC4J Configuration Menu"

menu_header
echo -n "${Green} Enter the PAC4J Google ID (default ${CAS_AUTHN_PAC4J_GOOGLE_ID_DEF}) : ${Yellow}"
read CAS_AUTHN_PAC4J_GOOGLE_ID
CAS_AUTHN_PAC4J_GOOGLE_ID=${CAS_AUTHN_PAC4J_GOOGLE_ID:-${CAS_AUTHN_PAC4J_GOOGLE_ID_DEF}}
echo -n "${Green} Enter the PAC4J Google Secret (default ${CAS_AUTHN_PAC4J_GOOGLE_SECRET_DEF}) : ${Yellow}"
read CAS_AUTHN_PAC4J_GOOGLE_SECRET
CAS_AUTHN_PAC4J_GOOGLE_SECRET=${CAS_AUTHN_PAC4J_GOOGLE_SECRET:-${CAS_AUTHN_PAC4J_GOOGLE_SECRET_DEF}}
echo -n "${Green} Enter the PAC4J Google Scope (default ${CAS_AUTHN_PAC4J_GOOGLE_SCOPE_DEF}) : ${Yellow}"
read CAS_AUTHN_PAC4J_GOOGLE_SCOPE
CAS_AUTHN_PAC4J_GOOGLE_SCOPE=${CAS_AUTHN_PAC4J_GOOGLE_SCOPE:-${CAS_AUTHN_PAC4J_GOOGLE_SCOPE_DEF}}

}

######  OPENID MENU  #################################################
OpenID_ext_menu () {
INSTALL_OPENID=true
SUB_MENU_TITLE="OpenID Extension Menu"

menu_header

}

######  QUICKCONNECT EXTENSION MENU  #######################################
quickconnect_menu () {
SUB_MENU_TITLE="QuickConnect Extension Menu"

menu_header

while true; do
	echo -n "${Green} Would you like to install Guacamole QuickConnect extensions (default yes)? ${Yellow}"
	read yn
	case $yn in
		[Yy]* )
			INSTALL_QC=true

			break;;
		[Nn]*|"" ) INSTALL_QC=false; break;;
		* ) echo "${Green} Please enter yes or no. ${Yellow}";;
	esac
done
}


######  SUMMARY MENUS  ###############################################
######################################################################

######  MAIN SUMMARY MENU  ###########################################
sum_menu () {
SUB_MENU_TITLE="Summary Menu"

menu_header

RUN_INSTALL=false
RET_SUM=false

# List categories/menus to review or change
echo "${Green} Select a category to review selections: ${Yellow}"
PS3="${Green} Enter the number of the category to review: ${Yellow}"
options=("Database" "Passwords" "SSL Cert Type" "Nginx" "Primary Authentication Extension" "2FA Extension" "QuickConnect Extension" "Accept and Run Installation" "Cancel and Start Over" "Cancel and Exit Script")
select opt in "${options[@]}"
do
	case $opt in
		"Database") sum_db; break;;
		"Passwords") sum_pw; break;;
		"SSL Cert Type") sum_ssl; break;;
		"Nginx") sum_nginx; break;;
		"Primary Authentication Extension") sum_prime_auth_ext; break;;
		"2FA Extension") sum_secondary_auth_ext; break;;
		"QuickConnect Extension") sum_quickconnect; break;;
		"Accept and Run Installation") RUN_INSTALL=true; break;;
		"Cancel and Start Over") ScriptLoc=$(readlink -f "$0"); exec "$ScriptLoc"; break;;
		"Cancel and Exit Script") tput sgr0; exit 1; break;;
		* ) echo "${Green} ${REPLY} is not a valid option, enter the number representing the category to review.";;
		esac
done
}

######  DATABASE SUMMARY  ############################################
sum_db () {
SUB_MENU_TITLE="Database Summary"

menu_header

echo "${Green} Guacamole DB name: ${Yellow}${DB_NAME}"
echo "${Green} Guacamole DB username: ${Yellow}${DB_USER}"
echo -e "${Green} Java KeyStore key-size: ${Yellow}${JKSTORE_KEY_SIZE}\n"

while true; do
	echo -n "${Green} Would you like to change these selections (default no)? ${Yellow}"
	read yn
	case $yn in
		[Yy]* ) db_menu; break;;
		[Nn]*|"" ) break;;
		* ) echo "${Green} Please enter yes or no. ${Yellow}";;
	esac
done

sum_menu
}

######  PASSWORD SUMMARY  ############################################
sum_pw () {
SUB_MENU_TITLE="Passwords Summary"

menu_header

echo "${Green} MariaDB root password: ${Yellow}${MYSQL_PASSWD}"
echo "${Green} Guacamole DB password: ${Yellow}${DB_PASSWD}"
echo -e "${Green} Guacamole Java KeyStore password: ${Yellow}${JKS_GUAC_PASSWD}\n"

while true; do
	echo -n "${Green} Would you like to change these selections (default no)? ${Yellow}"
	read yn
	case $yn in
		[Yy]* ) pw_menu; break;;
		[Nn]*|"" ) break;;
		* ) echo "${Green} Please enter yes or no. ${Yellow}";;
	esac
done

sum_menu
}

######  SSL CERTIFICATE SUMMARY  #####################################
sum_ssl () {
SUB_MENU_TITLE="SSL Certificate Summary"

menu_header

echo -e "${Green} Certficate Type: ${Yellow}${SSL_CERT_TYPE}\n"

# Check the certificate selection to display proper information for selection
case $SSL_CERT_TYPE in
	"LetsEncrypt")
		echo "${Green} e-mail for LetsEncrypt certificate: ${Yellow}${EMAIL_NAME}"
		echo "${Green} LetEncrypt key-size: ${Yellow}${LE_KEY_SIZE}"
		echo -e "${Green} Use OCSP Stapling?: ${Yellow}${OCSP_USE}\n"
		;;
	"Self-signed")
		echo -e "${Green} Self-Signed SSL key-size: ${Yellow}${SSL_KEY_SIZE}\n"
		;;
	"None")
		echo -e "${Yellow} As no certificate type was selected, an SSL certificate can be configured manually at a later time.\n"
		;;
esac

while true; do
	echo -n "${Green} Would you like to change these selections (default no)? ${Yellow}"
	read yn
	case $yn in
		[Yy]* ) ssl_cert_type_menu; break;;
		[Nn]*|"" ) break;;
		* ) echo "${Green} Please enter yes or no. ${Yellow}";;
	esac
done

sum_menu
}

######  NGINX SUMMARY  ###############################################
sum_nginx () {
SUB_MENU_TITLE="Nginx Summary"

menu_header

echo "${Green} Guacamole Server LAN IP address: ${Yellow}${GUAC_LAN_IP}"
echo "${Green} Guacamole Server hostname or public domain: ${Yellow}${DOMAIN_NAME}"
echo "${Green} URI path: ${Yellow}${GUAC_URIPATH}"
echo "${Green} Using only 256-bit >= ciphers?: ${Yellow}${NGINX_SEC}"
echo -e "${Green} Content-Security-Policy [CSP] enabled?: ${Yellow}${USE_CSP}\n"

while true; do
	echo -n "${Green} Would you like to change these selections (default no)? ${Yellow}"
	read yn
	case $yn in
		[Yy]* ) nginx_menu; break;;
		[Nn]*|"" ) break;;
		* ) echo "${Green} Please enter yes or no. ${Yellow}";;
	esac
done

sum_menu
}

######  STANDARD EXTENSIONS SUMMARY  #################################
sum_prime_auth_ext () {
SUB_MENU_TITLE="Primary Authentication Extension Summary"

menu_header

echo -e "${Green} Primary Authentication type: ${Yellow}${PRIME_AUTH_TYPE}\n"

echo "${Yellow}${Bold} -- MariaDB is used with all authentication implementations --${Reset}"
echo "${Green} Default Guacamole username: ${Yellow}guacadmin"
echo -e "${Green} Default Guacamole password: ${Yellow}guacadmin\n"

# Check the authentication selection to display proper information for the selection
case $PRIME_AUTH_TYPE in
	"LDAP")
		echo -e "${Reset}${Bold} -- LDAP Specific Parameters --${Reset}\n"
		echo "${Green} Use LDAPS instead of LDAP: ${Yellow}${SECURE_LDAP}"
		echo -e "${Green} LDAP(S) port: ${Yellow}${LDAP_PORT}\n"

		if [ $SECURE_LDAP = true ]; then
			echo "${Green} LDAPS full filename and path: ${Yellow}${LDAPS_CERT_FULL}"
			echo -e "${Green} CACert Java Keystroe password: ${Yellow}${JKS_CACERT_PASSWD}\n"
		fi

		echo "${Green} LDAP Server Hostname (should be FQDN, Ex: ldaphost.domain.com): ${Yellow}${LDAP_HOSTNAME}"
		echo "${Green} LDAP User-Base-DN (Ex: dc=domain,dc=com): ${Yellow}${LDAP_BASE_DN}"
		echo "${Green} LDAP Search-Bind-DN (Ex: cn=user,ou=Admins,dc=domain,dc=com): ${Yellow}${LDAP_BIND_DN}"
		echo "${Green} LDAP Search-Bind-Password: ${Yellow}${LDAP_BIND_PW}"
		echo "${Green} LDAP Username-Attribute: ${Yellow}${LDAP_UNAME_ATTR}"
		echo -e "${Green} LDAP user search filter: ${Yellow}${LDAP_SEARCH_FILTER}\n"
		;;
	"RADIUS")
		echo -e "${Red} RADIUS cannot currently be installed by this script.\n"
		;;
	"OpenID")
		echo -e "${Red} OpenID cannot currently be installed by this script.\n"
		;;
	"CAS")
		echo -e "${Reset}${Bold} -- CAS Specific Parameters --${Reset}\n"
		echo "${Green} CAS Authorization Endpoint : ${Yellow}${CAS_AUTHORIZATION_ENDPOINT}"
		echo "${Green} CAS Redirect URI : ${Yellow}${CAS_REDIRECT_URI}"
        	echo "${Green} Apereo CAS DB Name : ${Yellow}${CAS_DB_NAME}"
        	echo "${Green} Apereo CAS DB UserName : ${Yellow}${CAS_DB_USERNAME}"
        	echo "${Green} Apereo CAS Prefix Key : ${Yellow}${CAS_PREFIX_KEY}"
        	echo "${Green} Apereo CAS Prefix : ${Yellow}${CAS_PREFIX}"
        	echo "${Green} Apereo CAS Install PATH : ${Yellow}${CAS_INSTALL_PATH}"
        	echo "${Green} Apereo CAS Properties path : ${Yellow}${CAS_PROPERTIES_PATH}"
        	echo "${Green} Apereo CAS log4j2 properties path : ${Yellow}${CAS_LOG4J2_PATH}"
        	echo "${Green} Apereo CAS server name : ${Yellow}${CAS_SERVER_NAME}"
        	echo "${Green} Apereo CAS server prefix : ${Yellow}${CAS_SERVER_PREFIX}"
        	echo "${Green} Apereo CAS Service registry location :${Yellow} ${CAS_SERVICEREGISTRY_JSON_LOCATION}"
        	echo "${Green} Apereo CAS service name : ${Yellow}${CAS_SERVICE_NAME}"
        	echo "${Green} Apereo CAS service ID : ${Yellow}${CAS_SERVICE_ID}"
		if [ ${CONFIGURE_GOOGLE} = true ]; then
        	echo "${Green} PAC4J Google ID : ${Yellow}${CAS_AUTHN_PAC4J_GOOGLE_ID}"
        	echo "${Green} PAC4J Google Secret : ${Yellow}${CAS_AUTHN_PAC4J_GOOGLE_SECRET}"
        	echo "${Green} PAC4J Google Scope : ${Yellow}${CAS_AUTHN_PAC4J_GOOGLE_SCOPE}"
		fi
		;;
esac

while true; do
	echo -n "${Green} Would you like to change the authentication method and properties (default no)? ${Yellow}"
	read yn
	case $yn in
		[Yy]* ) prime_auth_ext_menu; break;;
		[Nn]*|"" ) break;;
		* ) echo "${Green} Please enter yes or no. ${Yellow}";;
	esac
done

sum_menu
}

######  SELECTED EXTENSIONS SUMMARY  #################################
sum_secondary_auth_ext () {
SUB_MENU_TITLE="2FA Extension Summary"

menu_header

echo -e "${Green} 2FA selection: ${Yellow}${TFA_TYPE}\n"

# Check the authentication selection to display proper information for the selection
case $TFA_TYPE in
	"None")
		echo -e "${Yellow}${Bold} -- No form of 2FA will be implemented by this script --${Reset}\n"
		;;
	"TOTP")
		echo "${Green} TOTP issuer: ${Yellow}${TOTP_ISSUER}"
		echo "${Green} Number of TOTP digits: ${Yellow}${TOTP_DIGITS}"
		echo "${Green} TOTP period in seconds: ${Yellow}${TOTP_PER}"
		echo -e "${Green} TOTP mode: ${Yellow}${TOTP_MODE}\n"
		;;
	"DUO")
		echo -e "${Red} DUO cannot currently be installed by this script.\n"
		;;
esac

while true; do
	echo -n "${Green} Would you like to change the 2FA method and properties (default no)? ${Yellow}"
	read yn
	case $yn in
		[Yy]* ) secondary_auth_ext_menu; break;;
		[Nn]*|"" ) break;;
		* ) echo "${Green} Please enter yes or no. ${Yellow}";;
	esac
done

sum_menu
}

######  QUICKCONNECT EXTENSION SUMMARY  ####################################
sum_quickconnect () {
SUB_MENU_TITLE="QuickConnect Extension Summary"

menu_header

echo -e "${Green} Install QuickConnect extension: ${Yellow}${INSTALL_QC}\n"

while true; do
	echo -n "${Green} Would you like to change these selections (default no)? ${Yellow}"
	read yn
	case $yn in
		[Yy]* ) quickconnect_menu; break;;
		[Nn]*|"" ) break;;
		* ) echo "${Green} Please enter yes or no. ${Yellow}";;
	esac
done

sum_menu
}

######  MENU EXECUTION  ##############################################
db_menu
pw_menu
ssl_cert_type_menu
nginx_menu
prime_auth_ext_menu
secondary_auth_ext_menu
quickconnect_menu
sum_menu

# Sets file descriptor to 3 for this special echo function and spinner
exec 3>&1

######################################################################
######  UTILITY FUNCTIONS  ###########################################
######################################################################

######  PROGRESS SPINNER FUNCTION  ###################################
# Used to show a process is making progress/running
spinner () {
pid=$!
#Store the background process id in a temp file to use in err_handler
echo "$(jobs -p)" > "${VAR_FILE}"

spin[0]="-"
spin[1]="\\"
spin[2]="|"
spin[3]="/"

local _D0=$(date +%s)
# Loop while the process is still running
while kill -0 $pid 2>/dev/null
do
	for i in "${spin[@]}"
	do
		if kill -0 $pid 2>/dev/null; then #Check that the process is running to prevent a full 4 character cycle on error
			# Display the spinner in 1/4 states
			echo -ne "\b\b\b${Bold}[${Green}$i${Reset}${Bold}]" >&3
			sleep .5 # time between each state
		else #process has ended, stop next loop from finishing iteration
			break
		fi
	done
done

# Check if background process failed once complete
if wait $pid; then # Exit 0
	local _D1=$(date +%s)
	local _S=$(expr $_D1 - $_D0)
	echo -ne "\b\b\b${Bold}[${Green}-done-${Reset}${Bold}] : ${Yellow}$_S${Reset} secs" >&3
else # Any other exit
	false
fi

#Set background process id value to -1 representing no background process running to err_handler
echo "-1" > "${VAR_FILE}"

tput sgr0 >&3
}

######  SPECIAL ECHO FUNCTION  #######################################
# This allows echo to log and stdout (now fd3) while sending all else to log by default via exec
s_echo () {
# Use first arg $1 to determine if echo skips a line (yes/no)
# Second arg $2 is the message
case $1 in
	# No preceeding blank line
	[Nn])
		echo -ne "\n${2}" | tee -a /dev/fd/3
		echo # add new line after in log only
		;;
	# Preceeding blank line
	[Yy]|*)
		echo -ne "\n\n${2}" | tee -a /dev/fd/3
		echo # add new line after in log only
		;;
esac
}

# Used to force all stdout and stderr to the log file
# s_echo function will be used when echo needs to be displayed and logged
exec &> "${logfile}"

######  ERROR HANDLER FUNCTION  ######################################
# Called by trap to display/log error info and exit script
err_handler () {
EXITCODE=$?

#Read values from temp file used to store cross process values
F_BG=$(sed -n 1p "${VAR_FILE}")

# Check if the temp variable file is greater than 1 line of text
if [ "$(wc -l < "${VAR_FILE}")" -gt 1 ]; then
	# If so, set variable according to value of the 2nd line in the file.
	H_ERR=$(sed -n 2p "${VAR_FILE}")
else # Otherwise, set to false, error was not triggered previously
	H_ERR=false
fi

#Check this is the first time the err_handler has triggered
if [ $H_ERR = false ]; then
	#Check if error occured with a background process running
	if [ $F_BG -gt 0 ]; then
		echo -ne "\b\b\b${Bold}[${Red}-FAILED-${Reset}${Bold}]" >&3
	fi

	FAILED_COMMAND=$(eval echo "$BASH_COMMAND") # Used to expand the variables in the command returned by BASH_COMMAND
	s_echo "y" "${Reset}${Red}%%% ${Reset}${Bold}ERROR (Script Failed) | Line${Reset} ${BASH_LINENO[0]} ${Bold}| Command:${Reset} ${FAILED_COMMAND} ${Bold}| Exit code:${Reset} ${EXITCODE} ${Red}%%%${Reset}\n\n"

	#Flag as trap having been run already skipping double error messages
	echo "true" >> "${VAR_FILE}"
fi

# Log cleanup to remove escape sequences caused by tput for formatting text
sed -i 's/\x1b\[[0-9;]*m\|\x1b[(]B\x1b\[m//g' ${logfile}

tput sgr0 >&3
exit $EXITCODE
}

######  CHECK INSTALLED PACKAGE FUNCTION  ############################
# Query rpm for package without triggering trap when not found
chk_installed () {
if rpm -q "$@"; then
	RETVAL=$?
else
	RETVAL=$?
fi
}

######  ERROR TRAP  ##################################################
# Trap to call error function to display and log error details
trap err_handler ERR SIGINT SIGQUIT

######################################################################
######  INSALLATION  #################################################
######################################################################

######  REPOS INSTALLATION  ##########################################
reposinstall () {
s_echo "n" "${Bold}   ----==== INSTALLING GUACAMOLE ${GUAC_SOURCE} ${GUAC_VER} ====----"

# Initial Update OS/packages
{ yum update -y; yum install firewalld wget -y; } &
s_echo "y" "${Bold}Initial ${OS_NAME} Updating, please wait...    "; spinner

s_echo "y" "Installing Repos"

# Install EPEL Repo
chk_installed "epel-release"

if [ $RETVAL -eq 0 ]; then
	s_echo "n" "${Reset}-EPEL is installed."
else
	{ rpm -Uvh https://dl.fedoraproject.org/pub/epel/epel-release-latest-${MAJOR_VER}.noarch.rpm; } &
	s_echo "n" "${Reset}-EPEL is missing. Installing...    "; spinner
fi

# Install RPMFusion Repo
chk_installed "rpmfusion-free-release"

if [ $RETVAL -eq 0 ]; then
	s_echo "n" "-RPMFusion is installed."
else
	{ rpm -Uvh https://download1.rpmfusion.org/free/el/rpmfusion-free-release-${MAJOR_VER}.noarch.rpm; } &
	s_echo "n" "-RPMFusion is missing. Installing...    "; spinner
fi

# Install Nginx Repo
{ echo "[nginx-stable]
name=Nginx Stable Repo
baseurl=${NGINX_URL}
gpgcheck=1
enabled=1
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true" > /etc/yum.repos.d/nginx.repo; } &
s_echo "n" "${Reset}-Installing Nginx repo...    "; spinner

# Install libjpeg-turbo Repo
{
	REPO_FILE=/etc/yum.repos.d/libjpeg-turbo.repo
	[ -f ${REPO_FILE} ] && rm -f ${REPO_FILE}
	wget ${LIBJPEG_REPO} -P /etc/yum.repos.d/

	# Exclude beta releases
	sed -i "s/exclude.*/${LIBJPEG_EXCLUDE}/g" $REPO_FILE
} &
s_echo "n" "-Installing libjpeg-turbo repo...    "; spinner

# Enable repos needed if using RHEL
if [ $OS_NAME == "RHEL" ] ; then
	{ subscription-manager repos --enable "rhel-*-optional-rpms" --enable "rhel-*-extras-rpms"; } &
	s_echo "n" "-Enabling ${OS_NAME} optional and extras repos...    "; spinner
fi

yumupdate
}

######  YUM UPDATES  #################################################
yumupdate () {

# Update OS/packages
{ yum update -y; } &
s_echo "y" "${Bold}New REPO(s) added, updating ${OS_NAME}, please wait...    "; spinner

baseinstall
}

######  INSTALL BASE PACKAGES  #######################################
baseinstall () {
s_echo "y" "${Bold}Installing Required Dependencies"

# Install Required Packages
{
	yum install -y cairo-devel ffmpeg-devel freerdp-devel freerdp-plugins gcc gnu-free-mono-fonts libjpeg-turbo-devel libjpeg-turbo-official libpng-devel libssh2-devel libtelnet-devel libvncserver-devel libgcrypt-devel libvorbis-devel libwebp-devel libwebsockets-devel mariadb mariadb-server nginx openssl-devel pango-devel policycoreutils-python pulseaudio-libs-devel setroubleshoot uuid-devel nano mlocate net-tools wget telnet mlocate policycoreutils-python autoconf automake firewalld java-11-openjdk-11.0.16.0.8-1.el7_9 java-11-openjdk-devel-11.0.16.0.8-1.el7_9 git libtool jq;
} &
s_echo "n" "${Reset}-Installing required packages...    "; spinner

{ yum remove -y java-1.7.0-openjdk.x86_64 java-1.8.0-openjdk.x86_64; } &
{ update-alternatives --set java /usr/lib/jvm/java-11-openjdk-11.0.16.0.8-1.el7_9.x86_64/bin/java; } &
s_echo "n" "${Reset}-Removing Java 7 and Java 8...    "; spinner


# Additional packages required by git
if [ $GUAC_SOURCE == "Git" ]; then
	#{ yum install -y git libtool java-11-openjdk-devel; } &
	#s_echo "n" "-Installing packages required for git...    "; spinner

	#Install Maven
	cd /opt || return
	{
		wget ${MAVEN_URL}${MAVEN_BIN}
		tar -xvzf ${MAVEN_BIN}
		ln -sfn ${MAVEN_FN} maven
		rm -rf /opt/${MAVEN_BIN}
	} &
	s_echo "n" "-Installing Apache Maven for git and setup JAVA_HOME...    "; spinner
	export PATH=/opt/maven/bin:${PATH}
	export JAVA_HOME=/usr/lib/jvm/java-11
	cd ~ || return
fi

tomcatinstall

}

######  INSTALL TOMCAT ##########################################
tomcatinstall ()
{
	{ 	wget ${TOMCAT_URL} 
	  	mkdir -p ${TOMCAT_INSTALL_DIR}/tomcat 
	  	tar xf apache-tomcat-${TOMCAT_VER}.tar.gz -C ${TOMCAT_INSTALL_DIR}/tomcat --strip-components 1 
	  	rm apache-tomcat-${TOMCAT_VER}.tar.gz
                rm -rf ${TOMCAT_INSTALL_DIR}/tomcat/webapps/*
                groupadd -f ${SERVICE_GROUP}
	        useradd -r ${TOMCAT_USER} -m -s "/bin/nologin" -g ${SERVICE_GROUP} -c ${TOMCAT_USER}
		usermod -a -G ${SERVICE_GROUP} ${TOMCAT_USER} 
		chown -R ${TOMCAT_USER}:${SERVICE_GROUP} ${TOMCAT_INSTALL_DIR}/tomcat
	} &
	
s_echo "y" "${Bold}Downloading and installing Tomcat ...    "; spinner

	{
	    	touch tomcat.service
	    	chmod 777 tomcat.service 
	    	echo "[Unit]" > tomcat.service
	    	echo "Description=Apache Tomcat Web Application Container" >> tomcat.service
	    	echo "After=network.target" >> tomcat.service
	
	    	echo "[Service]" >> tomcat.service
	    	echo "Type=forking" >> tomcat.service
	
	    	echo "Environment=JAVA_HOME=$JAVA_HOME" >> tomcat.service
	    	echo "Environment=CATALINA_PID=/usr/share/tomcat/temp/tomcat.pid" >> tomcat.service
	    	echo "Environment=JAVA_OPTS=-Xms512M -Xmx1024M -server -XX:+UseParallelGC" >> tomcat.service
	    	echo "Environment=JAVA_OPTS=-Djava.awt.headless=true -Djava.security.egd=file:/dev/./urandom" >> tomcat.service
	    	echo "User=${TOMCAT_USER}" >> tomcat.service
	    	echo "Group=${SERVICE_GROUP}" >> tomcat.service
	
	    	echo "ExecStart=/usr/share/tomcat/bin/startup.sh" >> tomcat.service
	    	echo "ExecStop=/usr/share/tomcat/bin/shutdown.sh" >> tomcat.service
	
	    	#echo "User=tomcat" >> tomcat.service
	    	#echo "Group=tomcat" >> tomcat.service
	    	echo "UMask=0007" >> tomcat.service
	    	echo "RestartSec=10" >> tomcat.service
	    	echo "Restart=always" >> tomcat.service
	
	    	echo "[Install]" >> tomcat.service
	    	echo "WantedBy=multi-user.target" >> tomcat.service
	
	    	mv tomcat.service /etc/systemd/system/tomcat.service
	    	chmod 755 /etc/systemd/system/tomcat.service
	    	systemctl daemon-reload
	} &


# Setup direcotries like yum install does
	{
 		mkdir -p /var/lib/tomcat
 		mkdir -p /etc/tomcat
                ln -sf -T ${TOMCAT_INSTALL_DIR}/tomcat/webapps /var/lib/tomcat/webapps
                cp ${TOMCAT_INSTALL_DIR}/tomcat/conf/server.xml /etc/tomcat/server.xml
                rm ${TOMCAT_INSTALL_DIR}/tomcat/conf/server.xml
	} &
createdirs
}

######  CREATE DIRECTORIES  ##########################################
createdirs () {
{
	rm -fr ${INSTALL_DIR}
	mkdir -vp /etc/guacamole
	mkdir -vp ${INSTALL_DIR}{client,selinux}
	mkdir -vp ${LIB_DIR}{extensions,lib}
	mkdir -vp /usr/share/tomcat/.guacamole/
	mkdir -vp /var/lib/tomcat/webapps
	chown -R ${TOMCAT_USER}:${SERVICE_GROUP} /var/lib/tomcat
	chown -R ${TOMCAT_USER}:${SERVICE_GROUP} /usr/share/tomcat
} &
s_echo "y" "${Bold}Creating Required Directories...    "; spinner

cd ${INSTALL_DIR} || return

downloadguac
}

######  DOWNLOAD GUACAMOLE  ##########################################
downloadguac () {
s_echo "y" "${Bold}Downloading Guacamole Packages"

	# MySQL Connector
	downloadmysqlconn () {
		{ wget ${MYSQL_CON_URL}${MYSQL_CON}.tar.gz; } &
		s_echo "n" "-Downloading MySQL Connector package for installation...    "; spinner
	}

if [ $GUAC_SOURCE == "Git" ]; then
	{ git clone ${GUAC_URL}${GUAC_SERVER}; } &
	s_echo "n" "${Reset}-Cloning Guacamole Server package from git...    "; spinner
	{ git clone ${GUAC_URL}${GUAC_CLIENT}; } &
	s_echo "n" "-Cloning Guacamole Client package from git...    "; spinner
	downloadmysqlconn
else # Stable release
	{ wget "${GUAC_URL}source/${GUAC_SERVER}.tar.gz" -O ${GUAC_SERVER}.tar.gz; } &
	s_echo "n" "${Reset}-Downloading Guacamole Server package for installation...    "; spinner
	{ wget "${GUAC_URL}binary/${GUAC_CLIENT}.war" -O ${INSTALL_DIR}client/guacamole.war; } &
	s_echo "n" "-Downloading Guacamole Client package for installation...    "; spinner
	{ wget "${GUAC_URL}binary/${GUAC_JDBC}.tar.gz" -O ${GUAC_JDBC}.tar.gz; } &
	s_echo "n" "-Downloading Guacamole JDBC Extension package for installation...    "; spinner
	downloadmysqlconn

	# Decompress Guacamole Packages
	s_echo "y" "${Bold}Decompressing Guacamole Packages"

	{
		tar xzvf ${GUAC_SERVER}.tar.gz
		rm -f ${GUAC_SERVER}.tar.gz
		mv -v ${GUAC_SERVER} server
	} &
	s_echo "n" "${Reset}-Decompressing Guacamole Server source...    "; spinner

	{
		tar xzvf ${GUAC_JDBC}.tar.gz
		rm -f ${GUAC_JDBC}.tar.gz
		mv -v ${GUAC_JDBC} extension
		mv -v extension/mysql/guacamole-auth-jdbc-mysql-${GUAC_VER}.jar ${LIB_DIR}extensions/
	} &
	s_echo "n" "-Decompressing Guacamole JDBC extension...    "; spinner
fi

{
	tar xzvf ${MYSQL_CON}.tar.gz
	rm -f ${MYSQL_CON}.tar.gz
	mv -v ${MYSQL_CON}/${MYSQL_CON}.jar ${LIB_DIR}lib/
} &
s_echo "n" "-Decompressing MySQL Connector...    "; spinner

installguacserver
}

######  INSTALL GUACAMOLE SERVER  ####################################
installguacserver () {
s_echo "y" "${Bold}Install Guacamole Server"

if [ $GUAC_SOURCE == "Git" ]; then
	cd guacamole-server/ || return
	{ autoreconf -fi; } &
	s_echo "n" "${Reset}-Guacamole Server compile prep...    "; spinner
else # Stable release
	cd server || return
fi

# Compile Guacamole Server
{ ./configure --with-systemd-dir=/etc/systemd/system; } &
s_echo "n" "${Reset}-Compiling Guacamole Server Stage 1 of 4...    "; spinner
{ make; } &
s_echo "n" "-Compiling Guacamole Server Stage 2 of 4...    "; spinner
{ make install; } &
s_echo "n" "-Compiling Guacamole Server Stage 3 of 4...    "; spinner
{ ldconfig; } &
s_echo "n" "-Compiling Guacamole Server Stage 4 of 4...    "; spinner
cd ..

installguacclient
}

###### Download and install google-chrome ############################
googlechrome_chk() {
	if [ ! -x "/usr/bin/google-chrome" ]; then
		installgooglechrome
	fi
}

installgooglechrome () {

CHROME_URL="https://dl.google.com/linux/direct"
CHROME_RPM="google-chrome-stable_current_x86_64.rpm"

s_echo "y" "${Bold}Install Google Chrome"

	if [ ! -f "/root/${CHROME_RPM}" ]; then
		{ wget ${CHROME_URL}/${CHROME_RPM} -O /root/${CHROME_RPM}; } &
		s_echo "n" "-Download google-chrome browser...    "; spinner
	fi
	{ yum install -y /root/${CHROME_RPM}; } &
	s_echo "n" "-Install google-chrome browser...    "; spinner
}

######  INSTALL GUACAMOLE CLIENT  ####################################
installguacclient () {
s_echo "y" "${Bold}Install Guacamole Client"

if [ $GUAC_SOURCE == "Git" ]; then
	# check whether google-chrome is installed, if not download and installed it.
	googlechrome_chk

	cd guacamole-client/
	{ mvn -X package; } &
	s_echo "n" "${Reset}-Compiling Guacamole Client...    "; spinner

	{ mv -v guacamole/target/guacamole-${GUAC_VER}.war ${LIB_DIR}guacamole.war; } &
	s_echo "n" "-Moving Guacamole Client...    "; spinner
	cd ..
else # Stable release
	{ mv -v client/guacamole.war ${LIB_DIR}guacamole.war; } &
	s_echo "n" "${Reset}-Moving Guacamole Client...    "; spinner
fi

finishguac
}

######  FINALIZE GUACAMOLE INSTALLATION  #############################
finishguac () {
s_echo "y" "${Bold}Setup Guacamole"

# Generate Guacamole Configuration File
{ echo "# Hostname and port of guacamole proxy
guacd-hostname: localhost
guacd-port:     ${GUAC_PORT}
# MySQL properties
mysql-hostname: localhost
mysql-port: ${MYSQL_PORT}
mysql-database: ${DB_NAME}
mysql-username: ${DB_USER}
mysql-password: ${DB_PASSWD}
mysql-default-max-connections-per-user: 0
mysql-default-max-group-connections-per-user: 0" > /etc/guacamole/${GUAC_CONF}; } &
s_echo "n" "${Reset}-Generating Guacamole configuration file...    "; spinner

# Create guacd.conf file, this fix it to accept connection from local IPv4 only
{ echo "[server]
bind_host = 127.0.0.1
bind_port = 4822" > /etc/guacamole/${GUACD_CONF}; } &
s_echo "n" "${Reset}-Generating guacd config file...   "; spinner

# Create Required Symlinks for Guacamole
{
	ln -vfs ${LIB_DIR}guacamole.war /var/lib/tomcat/webapps
	ln -vfs /etc/guacamole/${GUAC_CONF} /usr/share/tomcat/.guacamole/
	ln -vfs ${LIB_DIR}lib/ /usr/share/tomcat/.guacamole/
	ln -vfs ${LIB_DIR}extensions/ /usr/share/tomcat/.guacamole/
	ln -vfs /usr/local/lib/freerdp/guac* /usr/lib${ARCH}/freerdp
	chown -R ${TOMCAT_USER}:${SERVICE_GROUP} /var/lib/tomcat
	chown -R ${TOMCAT_USER}:${SERVICE_GROUP} /usr/share/tomcat
} &
s_echo "n" "-Making required symlinks...    "; spinner

# Copy JDBC if using git
if [ $GUAC_SOURCE == "Git" ]; then
	# Get JDBC from compiled client
	{ find ./guacamole-client/extensions -name "guacamole-auth-jdbc-mysql-${GUAC_VER}.jar" -exec mv -v {} ${LIB_DIR}extensions/ \;; } &
	s_echo "n" "-Moving Guacamole JDBC extension to extensions dir...    "; spinner
fi

# Setup guacd user, group and permissions
{
	# Create a user and group for guacd with a home folder but no login
	trap '' ERR
	GRP_EXIST=$(getent group | grep -o '^guacd:')
	trap err_handler ERR
	[ -z "$GRP_EXIST" ] && groupadd ${GUACD_USER}
	# The guacd user is created as a service account, no login but does get a home dir as needed by freerdp
	trap '' ERR
	USR_EXIST=$(getent passwd | grep -o '^guacd:')
	trap err_handler ERR
	[ -z "$USR_EXIST" ] && useradd -r ${GUACD_USER} -m -s "/bin/nologin" -g ${GUACD_USER} -c ${GUACD_USER}

	# Set the user that runs the guacd service
	sed -i "s/User=daemon/User=${GUACD_USER}/g" /etc/systemd/system/guacd.service
} &
s_echo "n" "-Setup guacd user...    "; spinner

appconfigs
}

######  DATABASE/TOMCAT/JKS SETUP  ###################################
appconfigs () {
s_echo "y" "${Bold}Configure MariaDB"

# Enable/Start MariaDB/MySQL Service
{
	systemctl enable mariadb.service
	systemctl restart mariadb.service
} &
s_echo "n" "${Reset}-Enable & start MariaDB service...    "; spinner

# Set MariaDB/MySQL Root Password
{ mysql -u root -p${MYSQL_PASSWD} || mysqladmin -u root password ${MYSQL_PASSWD}; } &
s_echo "n" "-Setting root password for MariaDB...    "; spinner

# Run MariaDB/MySQL Secure Install
{
	mysql_secure_installation <<EOF
${MYSQL_PASSWD}
n
y
y
y
y
EOF
	sed -i -e '13abind-address = 127.0.0.1' /etc/my.cnf.d/server.cnf
} &
s_echo "n" "-Harden MariaDB...    "; spinner

# Create Guacamole Database and user
{
	trap '' ERR
	DBEXIST=$(mysql -u root -p${MYSQL_PASSWD} -e 'show databases;' | grep "^${DB_NAME}$")
	trap err_handler ERR
	[ "${DBEXIST}" ] && \
	mysqldump -u root -p${MYSQL_PASSWD} ${DB_NAME} > "/root/db-${DB_NAME}-$(date +%s).sql"
	mysql -u root -p${MYSQL_PASSWD} -e "DROP DATABASE IF EXISTS ${DB_NAME};"
	mysql -u root -p${MYSQL_PASSWD} -e "CREATE DATABASE ${DB_NAME};"
	mysql -u root -p${MYSQL_PASSWD} -e "GRANT SELECT,INSERT,UPDATE,DELETE ON ${DB_NAME}.* TO '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASSWD}';"
	mysql -u root -p${MYSQL_PASSWD} -e "FLUSH PRIVILEGES;"
} &
s_echo "n" "-Creating Database & User for Guacamole...    "; spinner

# Create Guacamole Table
{
	if [ $GUAC_SOURCE == "Git" ]; then
		cat guacamole-client/extensions/guacamole-auth-jdbc/modules/guacamole-auth-jdbc-mysql/schema/*.sql | mysql -u root -p${MYSQL_PASSWD} -D ${DB_NAME}
	else # Stable release
		cat extension/mysql/schema/*.sql | mysql -u root -p${MYSQL_PASSWD} -D ${DB_NAME}
	fi
} &
s_echo "n" "-Creating Guacamole Tables...    "; spinner

# Apereo CAS Create Database and user
{
	trap '' ERR
	DBEXIST=$(mysql -u root -p${MYSQL_PASSWD} -e 'show databases;' | grep "^${CAS_DB_NAME}$")
	trap err_handler ERR
	[ "${DBEXIST}" ] && \
	mysqldump -u root -p${MYSQL_PASSWD} ${DB_NAME} > "/root/db-${CAS_DB_NAME}-$(date +%s).sql"
	mysql -u root -p${MYSQL_PASSWD} -e "DROP DATABASE IF EXISTS ${CAS_DB_NAME};"
	mysql -u root -p${MYSQL_PASSWD} -e "CREATE DATABASE ${CAS_DB_NAME};"
	mysql -u root -p${MYSQL_PASSWD} -e "GRANT SELECT,INSERT,UPDATE,DELETE ON ${CAS_DB_NAME}.* TO '${CAS_DB_USER}'@'localhost' IDENTIFIED BY '${CAS_DB_PASSWD}';"
	mysql -u root -p${MYSQL_PASSWD} -e "FLUSH PRIVILEGES;"
} &
s_echo "n" "-Creating Database & User for Apereo CAS...    "; spinner

# Populate mysql database with time zones from system
# Fixes timezone issues when using MySQLConnectorJ 8.x or geater
{
	mysql_tzinfo_to_sql /usr/share/zoneinfo | mysql -u root mysql -p${MYSQL_PASSWD}
	MY_CNF_LINE=$(grep -n "\[mysqld\]" /etc/my.cnf | grep -o '^[0-9]*')
	MY_CNF_LINE=$((MY_CNF_LINE + 1 ))
	MY_TZ=$(readlink /etc/localtime | sed "s/.*\/usr\/share\/zoneinfo\///")
	sed -i "${MY_CNF_LINE}i default-time-zone='${MY_TZ}'" /etc/my.cnf
	systemctl restart mariadb
} &
s_echo "n" "-Setting Time Zone Database & Config...    "; spinner

# Setup Tomcat
s_echo "y" "${Bold}Setup Tomcat Server"

{
	sed -i '70i URIEncoding="UTF-8"' /etc/tomcat/server.xml
	sed -i '96i    <Connector port="8443" \
			           protocol="org.apache.coyote.http11.Http11NioProtocol" \
			           maxThreads="150" \
			           compression="on" \
			           scheme="https" \
			           SSLEnabled="true" \
			           secure="true" \
			           defaultSSLHostConfigName="guacamole"> \
			    <SSLHostConfig hostName="guacamole" \
			                   protocols="TLSv1.2"> \
			        <Certificate certificateKeystoreFile="/var/lib/tomcat/webapps/.keystore" \
			                     certificateKeystorePassword="guac_adm" \
			                      /> \
			    </SSLHostConfig> \
			</Connector>' /etc/tomcat/server.xml
	sed -i "s/JKS_GUAC_PASSWD/${JKS_GUAC_PASSWD}/g" /etc/tomcat/server.xml
} &
s_echo "n" "${Reset}-Base Tomcat configuration...    "; spinner

{
# Tomcat RemoteIpValve (to pass remote host IP's from proxy to tomcat. Allows Guacamole to log remote host IPs)
	sed -i '/<\/Host>/i\<Valve className="org.apache.catalina.valves.RemoteIpValve" \
							internalProxies="GUAC_SERVER_IP" \
							remoteIpHeader="x-forwarded-for" \
							remoteIpProxiesHeader="x-forwarded-by" \
							protocolHeader="x-forwarded-proto" />' /etc/tomcat/server.xml

	sed -i "s/GUAC_SERVER_IP/${GUAC_LAN_IP}/g" /etc/tomcat/server.xml
} &
s_echo "n" "-Set RemoteIpValve in Tomcat configuration...    "; spinner

{
# Add ErrorReportingValve to prevent displaying tomcat info on error pages
	sed -i '/<\/Host>/i\<Valve className="org.apache.catalina.valves.ErrorReportValve" \
							showReport="false" \
							showServerInfo="false"/>' /etc/tomcat/server.xml
	chown -R ${TOMCAT_USER}:${SERVICE_GROUP} /etc/tomcat
} &
s_echo "n" "-Set ErrorReportingVavle in Tomcat configuration...    "; spinner
# Java KeyStore Setup
{ 
	KEYSTORE=/var/lib/tomcat/webapps/.keystore;
	[ -f "${KEYSTORE}" ] && mv -f "${KEYSTORE}" "${KEYSTORE}-$(date +%s)";
	keytool -genkey -alias Guacamole -keyalg RSA -keysize ${JKSTORE_KEY_SIZE} \
		-keystore ${KEYSTORE} -storepass ${JKS_GUAC_PASSWD} \
		-keypass ${JKS_GUAC_PASSWD} -noprompt \
		-dname "CN='', OU='', O='', L='', S='', C=''"; } &
s_echo "y" "${Bold}Configuring the Java KeyStore...    "; spinner

# Enable/Start Tomcat and Guacamole Services
{
	systemctl enable tomcat
	systemctl restart tomcat
	systemctl enable guacd
	systemctl restart guacd
} &
s_echo "y" "${Bold}Enable & Start Tomcat and Guacamole Services...    "; spinner

nginxcfg
}

######  NGINX CONFIGURATION  #########################################
nginxcfg () {
s_echo "y" "${Bold}Nginx Configuration"

# Backup Nginx Configuration
{ 
	set -x;
	CONF="/etc/nginx/conf.d/default.conf";
  	[ -f "${CONF}" ] && mv -f ${CONF} ${CONF}.ori.bkp; 
	set +x;
} &
s_echo "n" "${Reset}-Making Nginx config backup...    "; spinner

# Need this for generating a LE certificate for domain validation
{ echo "server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN_NAME};
    return 301 https://\$host\$request_uri;
}" > /etc/nginx/conf.d/guacamole.conf 
} &

s_echo "n" "${Reset}-Generate Nginx guacamole.config...    "; spinner

# HTTPS/SSL Nginx Conf
{
	echo "server {
		#listen 443 ssl http2 default_server;
		#listen [::]:443 ssl http2 default_server;
		server_name ${DOMAIN_NAME};
		server_tokens off;
		#ssl_certificate guacamole.crt;
		#ssl_certificate_key guacamole.key; " > /etc/nginx/conf.d/guacamole_ssl.conf

	# If OCSP Stapling was selected add lines
	if [ $OCSP_USE = true ]; then
		if [[ -r /etc/resolv.conf ]]; then
	            NAME_SERVERS=$(awk '/^nameserver/{print $2}' /etc/resolv.conf | xargs)
	        fi
		    
		if [[ -z $NAME_SERVERS ]]; then
		    NAME_SERVERS=$NAME_SERVERS_DEF
		fi
		
		echo "	#ssl_trusted_certificate guacamole.pem;
		ssl_stapling on;
		ssl_stapling_verify on;
		resolver ${NAME_SERVERS} valid=30s;
		resolver_timeout 30s;" >> /etc/nginx/conf.d/guacamole_ssl.conf
	fi

	# If using >= 256-bit ciphers
	if [ $NGINX_SEC = true ]; then
		echo "	ssl_ciphers 'TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-SHA384';" >> /etc/nginx/conf.d/guacamole_ssl.conf
	else
		echo "	ssl_ciphers 'TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA256';" >> /etc/nginx/conf.d/guacamole_ssl.conf
	fi

	# Rest of HTTPS/SSL Nginx Conf
	echo "	ssl_protocols TLSv1.3 TLSv1.2;
		ssl_ecdh_curve secp521r1:secp384r1:prime256v1;
		ssl_prefer_server_ciphers on;
		ssl_session_cache shared:SSL:10m;
		ssl_session_timeout 1d;
		ssl_session_tickets off;
		add_header Referrer-Policy \"no-referrer\";
		add_header Strict-Transport-Security \"max-age=15768000; includeSubDomains\" always;" >> /etc/nginx/conf.d/guacamole_ssl.conf
		
	# If CSP was enabled, add line, otherwise add but comment out (to allow easily manual toggle of the feature)
	if [ $USE_CSP = true ]; then
		echo "	add_header Content-Security-Policy \"default-src 'none'; script-src 'self' 'unsafe-eval'; connect-src 'self' wss://${DOMAIN_NAME}; object-src 'self'; frame-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self'; form-action 'self'; base-uri 'self'; frame-ancestors 'self';\" always;" >> /etc/nginx/conf.d/guacamole_ssl.conf
	else
		echo "	#add_header Content-Security-Policy \"default-src 'none'; script-src 'self' 'unsafe-eval'; connect-src 'self' wss://${DOMAIN_NAME}; object-src 'self'; frame-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self'; form-action 'self'; base-uri 'self'; frame-ancestors 'self';\" always;" >> /etc/nginx/conf.d/guacamole_ssl.conf
	fi

	echo "	add_header X-Frame-Options \"SAMEORIGIN\" always;
		add_header X-Content-Type-Options \"nosniff\" always;
		add_header X-XSS-Protection \"1; mode=block\" always;
		proxy_hide_header Server;
		proxy_hide_header X-Powered-By;
		client_body_timeout 10;
		client_header_timeout 10;

                rewrite ^/$ /guacamole;

		location ${GUAC_URIPATH} {
		proxy_pass http://${GUAC_LAN_IP}:8080/;
		proxy_buffering off;
		proxy_http_version 1.1;
		proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
		proxy_set_header Upgrade \$http_upgrade;
		proxy_set_header Connection \$http_connection;
		proxy_cookie_path /guacamole/ \"${GUAC_URIPATH}; HTTPOnly; Secure; SameSite\";
		access_log /var/log/nginx/guac_access.log;
		error_log /var/log/nginx/guac_error.log;
		}
	}" >> /etc/nginx/conf.d/guacamole_ssl.conf
} &
s_echo "n" "-Generate Nginx guacamole_ssl.config...    "; spinner

# Nginx CIS hardening v1.0.0
{
	# 2.3.2 Restrict access to Nginx files
	find /etc/nginx -type d -print0 | xargs -0 chmod 750
	find /etc/nginx -type f -print0 | xargs -0 chmod 640

	# 2.4.3 & 2.4.4 set keepalive_timeout and send_timeout to 1-10 seconds, default 65/60.
	sed -i '/keepalive_timeout/c\keepalive_timeout 10\;' /etc/nginx/nginx.conf
	# sed -i '/send_timeout/c\send_timeout 10\;' /etc/nginx/nginx.conf

	# 2.5.2 Removing mentions of Nginx from index and error pages
	! read -r -d '' BLANK_HTML <<"EOF"
<!DOCTYPE html>
<html>
<head>
</head>
<body>
</body>
</html>
EOF

	echo "${BLANK_HTML}" > /usr/share/nginx/html/index.html
	echo "${BLANK_HTML}" > /usr/share/nginx/html/50x.html

	# 3.4 Ensure logs are rotated (may set this as a user defined parameter)
	sed -i "s/daily/weekly/" /etc/logrotate.d/nginx
	sed -i "s/rotate 52/rotate 13/" /etc/logrotate.d/nginx
} &
s_echo "n" "-Hardening Nginx config...    "; spinner

# Enable and Start Nginx Service
{
	systemctl enable nginx
	systemctl start nginx
} &
s_echo "n" "-Enable Nginx Service...    "; spinner

# Call each Guac extension function for those selected
if [ $INSTALL_LDAP = true ]; then ldapsetup; fi
if [ $INSTALL_TOTP = true ]; then totpsetup; fi
if [ $INSTALL_DUO = true ]; then duosetup; fi
if [ $INSTALL_RADIUS = true ]; then radiussetup; fi
if [ $INSTALL_CAS = true ]; then casextsetup; fi
if [ $INSTALL_OPENID = true ]; then openidsetup; fi
if [ $INSTALL_QC = true ]; then quickconnectsetup; fi
if [ $INSTALL_APEREOCAS = true ]; then apereocassetup; fi

selinuxsettings
}

######  LDAP SETUP  ##################################################
ldapsetup () {
s_echo "y" "${Bold}Setup the LDAP Extension"

# Append LDAP configuration lines to guacamole.properties
{ echo "
# LDAP properties
ldap-hostname: ${LDAP_HOSTNAME}
ldap-port: ${LDAP_PORT}" >> /etc/guacamole/${GUAC_CONF}; } &
s_echo "n" "${Reset}-Updating guacamole.properties file for LDAP...    "; spinner

# LDAPS specific properties
if [ $SECURE_LDAP = true ]; then
	{
		KS_PATH=$(find "/usr/lib/jvm/" -name "cacerts")
		keytool -storepasswd -new ${JKS_CACERT_PASSWD} -keystore ${KS_PATH} -storepass "changeit" 
		keytool -importcert -alias "ldaps" -keystore ${KS_PATH} -storepass ${JKS_CACERT_PASSWD} -file ${LDAPS_CERT_FULL} -noprompt

		echo "ldap-encryption-method: ssl" >> /etc/guacamole/${GUAC_CONF}
	} &
	s_echo "n" "-Updating guacamole.properties file for LDAPS...    "; spinner
fi

# Finish appending general LDAP configuration lines to guacamole.properties
{ echo "ldap-user-base-dn: ${LDAP_BASE_DN}
ldap-search-bind-dn: ${LDAP_BIND_DN}
ldap-search-bind-password: ${LDAP_BIND_PW}
ldap-username-attribute: ${LDAP_UNAME_ATTR}
ldap-user-search-filter: ${LDAP_SEARCH_FILTER}
mysql-auto-create-accounts: true" >> /etc/guacamole/${GUAC_CONF}; } &
s_echo "n" "-Finishing updates to the guacamole.properties file for LDAP...    "; spinner

if [ $GUAC_SOURCE == "Git" ]; then
	# Copy LDAP Extension to Extensions Directory
	{ find ./guacamole-client/extensions -name "${GUAC_LDAP}.jar" -exec mv -v {} ${LIB_DIR}extensions/ \;; } &
	s_echo "n" "-Moving Guacamole LDAP extension to extensions dir...    "; spinner
else # Stable release
	# Download LDAP Extension
	{ wget "${GUAC_URL}binary/${GUAC_LDAP}.tar.gz" -O ${GUAC_LDAP}.tar.gz; } &
	s_echo "n" "-Downloading LDAP extension...    "; spinner

	# Decompress LDAP Extension
	{
		tar xzvf ${GUAC_LDAP}.tar.gz 
		rm -f ${GUAC_LDAP}.tar.gz
		mv ${GUAC_LDAP} extension
	} &
	s_echo "n" "-Decompressing Guacamole LDAP Extension...    "; spinner

	# Copy LDAP Extension to Extensions Directory
	{ mv -v extension/${GUAC_LDAP}/${GUAC_LDAP}.jar ${LIB_DIR}extensions/; } &
	s_echo "n" "-Moving Guacamole LDAP extension to extensions dir...    "; spinner
fi
}

######  TOTP SETUP  ##################################################
totpsetup () {
s_echo "y" "${Bold}Setup the TOTP Extension"

# Append TOTP configuration lines to guacamole.properties
{ echo "
# TOTP properties
totp-issuer: ${TOTP_ISSUER}
totp-digits: ${TOTP_DIGITS}
totp-period: ${TOTP_PER}
totp-mode: ${TOTP_MODE}" >> /etc/guacamole/${GUAC_CONF}; } &
s_echo "n" "${Reset}-Updating guacamole.properties file for TOTP...    "; spinner

if [ $GUAC_SOURCE == "Git" ]; then
   # Copy TOTP Extension to Extensions Directory
   { find ./guacamole-client/extensions -name "${GUAC_TOTP}.jar" -exec mv -v {} ${LIB_DIR}extensions/ \;; } &
   s_echo "n" "-Moving Guacamole TOTP extension to extensions dir...    "; spinner
else # Stable release
   # Download TOTP Extension
   { wget "${GUAC_URL}binary/${GUAC_TOTP}.tar.gz" -O ${GUAC_TOTP}.tar.gz; } &
   s_echo "n" "-Downloading TOTP extension...    "; spinner

   # Decompress TOTP Extension
   {
      tar xzvf ${GUAC_TOTP}.tar.gz 
      rm -f ${GUAC_TOTP}.tar.gz
      mv ${GUAC_TOTP} extension
   } &
   s_echo "n" "-Decompressing Guacamole TOTP Extension...    "; spinner

   # Copy TOTP Extension to Extensions Directory
   { mv -v extension/${GUAC_TOTP}/${GUAC_TOTP}.jar ${LIB_DIR}extensions/; } &
   s_echo "n" "-Moving Guacamole TOTP extension to extensions dir...    "; spinner
fi
}

######  QUICKCONNECT SETUP  ##################################################
quickconnectsetup () {
s_echo "y" "${Bold}Setup the QUICKCONNECT Extension"

if [ $GUAC_SOURCE == "Git" ]; then
   # Copy QUICKCONNECT Extension to Extensions Directory
   { find ./guacamole-client/extensions -name "${GUAC_QC}.jar" -exec mv -v {} ${LIB_DIR}extensions/ \;; } &
   s_echo "n" "-Moving Guacamole QUICKCONNECT extension to extensions dir...    "; spinner
else # Stable release
   # Download QUICKCONNECT Extension
   { wget "${GUAC_URL}binary/${GUAC_QC}.tar.gz" -O ${GUAC_QC}.tar.gz; } &
   s_echo "n" "-Downloading QUICKCONNECT extension...    "; spinner

   # Decompress TOTP Extension
   {
      tar xzvf ${GUAC_QC}.tar.gz 
      rm -f ${GUAC_QC}.tar.gz
      mv ${GUAC_QC} extension
   } &
   s_echo "n" "-Decompressing Guacamole QUICKCONNECT Extension...    "; spinner

   # Copy QUICKCONNECT Extension to Extensions Directory
   { mv -v extension/${GUAC_QC}/${GUAC_QC}.jar ${LIB_DIR}extensions/; } &
   s_echo "n" "-Moving Guacamole QUICKCONNECT extension to extensions dir...    "; spinner
fi
}

######  APEREO CAS SETUP  ##################################################
apereocassetup () {
s_echo "y" "${Bold}Setting up APEREO CAS"
	{ cd ${CAS_INSTALL_DIR}
          git clone "${APEREO_GIT_URL}" --branch ${APEREO_CAS_VER} 
          sed -i '129i \    implementation "org.apereo.cas:cas-server-support-pac4j-webflow"' cas-overlay-template/build.gradle
	  sed -i '130i \    implementation "org.apereo.cas:cas-server-support-json-service-registry"' cas-overlay-template/build.gradle
          mkdir -p ${CAS_HOME}/services
	  echo '<?xml version="1.0" encoding="UTF-8" ?>
		<!-- Specify the refresh internal in seconds. -->
		<Configuration monitorInterval="5" packages="org.apereo.cas.logging">
		    <Properties>
		        <!--
		        Default log directory is the current directory but that can be overridden with -Dcas.log.dir=<logdir>
		        Or you can change this property to a new default
		        -->
		        <Property name="cas.log.dir" >/usr/share/tomcat/logs</Property>
		        <!-- To see more CAS specific logging, adjust this property to info or debug or run server with -Dcas.log.leve=debug -->
		        <Property name="cas.log.level" >info</Property>
		    </Properties>
		    <Appenders>
		        <Console name="console" target="SYSTEM_OUT">
		            <PatternLayout pattern="%d %p [%c] - &lt;%m&gt;%n"/>
		        </Console>
		        <RollingFile name="file" fileName="${sys:cas.log.dir}/cas.log" append="true"
		                     filePattern="${sys:cas.log.dir}/cas-%d{yyyy-MM-dd-HH}-%i.log">
		            <PatternLayout pattern="%d %p [%c] - &lt;%m&gt;%n"/>
		            <Policies>
		                <OnStartupTriggeringPolicy />
		                <SizeBasedTriggeringPolicy size="10 MB"/>
		                <TimeBasedTriggeringPolicy />
		            </Policies>
		        <DefaultRolloverStrategy max="1"/>
		        </RollingFile>
		        <RollingFile name="auditlogfile" fileName="${sys:cas.log.dir}/cas_audit.log" append="true"
		                     filePattern="${sys:cas.log.dir}/cas_audit-%d{yyyy-MM-dd-HH}-%i.log">
		            <PatternLayout pattern="%d %p [%c] - %m%n"/>
		            <Policies>
		                <OnStartupTriggeringPolicy />
		                <SizeBasedTriggeringPolicy size="10 MB"/>
		                <TimeBasedTriggeringPolicy />
		            </Policies>
		            <DefaultRolloverStrategy max="1"/>
		        </RollingFile>
		
		        <RollingFile name="perfFileAppender" fileName="${sys:cas.log.dir}/perfStats.log" append="true"
		                     filePattern="${sys:cas.log.dir}/perfStats-%d{yyyy-MM-dd-HH}-%i.log">
		            <PatternLayout pattern="%m%n"/>
		            <Policies>
		                <OnStartupTriggeringPolicy />
		                <SizeBasedTriggeringPolicy size="10 MB"/>
		                <TimeBasedTriggeringPolicy />
		            </Policies>
		            <DefaultRolloverStrategy max="1"/>
		        </RollingFile>
		
		        <CasAppender name="casAudit">
		            <AppenderRef ref="auditlogfile" />
		        </CasAppender>
		        <CasAppender name="casFile">
		            <AppenderRef ref="file" />
		        </CasAppender>
		        <CasAppender name="casConsole">
		            <AppenderRef ref="console" />
		        </CasAppender>
		        <CasAppender name="casPerf">
		            <AppenderRef ref="perfFileAppender" />
		        </CasAppender>
		    </Appenders>
		    <Loggers>
		        <!-- If adding a Logger with level set higher than warn, make category as selective as possible -->
		        <!-- Loggers inherit appenders from Root Logger unless additivity is false -->
		        <AsyncLogger name="org.apereo" level="${sys:cas.log.level}" includeLocation="true"/>
		        <AsyncLogger name="org.apereo.services.persondir" level="${sys:cas.log.level}" includeLocation="true"/>
		        <AsyncLogger name="org.apereo.cas.web.flow" level="info" includeLocation="true"/>
		        <AsyncLogger name="org.apache" level="warn" />
		        <AsyncLogger name="org.apache.http" level="error" />
		        <AsyncLogger name="org.springframework" level="warn" />
		        <AsyncLogger name="org.springframework.cloud.server" level="warn" />
		        <AsyncLogger name="org.springframework.cloud.client" level="warn" />
		        <AsyncLogger name="org.springframework.cloud.bus" level="warn" />
		        <AsyncLogger name="org.springframework.aop" level="warn" />
		        <AsyncLogger name="org.springframework.boot" level="warn" />
		        <AsyncLogger name="org.springframework.boot.actuate.autoconfigure" level="warn" />
		        <AsyncLogger name="org.springframework.webflow" level="warn" />
		        <AsyncLogger name="org.springframework.session" level="warn" />
		        <AsyncLogger name="org.springframework.amqp" level="error" />
		        <AsyncLogger name="org.springframework.integration" level="warn" />
		        <AsyncLogger name="org.springframework.messaging" level="warn" />
		        <AsyncLogger name="org.springframework.web" level="warn" />
		        <AsyncLogger name="org.springframework.orm.jpa" level="warn" />
		        <AsyncLogger name="org.springframework.scheduling" level="warn" />
		        <AsyncLogger name="org.springframework.context.annotation" level="error" />
		        <AsyncLogger name="org.springframework.boot.devtools" level="error" />
		        <AsyncLogger name="org.springframework.web.socket" level="warn" />
		        <AsyncLogger name="org.thymeleaf" level="warn" />
		        <AsyncLogger name="org.pac4j" level="warn" />
		        <AsyncLogger name="org.opensaml" level="warn"/>
		        <AsyncLogger name="net.sf.ehcache" level="warn" />
		        <AsyncLogger name="com.couchbase" level="warn" includeLocation="true"/>
		        <AsyncLogger name="com.ryantenney.metrics" level="warn" />
		        <AsyncLogger name="net.jradius" level="warn" />
		        <AsyncLogger name="org.openid4java" level="warn" />
		        <AsyncLogger name="org.ldaptive" level="warn" />
		        <AsyncLogger name="com.hazelcast" level="warn" />
		        <AsyncLogger name="org.jasig.spring" level="warn" />
		
		        <AsyncLogger name="org.pac4j" level="warn" additivity="true">
		            <AppenderRef ref="casConsole"/>
		            <AppenderRef ref="casFile"/>
		        </AsyncLogger>
		
		        <!-- Log perf stats only to perfStats.log -->
		        <AsyncLogger name="perfStatsLogger" level="info" additivity="false" includeLocation="true">
		            <AppenderRef ref="casPerf"/>
		        </AsyncLogger>
		
		        <!-- Log audit to all root appenders, and also to audit log (additivity is not false) -->
		        <AsyncLogger name="org.apereo.inspektr.audit.support" level="info" includeLocation="true" >
		            <AppenderRef ref="casAudit"/>
		        </AsyncLogger>
		
		        <!-- All Loggers inherit appenders specified here, unless additivity="false" on the Logger -->
		        <AsyncRoot level="warn">
		            <AppenderRef ref="casFile"/>
		            <!--
		                 For deployment to an application server running as service,
		                 delete the casConsole appender below
		            -->
		            <AppenderRef ref="casConsole"/>
		        </AsyncRoot>
		    </Loggers>
		</Configuration>' > cas-overlay-template/etc/cas/config/log4j2.xml

          if [ ${CONFIGURE_GOOGLE} = true ]; then
          echo "cas.server.name:${CAS_SERVER_NAME}
cas.server.prefix:${CAS_SERVER_PREFIX}

cas.authn.accept.users=
logging.config=file:${CAS_HOME}/log4j2.xml

cas.view.defaultRedirectUrl=${CAS_REDIRECT_URI}

cas.authn.pac4j.google.id=${CAS_AUTHN_PAC4J_GOOGLE_ID}
cas.authn.pac4j.google.secret=${CAS_AUTHN_PAC4J_GOOGLE_SECRET}
cas.authn.pac4j.google.scope=${CAS_AUTHN_PAC4J_GOOGLE_SCOPE}

cas.serviceRegistry.json.location=${CAS_SERVICEREGISTRY_JSON_LOCATION}
          " > cas-overlay-template/etc/cas/config/cas.properties
	  else
          echo "cas.server.name:${CAS_SERVER_NAME}
cas.server.prefix:${CAS_SERVER_PREFIX}

cas.authn.accept.users=
logging.config=file:${CAS_HOME}/log4j2.xml

cas.view.defaultRedirectUrl=${CAS_REDIRECT_URI}

cas.serviceRegistry.json.location=${CAS_SERVICEREGISTRY_JSON_LOCATION}
          " > cas-overlay-template/etc/cas/config/cas.properties
	  fi
	  echo "
guacamole.jdbc.saltFieldName=password_salt
# guacamole.jdbc.staticSalt=
guacamole.jdbc.sql=${GUAC_JDBC_SQL}
guacamole.jdbc.passwordFieldName=password_hash
guacamole.jdbc.healthQuery=${GUAC_JDBC_HEALTH_QUERY}
# guacamole.jdbc.isolateInternalQueries=false
guacamole.jdbc.url=jdbc:mysql://localhost:${MYSQL_PORT}/${DB_NAME}
# guacamole.jdbc.failFast=true
# guacamole.jdbc.isolationLevelName=ISOLATION_READ_COMMITTED
guacamole.jdbc.dialect=${GUAC_JDBC_DIALECT}
# guacamole.jdbc.leakThreshold=10
# guacamole.jdbc.propagationBehaviorName=PROPAGATION_REQUIRED
# guacamole.jdbc.batchSize=1
guacamole.jdbc.user=${DB_USER}
guacamole.jdbc.ddlAuto=none
# guacamole.jdbc.maxAgeDays=180
guacamole.jdbc.password=${DB_PASSWD}
# guacamole.jdbc.autocommit=false
guacamole.jdbc.driverClass=${GUAC_JDBC_DRIVER_CLASS}
# guacamole.jdbc.idleTimeout=5000
# guacamole.jdbc.credentialCriteria=

# guacamole.jdbc.passwordEncoder.type=NONE|DEFAULT|STANDARD|BCRYPT
# guacamole.jdbc.passwordEncoder.characterEncoding=
# guacamole.jdbc.passwordEncoder.encodingAlgorithm=
# guacamole.jdbc.passwordEncoder.secret=
# guacamole.jdbc.passwordEncoder.strength=16

# guacamole.jdbc.principalTransformation.suffix=
guacamole.jdbc.principalTransformation.caseConversion=NONE
# guacamole.jdbc.principalTransformation.prefix=
          " >> cas-overlay-template/etc/cas/config/cas.properties

          json=$(jq -n --arg CAS_REDIRECT_URI "^(https)://.*" --arg CAS_SERVICE_NAME "$CAS_SERVICE_NAME" --arg CAS_SERVICE_ID "$CAS_SERVICE_ID" \
               '{"@class" : "org.apereo.cas.services.RegexRegisteredService",
                  serviceId : $CAS_REDIRECT_URI,
                  name : $CAS_SERVICE_NAME,
                  id : $CAS_SERVICE_ID,
                  description : "Guacamole Remote Access Service",
                  evaluationOrder : 1
                }')
          echo "$json" > "${CAS_SERVICE_NAME}-${CAS_SERVICE_ID}".json
          cp cas-overlay-template/etc/cas/config/cas.properties ${CAS_PROPERTIES_PATH}
          cp "${CAS_SERVICE_NAME}-${CAS_SERVICE_ID}".json ${CAS_HOME}/services/
          cp cas-overlay-template/etc/cas/config/log4j2.xml ${CAS_LOG4J2_PATH} ;} &
s_echo "n" "-Downloading and configuring CAS ${APEREO_CAS_VER}...    "; spinner
        { 
	  echo "Current directory"
	  pwd
          cd ${CAS_INSTALL_DIR}/cas-overlay-template
          ./gradlew build
          cd .. 
          cp ${CAS_INSTALL_DIR}/cas-overlay-template/build/libs/cas.war /etc/cas/ 
	  chown -R ${TOMCAT_USER}:${SERVICE_GROUP} /etc/cas
        } &
s_echo "n" "-Building CAS ${APEREO_CAS_VER}...    "; spinner


}
######  DUO SETUP  ###################################################
duosetup () {
	# Placehold until extension is added
	echo "duosetup"
}

######  RADIUS SETUP  ################################################
radiussetup () {
	# Placehold until extension is added
	echo "radiussetup"
}

######  CAS EXT SETUP  ###################################################
casextsetup () {
s_echo "y" "${Bold}Setup the CAS Extension"

# Append CAS configuration lines to guacamole.properties
{ echo "
## extension priority
extension-priority: *,cas

## CAS properties
cas-authorization-endpoint: ${CAS_AUTHORIZATION_ENDPOINT}
cas-redirect-uri: ${CAS_REDIRECT_URI}
## optional CAS properties
#cas-clearpass-key: ${CAS_CLEARPASS_KEY}
#cas-group-attribute: ${CAS_GROUP_ATTRIBUTE}
#cas-group-format: ${CAS_GROUP_FORMAT}
#cas-group-ldap-base-dn: ${CAS_GROUP_LDAP_BASE_DN}
#cas-group-ldap-attribute: ${CAS_GROUP_LDAP_ATTRIBUTE}" >> /etc/guacamole/${GUAC_CONF}; 
 
trap '' ERR;
set -x;
[ "${CAS_CLEARPASS_KEY}" ] && sed -i -e 's/^#cas-clearpass-key/cas-clearpass-key/' /etc/guacamole/${GUAC_CONF};
[ "${CAS_GROUP_ATTRIBUTE}" ] && sed -i -e 's/^#cas-group-attribute/cas-group-attribute/' /etc/guacamole/${GUAC_CONF};
[ "${CAS_GROUP_FORMAT}" ] && sed -i -e 's/^#cas-group-format/cas-group-format/' /etc/guacamole/${GUAC_CONF};
[ "${CAS_GROUP_LDAP_BASE_DN}" ] && sed -i -e 's/^#cas-group-ldap-base-dn/cas-group-ldap-base-dn/' /etc/guacamole/${GUAC_CONF};
[ "${CAS_GROUP_LDAP_ATTRIBUTE}" ] && sed -i -e 's/^#cas-group-ldap-attribute/cas-group-ldap-attribute/' /etc/guacamole/${GUAC_CONF};
set +x;
trap err_handler ERR;
} &
s_echo "n" "${Reset}-Updating guacamole.properties file for CAS...    "; spinner

if [ $GUAC_SOURCE == "Git" ]; then
   # Copy CAS Extension to Extensions Directory
   { find ./guacamole-client/extensions -name "${GUAC_CAS}.jar" -exec mv -v {} ${LIB_DIR}extensions/ \;; } &
   s_echo "n" "-Moving Guacamole CAS extension to extensions dir...    "; spinner
else # Stable release
   # Download SSO bundle Extension
   { wget "${GUAC_CAS_EXT_URL}" -O ${GUAC_CAS}.tar.gz; } &
   s_echo "n" "-Downloading CAS bundle extension...    "; spinner

   # Decompress CAS bundle Extension
   {
      tar xzvf ${GUAC_CAS}.tar.gz
      rm -f ${GUAC_CAS}.tar.gz
      pwd
      mv -v guacamole-auth-sso-${GUAC_VER}/cas/${GUAC_CAS}.jar ${LIB_DIR}extensions/
   } &
   s_echo "n" "-Decompressing Guacamole CAS Extension...    "; spinner

fi
}

######  OpenID SETUP  ################################################
openidsetup () {
	# Placehold until extension is added
	echo "openidsetup"
}

######  QUICKCONNECT EXTENSION SETUP  ######################################
custsetup () {
# Copy Custom Extension to Extensions Directory
{ mv -v ${CUST_FULL} ${LIB_DIR}extensions/; } &
s_echo "y" "${Bold}Copying Custom Guacamole Extension to Extensions Dir...    "; spinner
}

######  SELINUX SETTINGS  ############################################
selinuxsettings () {
{
	# Set Booleans
	setsebool -P httpd_can_network_connect 1
	setsebool -P httpd_can_network_relay 1
	setsebool -P tomcat_can_network_connect_db 1

	# Guacamole Client Context
	semanage fcontext -a -t tomcat_exec_t "${LIB_DIR}guacamole.war"
	restorecon -v "${LIB_DIR}guacamole.war"

	# Guacamole JDBC Extension Context
	semanage fcontext -a -t tomcat_exec_t "${LIB_DIR}extensions/guacamole-auth-jdbc-mysql-${GUAC_VER}.jar"
	restorecon -v "${LIB_DIR}extensions/guacamole-auth-jdbc-mysql-${GUAC_VER}.jar"

	# MySQL Connector Extension Context
	semanage fcontext -a -t tomcat_exec_t "${LIB_DIR}lib/${MYSQL_CON}.jar"
	restorecon -v "${LIB_DIR}lib/${MYSQL_CON}.jar"

	# Guacamole LDAP Extension Context (If selected)
	if [ $INSTALL_LDAP = true ]; then
		semanage fcontext -a -t tomcat_exec_t "${LIB_DIR}extensions/${GUAC_LDAP}.jar"
		restorecon -v "${LIB_DIR}extensions/${GUAC_LDAP}.jar"
	fi

	# Guacamole TOTP Extension Context (If selected)
	if [ $INSTALL_TOTP = true ]; then
		# Placehold until extension is added
		# echo "totp true"
		semanage fcontext -a -t tomcat_exec_t "${LIB_DIR}extensions/${GUAC_TOTP}.jar"
		restorecon -v "${LIB_DIR}extensions/${GUAC_TOTP}.jar"
	fi

	# Guacamole QUICKCONNECT Extension Context (If selected)
	if [ $INSTALL_QC = true ]; then
		semanage fcontext -a -t tomcat_exec_t "${LIB_DIR}extensions/${GUAC_QC}.jar"
		restorecon -v "${LIB_DIR}extensions/${GUAC_QC}.jar"
	fi

	# Guacamole Duo Extension Context (If selected)
	if [ $INSTALL_DUO = true ]; then
		# Placehold until extension is added
		echo "duo true"
		#semanage fcontext -a -t tomcat_exec_t "${LIB_DIR}extensions/${GUAC_DUO}.jar"
		#restorecon -v "${LIB_DIR}extensions/${GUAC_DUO}.jar"
	fi

	# Guacamole RADIUS Extension Context (If selected)
	if [ $INSTALL_RADIUS = true ]; then
		# Placehold until extension is added
		echo "radius true"
		#semanage fcontext -a -t tomcat_exec_t "${LIB_DIR}extensions/${GUAC_RADIUS}.jar"
		#restorecon -v "${LIB_DIR}extensions/${GUAC_RADIUS}.jar"
	fi

	# Guacamole CAS Extension Context (If selected)
	if [ $INSTALL_CAS = true ]; then
		# Placehold until extension is added
		# echo "cas true"
		semanage fcontext -a -t tomcat_exec_t "${LIB_DIR}extensions/${GUAC_CAS}.jar"
		restorecon -v "${LIB_DIR}extensions/${GUAC_CAS}.jar"
	fi

	# Guacamole OpenID Extension Context (If selected)
	if [ $INSTALL_OPENID = true ]; then
		# Placehold until extension is added
		echo "openid true"
		#semanage fcontext -a -t tomcat_exec_t "${LIB_DIR}extensions/${GUAC_OPENID}.jar"
		#restorecon -v "${LIB_DIR}extensions/${GUAC_OPENID}.jar"
	fi

	# Guacamole Custom Extension Context (If selected)
	if [ $INSTALL_CUST_EXT = true ]; then
		semanage fcontext -a -t tomcat_exec_t "${LIB_DIR}extensions/${CUST_FN}"
		restorecon -v "${LIB_DIR}extensions/${CUST_FN}"
	fi
} &

s_echo "y" "${Bold}Setting SELinux Context...    "; spinner

# Log SEL status
sestatus

firewallsettings
}

######  FIREWALL SETTINGS  ###########################################
firewallsettings () {
s_echo "y" "${Bold}Firewall Configuration"

chk_installed "firewalld"

# Ensure firewalld is enabled and started
{
	if [ $RETVAL -eq 0 ]; then
		systemctl enable firewalld
		systemctl restart firewalld
	fi
} &
s_echo "n" "${Reset}-firewalld is installed and started on the system...    "; spinner

# Backup firewall public zone config
{ test -f /etc/firewalld/zones/public.xml && cp /etc/firewalld/zones/public.xml $fwbkpfile || true; } &
s_echo "n" "-Backing up firewall public zone to: $fwbkpfile    "; spinner

# Open HTTP and HTTPS ports
{
	echo -e "Add new rule...\nfirewall-cmd --permanent --zone=public --add-service=http"
	firewall-cmd --permanent --zone=public --add-service=http
	echo -e "Add new rule...\nfirewall-cmd --permanent --zone=public --add-service=https"
	firewall-cmd --permanent --zone=public --add-service=https
} &
s_echo "n" "-Opening HTTP and HTTPS service ports...    "; spinner

# Open 8080 and 8443 ports. Need to review if this is required or not
{
	echo -e "Add new rule...\nfirewall-cmd --permanent --zone=public --add-port=8080/tcp"
	firewall-cmd --permanent --zone=public --add-port=8080/tcp
	echo -e "Add new rule...\nfirewall-cmd --permanent --zone=public --add-port=8443/tcp"
	firewall-cmd --permanent --zone=public --add-port=8443/tcp
} &
s_echo "n" "-Opening ports 8080 and 8443 on TCP...    "; spinner

#echo -e "Reload firewall...\nfirewall-cmd --reload\n"
{ firewall-cmd --reload; } &
s_echo "n" "-Reloading firewall...    "; spinner

sslcerts
}

######  SSL CERTIFICATE  #############################################
sslcerts () {
s_echo "y" "${Bold}SSL Certificate Configuration"

if [ $SSL_CERT_TYPE != "None" ]; then
	# Lets Encrypt Setup (If selected)
	if [ $SSL_CERT_TYPE = "LetsEncrypt" ]; then
		# Install certbot from repo
		{ yum install -y certbot python2-certbot-nginx; } &
		s_echo "n" "${Reset}-Downloading certboot tool...    "; spinner

		# OCSP
		{
			if [ $OCSP_USE = true ]; then
				certbot certonly --nginx --must-staple -n --agree-tos --rsa-key-size ${LE_KEY_SIZE} -m "${EMAIL_NAME}" -d "${DOMAIN_NAME}","${DOMAIN_NAME}","${DOMAIN_NAME}"
			else # Generate without OCSP --must-staple
				certbot certonly --nginx -n --agree-tos --rsa-key-size ${LE_KEY_SIZE} -m "${EMAIL_NAME}" -d "${DOMAIN_NAME}","${DOMAIN_NAME}","${DOMAIN_NAME}"
			fi
		} &
		s_echo "n" "-Generating a ${SSL_CERT_TYPE} SSL Certificate...    "; spinner

		# Symlink Lets Encrypt certs so renewal does not break Nginx
		{
			ln -vs "/etc/letsencrypt/live/${DOMAIN_NAME}/fullchain.pem" /etc/nginx/guacamole.crt
			ln -vs "/etc/letsencrypt/live/${DOMAIN_NAME}/privkey.pem" /etc/nginx/guacamole.key
			ln -vs "/etc/letsencrypt/live/${DOMAIN_NAME}/chain.pem" /etc/nginx/guacamole.pem
		} &
		s_echo "n" "-Creating symlinks to ${SSL_CERT_TYPE} SSL certificates...    "; spinner

		# Setup automatic cert renewal
		{
			systemctl enable certbot-renew.service
			systemctl enable certbot-renew.timer
			systemctl list-timers --all | grep certbot
		} &
		s_echo "n" "-Setup automatic ${SSL_CERT_TYPE} SSL certificate renewals...    "; spinner

	else # Use a Self-Signed Cert
		{ openssl req -x509 -sha512 -nodes -days 365 -newkey rsa:${SSL_KEY_SIZE} -keyout /etc/nginx/guacamole.key -out /etc/nginx/guacamole.crt -subj "/C=''/ST=''/L=''/O=''/OU=''/CN=''"; } &
		s_echo "n" "${Reset}-Generating ${SSL_CERT_TYPE} SSL Certificate...    "; spinner
	fi

	# Nginx CIS v1.0.0 - 4.1.3 ensure private key permissions are restricted
	{
		ls -l /etc/nginx/guacamole.key
		chmod 400 /etc/nginx/guacamole.key
	} &
	s_echo "n" "${Reset}-Changing permissions on SSL private key...    "; spinner

	{
		# Uncomment listen lines from Nginx guacamole_ssl.conf (fixes issue introduced by Nginx 1.16.0)
		sed -i 's/#\(listen.*443.*\)/\1/' /etc/nginx/conf.d/guacamole_ssl.conf
		# Uncomment cert lines from Nginx guacamole_ssl.conf
		sed -i 's/#\(.*ssl_.*certificate.*\)/\1/' /etc/nginx/conf.d/guacamole_ssl.conf
	} &
	s_echo "n" "${Reset}-Enabling SSL certificate in guacamole_ssl.conf...    "; spinner

	HTTPS_ENABLED=true
else # Cert is set to None
	s_echo "n" "${Reset}-No SSL Cert selected..."

	# Will not force/use HTTPS without a cert, comment out redirect
	{ sed -i '/\(return 301 https\)/s/^/#/' /etc/nginx/conf.d/guacamole.conf; } &
	s_echo "n" "${Reset}-Update guacamole.conf to allow HTTP connections...    "; spinner

	HTTPS_ENABLED=false
fi

make_misc_symlinks
}

#####  MISCELLANEOUS SYMLINKS #######################################
make_misc_symlinks () {
s_echo "y" "${Bold}Symlinks"

{
  chown -R ${TOMCAT_USER}:${SERVICE_GROUP} /etc/guacamole
  ln -sf -T /usr/share/tomcat /opt/tomcat
  ln -sf -T /etc/guacamole /opt/guacamole
  mkdir -p /opt/etc
  ln -sf -T /etc/guacamole /opt/etc/guacamole
  ln -sf -T /etc/cas /opt/etc/cas
  ln -sf -T /etc/cas "${CAS_INSTALL_PATH}"
  ln -sf -T /etc/cas/cas.war /var/lib/tomcat/webapps/cas.war
  ln -sf -T /etc/tomcat/server.xml ${TOMCAT_INSTALL_DIR}/tomcat/conf/server.xml 
  chown -h ${TOMCAT_USER}:${SERVICE_GROUP} /etc/tomcat/server.xml
  ln -sf -T ${LIB_DIR}extensions /etc/guacamole/extensions
  ln -sf -T ${LIB_DIR}lib /etc/guacamole/lib
} &
s_echo "n" "${Reset}-Making symlinks in /opt...    "; spinner

showmessages
}

######  COMPLETION MESSAGES  #########################################
showmessages () {
s_echo "y" "${Bold}Services"

# Restart all services and log status
{
	systemctl restart tomcat
	systemctl status tomcat
	systemctl restart guacd
	systemctl status guacd
	systemctl restart mariadb
	systemctl status mariadb
	systemctl restart nginx
	systemctl status nginx

	# Verify that the guacd user is running guacd
	ps aux | grep ${GUACD_USER}
	ps -U ${GUACD_USER}
} &
s_echo "n" "${Reset}-Restarting all services...    "; spinner

# Completion messages
s_echo "y" "${Bold}${Green}##### Installation Complete! #####${Reset}"

s_echo "y" "${Bold}Log Files"
s_echo "n" "${Reset}-Log file: ${logfile}"
s_echo "n" "-firewall backup file: ${fwbkpfile}"

# Determine Guac server URL for web GUI
if [ ${DOMAIN_NAME} = "localhost" ]; then
	GUAC_URL=${GUAC_LAN_IP}${GUAC_URIPATH}
else # Not localhost
	GUAC_URL=${DOMAIN_NAME}${GUAC_URIPATH}
fi

# Determine if HTTPS is used or not
if [ ${HTTPS_ENABLED} = true ]; then
	HTTPS_MSG="${Bold}https://${GUAC_URL}${Reset}"
else # HTTPS not used
	HTTPS_MSG="${Reset}. Without a cert, HTTPS is not forced/available."
fi

# Manage Guac
s_echo "y" "${Bold}To manage Guacamole"
s_echo "n" "${Reset}-go to: ${HTTPS_MSG}"
s_echo "n" "-The default username and password are: ${Red}guacadmin"

# Recommendations
s_echo "y" "Important Recommendations${Reset}"

if [ $INSTALL_LDAP = false ]; then
	s_echo "n" "-It is highly recommended to create an admin account in Guacamole and delete/disable the default asap!"
else
	s_echo "n" "-You should assign at least one AD/LDAP user to have full admin, see the directions on how-to at:"
	s_echo "n" "${Green} https://github.com/Zer0CoolX/guacamole-install-rhel-7/wiki/LDAP-or-LDAPS-Authentication#important-manual-steps${Reset}"
	s_echo "n" "-Afterwards, it is highly recommended to delete/disable the default admin account and/or create a uniquely named local admin account asap!"

	if [ $SECURE_LDAP = true ]; then
		s_echo "n" "-Its highly recommended to remove the LDAPS certificate file from: ${LDAPS_CERT_FULL}"
	fi
fi

s_echo "y" "${Green}While not technically required, you should consider a reboot after verifying installation${Reset}"
s_echo "y" "${Bold}Contact ${Reset}${ADM_POC}${Bold} with any questions or concerns regarding this script\n"

# Log cleanup to remove escape sequences caused by tput for formatting text
sed -i -e 's/\x1b\[[0-9;]*m\|\x1b[(]B\x1b\[m//g' -e 's/\r\n/\n/g' -e 's/\r/\n/g' ${logfile}

# Add domain to 127.0.0.1 to prevent CAS from going external
sed -i "1 s/$/\ ${DOMAIN_NAME}/" /etc/hosts
tput sgr0 >&3
}

######  INSTALLATION EXECUTION  ######################################
# Runs the install if the option was selected from the summary menu
if [ ${RUN_INSTALL} = true ]; then
	tput sgr0 >&3
	clear >&3
	reposinstall
	if [ $DEL_TMP_VAR = true ]; then
		rm "$VAR_FILE"
	fi
	exit 0
fi
