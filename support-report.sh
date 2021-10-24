#!/bin/bash
#
# AppDynamics Cisco Technical Support report generator for AppD on-prem host
#
# https://serverfault.com/questions/103501/how-can-i-fully-log-all-bash-scripts-actions
APPDSYSTEMLOGFILE=$(mktemp -q /tmp/support_report_out.log.XXXXXX)
APPDSYSTEMXLOGFILE=$(mktemp -q /tmp/support_report_xtrace.log.XXXXXX)
exec 3>&1 4>&2
trap 'exec 2>&4 1>&3' 0 1 2 3 RETURN
exec 1>${APPDSYSTEMLOGFILE} 2>&1
exec 6>${APPDSYSTEMXLOGFILE}
BASH_XTRACEFD=6
set -x
TTY_STATE=$(stty -g)

VERSION=0.14
DAYS=3
SYSLOGDAYS=3
ZIPREPORT=1
CGI=1
DEBUG=0
GETSYSTEM=1
GETVM=1
GETSTORAGE=1
GETOPENFILES=0
GETHARDWARE=1
GETMEMORY=1
GETSYSTEMD=1
GETSYSLOGS=1
GETNETCONF=1
GETTIMECONFIG=1
GETINIINFO=1
GETAPPD=1
GETNUMA=1
GETCONTROLLERLOGS=1
GETCONTROLLERMYSQLLOGS=1
GETCONTROLLERCONFIGS=1
GETCONTROLLERINFO=1
GETCONTROLLERREPORT=1
GETHAINFO=1
GETECLOGS=1
GETECMYSQLLOGS=1
GETECCONFIGS=1
GETLOAD=0
GETUSERENV=1
GETCERTSINFO=1
GETMYSQLQUERIES=1
GETPROCESSES=1
GETTOP=1
GETFILELIST=1
GETSESTATUS=1
CLEANUP_WKDIR=1
ENCRYPT=0

GETESLOGS=1
GETESCONFIGS=1
GETESQUERIES=1

GETEUMLOGS=1
GETEUMCONFIGS=1
GETEUMMYSQLLOGS=1

# Flags indicating the component is found on a host
CONTROLLER_INSTALLED=0
EC_INSTALLED=0
ES_INSTALLED=0
EUM_INSTALLED=0

# Collecting mode flags
SEARCH_CONTROLLER=0
SEARCH_EC=0
SEARCH_EUM=0
SEARCH_ES=0

# Included into output filename to identify components requested with -CEUS options
SEARCHED_COMPONENTS=()

ROOT_USER="root"
ROOT_GROUP="root"
MYSQL_PORT="3388"
SDATE=$(date +%F_%T | tr ":" '-')
INPROGRESS_LOCK="/tmp/support_report.LCK"
INPROGRESS_LOCKFD=100
REPORT_PATH="${PWD}/support-report" #defaults to $PWD/support-report
: ${CONTROLLER_MYSQL_PASSWORD:=""}
: ${CONTROLLER_ROOT_PASSWORD:=""}
: ${EUM_MYSQL_PASSWORD:=""}
HAVE_ACCESS_TO_CONTROLLER_DB=0
HAVE_ACCESS_TO_CONTROLLER_ROOT=0
HAVE_ACCESS_TO_EUM_DB=0
MYSQL_QUERY_TIMEOUT=50000

MAX_FILE_SIZE=15728640 # 15 MB

function lock()	{ 
	eval "exec $INPROGRESS_LOCKFD>\"$INPROGRESS_LOCK\""
	flock -xn $INPROGRESS_LOCKFD
}

function unlock() {
	flock -u $INPROGRESS_LOCKFD
	rm $INPROGRESS_LOCK
}

# Joins elements with a single char separator
# $1 - seperator
# $2..$n - elements to join
function join_by()
{
    local IFS="$1"
    shift
    echo "$*"
}

function find_wkdir()
{
    local _findmounts=$(mktemp -q /tmp/support_report.findtemp_mounts.XXXXXX)
    local _finddf=$(mktemp -q /tmp/support_report.findtemp_df.XXXXXX)
    # Find out what non-pseudo filesystems are supported by kernel
    for i in $(grep -v nodev /proc/filesystems); do
        # Filter only writable mounts
        mount | grep "$i" | grep rw >> $_findmounts
    done
    # Gather df information from writable mounts
    for i in $(awk '{print $3}' $_findmounts); do
        df -P | grep -e "$i$" >> $_finddf
    done
    # Fallback default path if we can't write anywhere else
    local _wkdir_path=${HOME}
    # Going thru mounts list sorted by available space
    for i in $(sort -k 4 -rn $_finddf | awk '{print $6}'); do
        # we avoid writing to the root directory
        if [[ $i == "/" ]] || [[ $i == /boot* ]]; then
            continue
        fi
        # Write test
        local _write_test=$(mktemp -q $i/support_report_write_test.XXXXXX)
        touch $_write_test 2> /dev/null
        rm $_write_test 2> /dev/null
        if [ $? == 0 ]; then
            _wkdir_path=${i}
            break
        fi
    done
    rm $_findmounts
    rm $_finddf
    local _searched_components=$(join_by "-" "${SEARCHED_COMPONENTS[@]}")
    WKDIR="${_wkdir_path}/support-report_${_searched_components}_$(hostname)_${SDATE}"
    REPORTFILE="support-report_${_searched_components}_$(hostname)_${SDATE}.tar.gz"
}

# trap ctrl-c and clean before exit
function clean_after_yourself {
    if [ $CLEANUP_WKDIR -eq 1 ]; then
        rm -fr "${WKDIR}"
    fi

    # we need to delete report temp and log files as well
    [ $DEBUG -eq 0 ] && rm $APPDSYSTEMLOGFILE $APPDSYSTEMXLOGFILE

    # restore initial TTY configuration
    stty $TTY_STATE
}

trap ctrl_c INT
function ctrl_c() {
    clean_after_yourself
    unlock 
    exit
}

# simplified substitute for curl or wget, as these tools are not always present on server
# tested against locally running controller, with purpose to check status and simple API calls
# uses bash redirection hack
# example usage:   http_query  http://127.0.0.1/controller/rest/serverstatus

function http_query()
{
    local _timeout=2

    local _url_regex="http:\/\/([-.a-zA-Z0-9]+):?([0-9]{1,4})?(.*)"
    local _host=$(echo "$1" | sed -E "s/$_url_regex/\1/" )
    local _port=$(echo "$1" | sed -E "s/$_url_regex/\2/" )
    : "${_port:=80}"    # if empty, replace with default 80
    local _resource=$(echo "$1" | sed -E "s/$_url_regex/\3/" )
    : "${_resource:=/}" # if empty, replace with default /

    # Testing connection
    timeout $_timeout bash -c "</dev/tcp/$_host/$_port" &> /dev/null
    [ $? -ne 0 ] && return 1

    # Make HTTP connection
    exec 5<>/dev/tcp/$_host/$_port
    echo -e "GET $_resource HTTP/1.1\r\nHost: $_host\r\nConnection: close\r\n\r\n" >&5
    timeout $_timeout bash -c "cat <&5"
}

# $1 - url
# $2 - outfile
function http_get_file()
{
    local _conn_timeout=2
    local _timeout=10

    local _url_regex="http:\/\/([-.a-zA-Z0-9]+):?([0-9]{1,4})?(.*)"
    local _host=$(echo "$1" | sed -E "s/$_url_regex/\1/" )
    local _port=$(echo "$1" | sed -E "s/$_url_regex/\2/" )
    : "${_port:=80}"    # if empty, replace with default 80
    local _resource=$(echo "$1" | sed -E "s/$_url_regex/\3/" )
    : "${_resource:=/}" # if empty, replace with default /

    # Testing connection
    timeout $_conn_timeout bash -c "</dev/tcp/$_host/$_port" &> /dev/null
    [ $? -ne 0 ] && return 1

    # Make HTTP connection
    exec 5<>/dev/tcp/$_host/$_port
    {
        echo -en "GET $_resource HTTP/1.1\r\n"
        echo -en "Host: $_host\r\n"
        [ -n "$AUTH" ] && echo -en "Authorization: Basic $AUTH\r\n"
        echo -en "User-Agent: support-report/$VERSION\r\n"
        echo -en "Connection: close\r\n"
        echo -en "Accept: */*\r\n\r\n"
    } >&5

    timeout $_timeout bash -c "cat <&5 > $2"
}
# $1 - src file path
# $2 - out file path
function file_unchunk()
{
    if [ -f "$1" ]; then
        # removes chunks separators \r\n[bytes]\r\n
        sed '/\r$/{N;N; s/\r\n.\+\r\n// }' $1 > $2
        rm $1
    fi
}

# compare two versions in string form, dot separated, up to three numeric parts
function compare_versions() {
    version1=$1  condition=$2 version2=$3
    local IFS=.
    v1_array=($version1) v2_array=($version2)
    v1=$((v1_array[0] * 1000 + v1_array[1] * 100 + v1_array[2]))
    v2=$((v2_array[0] * 1000 + v2_array[1] * 100 + v2_array[2]))
    diff=$((v2 - v1))
    [[ $condition = '='  ]] && ((diff == 0)) && return 0
    [[ $condition = '!=' ]] && ((diff != 0)) && return 0
    [[ $condition = '<'  ]] && ((diff >  0)) && return 0
    [[ $condition = '<=' ]] && ((diff >= 0)) && return 0
    [[ $condition = '>'  ]] && ((diff <  0)) && return 0
    [[ $condition = '>=' ]] && ((diff <= 0)) && return 0
    return 1
}


# we cannot assume linux flavor, and path for tools are sometimes different or tools are not present at all on customer's server
function assign_command()
{
	_cmd=$(which $1 2>/dev/null)
#	_cmd=$(which $1)
	_cmd=${_cmd:=warning "missing command: $1"}
	echo ${_cmd}
}

function prepare_paths()
{
LSB_RELEASE=$(assign_command lsb_release)
LSPCI=$(assign_command lspci)
LSCPU=$(assign_command lscpu)
IPTABLES=$(assign_command iptables)
VMWARE_CHECKVM=$(assign_command vmware-checkvm)
VMWARE_TOOLBOX_CMD=$(assign_command vmware-toolbox-cmd)
VBOX_CONTROL_CMD=$(assign_command VBoxControl)
XENSTORE_LS_CMD=$(assign_command xenstore-ls)
CP_CMD="cp -af"
SS=$(assign_command ss)
IP=$(assign_command ip)
LSMOD=$(assign_command lsmod)
LSOF=$(assign_command lsof)
LSBLK=$(assign_command lsblk)
NTPQ=$(assign_command ntpq)
CHRONYC=$(assign_command chronyc)
IOSTAT=$(assign_command iostat)
VMSTAT=$(assign_command vmstat)
MPSTAT=$(assign_command mpstat)
TOP=$(assign_command top)
SAR=$(assign_command sar)
DMIDECODE=$(assign_command dmidecode)
OPENSSL=$(assign_command openssl)
BASE64=$(assign_command base64)
SYSTEMCTL=$(assign_command systemctl)
TIMEDATECTL=$(assign_command timedatectl)
JOURNALCTL=$(assign_command journalctl)
SYS_JAVA=$(assign_command java)

# collection files
SYSTEM_CONFIGFILE=$WKDIR/11-system-config.txt
SYSTEM_PACKAGESFILE=$WKDIR/12-installed-software.txt
VM_CONFIGFILE=$WKDIR/13-vm-system.txt
STORAGE_CONFIGFILE=$WKDIR/14-storage.txt
OPENFILES=$WKDIR/15-openfiles.txt
HWCONF=$WKDIR/16-hw-config.txt
NETCONF=$WKDIR/17-net-config.txt
SYSLOGS=$WKDIR/system-logs/
SYSCTL=$WKDIR/18-sysctl.txt
SLABINFO=$WKDIR/19-slabinfo.txt
SYSTREE=$WKDIR/20-systree.txt
CRONFILES=$WKDIR/21-cronfiles.txt
HOSTSFILE=$WKDIR/22-hosts
RESOLVFILE=$WKDIR/23-resolv.conf
ROOTCRON=$WKDIR/24-root-crontab.txt
TIMECONFIG=$WKDIR/25-time-config.txt
INITSCRIPTS=$WKDIR/26-initscripts.txt
PACKAGESFILE=$WKDIR/27-packages.txt
NUMAFILE=$WKDIR/28-numa.txt
PERFSTATS=$WKDIR/29-perfstats
PROCESSES=$WKDIR/30-processes.txt
TOPREPORT=$WKDIR/31-top.txt
MEMINFO=$WKDIR/32-meminfo.txt
FILELIST=$WKDIR/33-filelist.csv
SELINUX_INFO=$WKDIR/34-selinux-info.txt
SYSTEMD_INFO=$WKDIR/35-systemd-info.txt
HA_INFO=$WKDIR/36-ha-info.txt
APPD_INSTALL_USER_ENV=$WKDIR/37-install-user-env.txt

# product specific paths and variables
APPD_HOME="/opt/appd" #just default
APPD_CONTROLLER_HOME=""
APPD_CONTROLLER_JAVA_HOME=""
APPD_CONTROLLER_GLASSFISH_PID=
APPD_CONTROLLER_MYSQL_PID=
APPD_CONTROLLER_INSTALL_USER=""
APPD_CONTROLLER_INSTALL_GROUP=""
PREDICTED_APPD_DIRS=""
ORCHA_NOT_FOUND=0

APPD_CONTROLLER=$WKDIR/controller
APPLOGS=$APPD_CONTROLLER/controller-logs
CONTROLLERLOGS=$APPD_CONTROLLER/controller-logs/
CONTROLLERREPORT=$APPD_CONTROLLER/controller-report/
CONTROLLERMYSQLLOGS=$APPD_CONTROLLER/controller-mysql-logs/
CONTROLLERCONFIGS=$APPD_CONTROLLER/controller-configs/
APPD_CONTROLLER_JAVAINFO=$APPD_CONTROLLER/301-controller-javainfo.txt
APPD_CONTROLLER_MYSQLINFO=$APPD_CONTROLLER/302-controller-mysqlinfo.txt
APPD_CERTS=$APPD_CONTROLLER/303-controller-certs.txt
APPD_CONTROLLER_QUERIES=$APPD_CONTROLLER/304-controller-queries.txt
APPD_CONTROLLER_INFO=$APPD_CONTROLLER/305-controller-info.txt

APPD_EC=$WKDIR/ec
ECLOGS=$APPD_EC/EC-logs/
ECMYSQLLOGS=$APPD_EC/EC-mysql-logs/
ECCONFIGS=$APPD_EC/EC-configs/
ADDITIONAL_CONFIG_FILES=""

# --------- EVENTS SERVICE SECTION ---------------
APPD_ES=$WKDIR/events-service
APPD_ES_JAVAINFO=$APPD_ES/101-events-service-javainfo.txt
APPD_ES_CERTS=$APPD_ES/102-events-service-certs.txt
APPD_ELASTICSEARCH_QUERIES=$APPD_ES/103-elasticsearch-queries.txt
APPD_ES_INFO=$APPD_ES/104-events-service-info.txt

# product specific paths and variables
APPD_ES_HOME=""
APPD_ES_JAVA_HOME=""
APPD_ES_INSTALL_USER=""
APPD_ES_INSTALL_GROUP=""
ESLOGS=$APPD_ES/es-logs/
ESCONFIGS=$APPD_ES/es-configs/

# ------------------- EUM SECTION ----------------------------
APPD_EUM=$WKDIR/eum
APPD_EUM_JAVAINFO=$APPD_EUM/201-eum-javainfo.txt
APPD_EUM_CERTS=$APPD_EUM/202-eum-certs.txt
APPD_EUM_QUERIES=$APPD_EUM/203-eum-queries.txt
APPD_EUM_INFO=$APPD_EUM/204-eum-info.txt
APPD_EUM_MYSQLINFO=$APPD_EUM/205-eum-mysqlinfo.txt
EUMMYSQLLOGS=$APPD_EUM/eum-mysql-logs/
EUMLOGS=$APPD_EUM/eum-logs/
EUMCONFIGS=$APPD_EUM/eum-configs/
}

# product specific paths and variables
APPD_EUM_HOME=""
APPD_EUM_JAVA_HOME=""
APPD_EUM_INSTALL_USER=""
APPD_EUM_INSTALL_GROUP=""


function log_variables()
{
  # clear password variable, we dont want to log it
  CONTROLLER_MYSQL_PASSWORD=""
  CONTROLLER_ROOT_PASSWORD=""
  EUM_MYSQL_PASSWORD=""
  set -o posix
  echo  "VARIABLES: " >> $APPDSYSTEMLOGFILE
  set >> $APPDSYSTEMLOGFILE
}

function message()
{
  echo "$@" >&3
  if [ $CGI -eq 1 ] && [ -f $APPDSYSTEMLOGFILE ]; then
    echo -ne "\n[REPORT] $(date) :: $@ \n" >> $APPDSYSTEMLOGFILE
  fi
}

function log_message()
{
  if [ $CGI -eq 1 ] && [ -f $APPDSYSTEMLOGFILE ]; then
    echo -ne "\n[REPORT] $(date) :: $@ \n" >> $APPDSYSTEMLOGFILE
  fi
}

function message_format()
# print message, with ANSI formatting given as 1st argument
{
  FORMAT=$1
  shift
  printf $FORMAT "$@" >&3
  if [ $CGI -eq 1 ] && [ -f $APPDSYSTEMLOGFILE ]; then
    echo -ne "\n[REPORT] $(date) :: $@ \n" >> $APPDSYSTEMLOGFILE 
  fi
}

function warning()
{
  message "WARNING: $@" >&3
  if [ $CGI -eq 1 ] && [ -f $APPDSYSTEMLOGFILE ]; then
    echo -ne "\n[REPORT] $(date) :: WARNING: $@ \n" >> $APPDSYSTEMLOGFILE 
  fi
  return 2
}

function log_warning()
{
  if [ $CGI -eq 1 ] && [ -f $APPDSYSTEMLOGFILE ]; then
    echo -ne "\n[REPORT] $(date) :: WARNING: $@ \n" >> $APPDSYSTEMLOGFILE 
  fi
  return 2
}

function err()
{
        message "ERROR: $1" >&3
        clean_after_yourself
        unlock
        exit 1
}

function version()
{
   echo "$(basename $0) v$VERSION" >&3
   clean_after_yourself
   unlock
   exit 2
}
	
function reportheader()
{
        message "Generating report..."
        echo -e "$(basename $0) ver. $VERSION" >> $SYSTEM_CONFIGFILE
        echo -e "Host: $(hostname -f)" >> $SYSTEM_CONFIGFILE
        echo -e "Generated on: $(date +%c)" >> $SYSTEM_CONFIGFILE
        echo -e "Generated by: $(whoami)" >> $SYSTEM_CONFIGFILE
        echo -e "Temporary WKDIR: $WKDIR\n" >> $SYSTEM_CONFIGFILE
}

function infoheader()
{
    echo -en "\n=================================\n$1\n---------------------------------\n"
}

function infosubheader() {
	echo -en "\n---------------------------------\n$1\n---------------------------------\n"
}

function usage()
{
    FORMAT="%5s\t%-30s\n"
    message "Usage: $(basename $0) [ -CEUScpHlazeoxv ] [ -d days of logs ] [ -o dir ]"
        message_format $FORMAT "-C" "Collect information about Controller"
        message_format $FORMAT "-E" "Collect information about Enterprise Console"
        message_format $FORMAT "-U" "Collect information about EUM server"
        message_format $FORMAT "-S" "Collect information about Events Service"
        message_format $FORMAT "-c" "Disable generating system configuration"
        message_format $FORMAT "-p" "Enable measuring system load/performance. It will be 720 of 5s samples. 1h in total."
        message_format $FORMAT "-H" "Disable generating hardware report"
        message_format $FORMAT "-l" "Disable gathering system logs"
        message_format $FORMAT "-a" "Disable gathering AppD logs"
        message_format $FORMAT "-d" "Number of days back of logs to retrieve (default is $DAYS days)"
        message_format $FORMAT "-z" "Do not zip report and leave it in /tmp"
        message_format $FORMAT "-e" "Encrypt output report archive with password"
        message_format $FORMAT "-o" "Set the support-report output path"
        message_format $FORMAT "-x" "Keep the support-report logs in /tmp for debugging"
        message_format $FORMAT "-v" "Version"
        clean_after_yourself
        unlock
        exit 2
}

# function to get a folder path by a field name in the db.cnf file. 
# 
# Accepts parameters:
# $1 - component that uses the function (Controller, EUM)
# $2 - field name (what is searched in the db.cnf)
# 
# the function throws warning message in case the path to db.cnf is not valid or if a field name in the db.cnf was not found
# 
function find_entry_in_mysql_dbconf()
{
    local _db_conf
    if [ "$1" == 'controller' ]; then
        _db_conf="${APPD_CONTROLLER_MYSQL_HOME}/db.cnf"
    elif [ "$1" == 'eum' ]; then
        _db_conf="${APPD_EUM_MYSQL_HOME}/db.cnf"
    elif [ "$1" == 'ec' ]; then
        _db_conf="${APPD_EC_MYSQL_HOME}/db.cnf"
    fi
    local _value_in_db_cnf
    local _field_name=$2
    if [ -f $_db_conf ]; then
        _value_in_db_cnf=$(awk -F= '$1 ~ /^\s*'"$_field_name"'/ {print $2}' ${_db_conf})
        echo $_value_in_db_cnf
    else
        log_warning "Could not find value of '"$2"' in db.cnf"
    fi
}

# testing if service is running
# $1 - service name
#
function is_service_running()
{
    local _return=1
    case "$INIT_SYSTEM" in
        systemd)
            ${SYSTEMCTL} is-active --quiet $1
            _return=$?
            ;;
        docker)
            ;;
        *)
            service $1 status
            _return=$?
            ;;
    esac
    return $_return
}

function zipreport()
{
    local _upper_dir=$(dirname $WKDIR)
    local _artifact_dir=$(basename $WKDIR)
    local _tar_archive=${REPORT_PATH}/${REPORTFILE}
    # zip -q9r $REPORT_PATH/$REPORTFILE $(basename $WKDIR)
    # zip could be preferable, easier for CU to review archive, but this tool is not always available.
    cp $APPDSYSTEMLOGFILE $WKDIR/support_report_out.log
    cp $APPDSYSTEMXLOGFILE $WKDIR/support_report_xtrace.log
    # tar -C <dir> changes the directory before adding files
    tar -C $_upper_dir -cvzf $_tar_archive $_artifact_dir

    chown $REPORT_USER:$REPORT_GROUP ${_tar_archive}

    if [ -f $_tar_archive ]; then
        echo $REPORTFILE
    else
        err "Report $REPORTFILE  could not be created"
    fi
}

function encryptreport()
{
    #TODO: test this function
	message "Encrypting output file"
        $OPENSSL enc -e -aes-256-cbc -in ${REPORT_PATH}/${REPORTFILE} -out ${REPORT_PATH}/${REPORTFILE}.enc
        if [ $? -eq 1 ]; then
        	err "Report $REPORTFILE could not be encrypted, giving up"
        	exit 1
        else
        	rm -f ${REPORT_PATH}/${REPORTFILE}
        	return 0	
        fi
}

# traverse / and return a list of top dirs containing '*orcha*' inside
function find_predicted_dirs()
{
    if [[ -z "$PREDICTED_APPD_DIRS" && $ORCHA_NOT_FOUND -eq 0 ]]; then
        PREDICTED_APPD_DIRS=$(find / -iname '*orcha*' 2>/dev/null | awk -F/ '{print FS $2}' | sort | uniq | tr '\n' ' ')
        [[ -z "$PREDICTED_APPD_DIRS" ]] && ORCHA_NOT_FOUND=1
    fi
}

function getpackages()
{
        message "Building package list"
        echo linux flavour - $LINUX_FLAVOUR
        [[ ${LINUX_FLAVOUR} = "redhat" ]] && rpm -qa --queryformat "%{NAME} %{VERSION}\n" | sort  >> $PACKAGESFILE
        [[ ${LINUX_FLAVOUR} = "debian" ]] && dpkg-query -W -f='${Package} ${Version}\n' | sort  >> $PACKAGESFILE
        echo "done!"
}

function getlinuxflavour()
{
        _out=$(cat /etc/[A-Za-z]*[_-][rv]e[lr]* | uniq -u)
        [[ $(echo ${_out} | grep -i -E -e '(debian|ubuntu)' | wc -l ) -ge 1 ]] && LINUX_FLAVOUR=debian
        [[ $(echo ${_out} | grep -i -E -e '(rhel|redhat)'| wc -l ) -ge 1 ]] && LINUX_FLAVOUR=redhat
}

function getinitsystem()
{
    if [ -x "$SYSTEMCTL" ]; then
        INIT_SYSTEM="systemd"
    elif /sbin/init --version 2> /dev/null | grep -q -i 'upstart'; then
        INIT_SYSTEM="upstart"
    elif [ -f /.dockerenv ]; then
        INIT_SYSTEM="docker"
    else
        INIT_SYSTEM="sysv"
    fi
    echo $INIT_SYSTEM
}

function getsystem()
{
    message "Building system configuration"
    echo "uptime: $(uptime)" >> $SYSTEM_CONFIGFILE
    infoheader "Operating System" >> $SYSTEM_CONFIGFILE
    uname -a >> $SYSTEM_CONFIGFILE

    [[ -f /etc/redhat-release ]] && $( head -1 /etc/redhat-release >> $SYSTEM_CONFIGFILE )
    [[ -f /etc/debian_version ]] && $( head -1 /etc/debian_version >> $SYSTEM_CONFIGFILE )

    cat /etc/*-release | uniq -u >> $SYSTEM_CONFIGFILE

    if [ -x "$LSB_RELEASE" ]; then
        $LSB_RELEASE -a >> $SYSTEM_CONFIGFILE
    fi

    infoheader "Init System" >> $SYSTEM_CONFIGFILE
    getinitsystem >> $SYSTEM_CONFIGFILE

    infoheader "Loaded Modules" >> $SYSTEM_CONFIGFILE
    $LSMOD >> $SYSTEM_CONFIGFILE

    if [ -f /etc/modules.conf ]; then
        cp -a /etc/modules.conf $WKDIR
    elif [ -f /etc/modprobe.conf ]; then
        cp -a /etc/modprobe.conf* $WKDIR
    fi

    infoheader "Last logins" >> $SYSTEM_CONFIGFILE
    last -20 >> $SYSTEM_CONFIGFILE

    sysctl -A 2>/dev/null > $SYSCTL

    [ $ROOT_MODE -eq 1 ] && cat /proc/slabinfo > $SLABINFO

    [ -d /sys ] && ls -laR /sys 2>/dev/null > $SYSTREE

    # Get list of cron jobs
    ls -lr /etc/cron* > $CRONFILES

    [ $ROOT_MODE -eq 1 ] && [ -f /var/spool/cron/tabs/root ] && crontab -l > $ROOTCRON

    $CP_CMD /etc/hosts $HOSTSFILE
    # resolv.conf is often symlink
    cp /etc/resolv.conf  $RESOLVFILE
    ADDITIONAL_CONFIG_FILE_LIST=$(echo $ADDITIONAL_CONFIG_FILES | tr ',' ' ');
    for CONFIG_FILE in $ADDITIONAL_CONFIG_FILE_LIST; do
        [ -f $CONFIG_FILE ] && cp -a $CONFIG_FILE $WKDIR ;
    done

    getpackages
}


function gethypervisor()
{
    message "Checking hypervisor"

    HV_INFO=""

    if grep -q "^flags.*hypervisor" /proc/cpuinfo ; then
        echo "Machine running under VM hypervisor." >> $VM_CONFIGFILE
    else
        echo "Seems not running under VM hypervisor." >> $VM_CONFIGFILE
    fi

    local _sys_vendor_file=/sys/class/dmi/id/sys_vendor
    local _sys_prod_file=/sys/class/dmi/id/product_name

    if [ -r $_sys_prod_file -o -r $_sys_vendor_file ]; then
        local _sys_vendor_info=$(<$_sys_vendor_file)
        local _sys_prod_info=$(<$_sys_prod_file)
    else
        local _sys_vendor_info=$(dmesg | grep -i 'Hypervisor' -m 1)
        local _sys_prod_info=$(dmesg | grep -i 'DMI:' -m 1)
    fi

    case "$_sys_prod_info $_sys_vendor_info" in
        # Amazon EC2 uses KVM/XEN we want this pattern first
        *[aA][mM][aA][zZ][oO][nN]*)
                HV_INFO="EC2"
                ;;
        # similarly Vbox utilizes KVM on some platform
        *[vV][iI][rR][tT][uU][aA][lL][bB][oO][xX]*)
                HV_INFO="VirtualBox"
                ;;
        *[xX][eE][nN]*)
                HV_INFO="Xen"
                ;;
        *[kK][vV][mM]*)
                HV_INFO="KVM"
                ;;
        *[qQ][eE][mM][uU]*)
                HV_INFO="QEMU"
                ;;
        *[vV][mM][wW][aA][rR][eE]*)
                HV_INFO="VMware"
                ;;
        *[mM][iI][cC][rR][oO][sS][oO][fF][tT]* )
                HV_INFO="Hyper-V"
                ;;
        *)
                HV_INFO="unknown";
                ;;
    esac

    echo  -e "\nHypervisor Vendor: $HV_INFO" >> $VM_CONFIGFILE

    if  [ "$HV_INFO" = "VMware" ]; then
        getvmware
    fi

    if [ "$HV_INFO" = "EC2" -o "$HV_INFO" = "Xen"  ]; then
        getec2
    fi

    if [ "$HV_INFO" = "VirtualBox" -a -x "$VBOX_CONTROL_CMD" ]; then
        getvbox
    fi

    if [ "$HV_INFO" = "Xen" -a -x "$XENSTORE_LS_CMD" ]; then
        getxen
    fi

}

function getvmware()
{
    message "Getting VMware guest info"
    [ -x "$VMWARE_CHECKVM" ] && $VMWARE_CHECKVM -h >> $VM_CONFIGFILE

    if [ -x "$VMWARE_TOOLBOX_CMD" ]; then
        infoheader "VMware details" >> $VM_CONFIGFILE
        { echo -n "Host time: "; $VMWARE_TOOLBOX_CMD stat hosttime;
            echo -n "This machine time: "; date;
            echo -n "Host time-sync status: "; $VMWARE_TOOLBOX_CMD timesync status;
            echo -n "CPU speed: "; $VMWARE_TOOLBOX_CMD stat speed;
            echo -n "CPU res: "; $VMWARE_TOOLBOX_CMD stat cpures;
            echo -n "CPU limit: "; $VMWARE_TOOLBOX_CMD stat cpulimit;
            echo -n "MEM baloon: "; $VMWARE_TOOLBOX_CMD stat balloon;
            echo -n "MEM swap: "; $VMWARE_TOOLBOX_CMD stat swap;
            echo -n "MEM res: "; $VMWARE_TOOLBOX_CMD stat memres;
            echo -n "MEM limit: "; $VMWARE_TOOLBOX_CMD stat memlimit;
        } >> $VM_CONFIGFILE

        infoheader "All available stats:" >> $VM_CONFIGFILE
        while read item; do
            echo "$item statistics:" >> $VM_CONFIGFILE
            $VMWARE_TOOLBOX_CMD stat raw text $item >> $VM_CONFIGFILE
        done < <($VMWARE_TOOLBOX_CMD stat raw)
    fi
}

function getec2()
{
    local _http_out=$(http_query "http://169.254.169.254/latest/dynamic/instance-identity/document" | sed '/^{/,$!d')

    if [ ! -z "$_http_out" ]; then
        message "Getting EC2 instance info"
        infoheader "EC2 instance details" >> $VM_CONFIGFILE
        echo "$_http_out" >> $VM_CONFIGFILE
    fi
}

function getvbox()
{
    message "Getting VirtualBox info"
    infoheader "VirtualBox details" >> $VM_CONFIGFILE
    $VBOX_CONTROL_CMD guestproperty enumerate | sed -E 's/Name: ([^,]+), value: ([^,]*),.*/\1: \2/g' >> $VM_CONFIGFILE
}

function getxen()
{
    message "Getting Xenstore info"
    infoheader "Xen details" >> $VM_CONFIGFILE
    $XENSTORE_LS_CMD >> $VM_CONFIGFILE
}

function getmemory()
{
	message "Memory information"
        echo -e "\n----------\n free, human readable\n ----------" >> $MEMINFO
	free -h -w  >> $MEMINFO 2>/dev/null
    # old version has no -w option
    [ $? -eq 0 ] || free -h >> $MEMINFO 2>/dev/null
        echo -e "\n----------\n free, machine friendly\n ----------" >> $MEMINFO
	free -w  >> $MEMINFO 2>/dev/null
    # old version has no -w option
    [ $? -eq 0 ] || free >> $MEMINFO 2>/dev/null
        echo -e "\n----------\n swap partitions \n ----------" >> $MEMINFO
	cat /proc/swaps  >> $MEMINFO
        echo -e "\n----------\n /proc/sys/vm/swappiness \n ----------" >> $MEMINFO
	cat /proc/sys/vm/swappiness  >> $MEMINFO
        echo -e "\n----------\n MEM INFO\n ----------" >> $MEMINFO
        cat /proc/meminfo >> $MEMINFO
}

function gethardware()
{
        message "Copying hardware profile"
        echo -en "=================================\nSystem Specs\n---------------------------------\n" >> $HWCONF
        echo -e "\n---------------------------------\n Summarised CPU INFO\n ---------------------------------" >> $HWCONF
        ${LSCPU} >> $HWCONF
        echo -e "\n---------------------------------\n Detailed CPU INFO \n ---------------------------------" >> $HWCONF
        cat /proc/cpuinfo >> $HWCONF
        echo -e "\n---------- \n PCI BUS \n-----------" >> $HWCONF
        ${LSPCI} >> $HWCONF
        if [[ $ROOT_MODE -eq 1 ]]; then 
            ${DMIDECODE} >> $HWCONF
        else
           echo -e "\n---------- \ndmidecode \n-----------" >> $HWCONF
           sudo --non-interactive ${DMIDECODE} >> $HWCONF
           echo -en "\nScript has been not run by root, full hardware profile could not be collected." >> $HWCONF
           message "Script has been not run by root, full hardware profile could not be collected."
        fi
}

function getnetconf()
{
	message "Networking information"
        echo "=================================" >> $NETCONF
        echo "Network Configuration " >> $NETCONF
        echo -e "\n---------- Links Info ----------" >> $NETCONF
        $IP -o -s link >> $NETCONF
        echo -e "\n---------- Address Info ----------" >> $NETCONF
        $IP -o address >> $NETCONF
        echo -e "\n---------- Routes Info ----------" >> $NETCONF
        $IP -o route >> $NETCONF
        echo -e "\n---------- Rules Info ----------" >> $NETCONF
        $IP -o rule >> $NETCONF
        echo -e "\n---------- Network sockets ----------" >> $NETCONF
        $SS -anp >> $NETCONF

        if [[ $ROOT_MODE -eq 1 ]]; then 
        echo -e "\n---------- Network firewall configuration ----------" >> $NETCONF
            $IPTABLES -L -nv >> $NETCONF
        echo -e "\n---------- Network firewall configuration: NAT table ----------" >> $NETCONF
            $IPTABLES -L -t nat -nv >> $NETCONF
        fi
}


function getstorage()
{
	message "Storage information"
        echo -en "=================================\nStorage\n---------------------------------\n" >> $STORAGE_CONFIGFILE
        cat /proc/partitions >> $STORAGE_CONFIGFILE
        echo "----------------------------------" >> $STORAGE_CONFIGFILE
        echo -e "Device Partition table" >> $STORAGE_CONFIGFILE

# limited lskblk output for humans
        $LSBLK -fs -t >> $STORAGE_CONFIGFILE
        echo "----------------------------------" >> $STORAGE_CONFIGFILE
# lskblk output for machine parsing
# different lsblk versions have different possibilities, we want to catch all possible columns
        lsblk_columns=$($LSBLK  -h | grep '^  *[A-Z]' | awk '{print $1 }' |tr '\n' ',' | sed 's/,$//')
        $LSBLK -r -i -a --output ${lsblk_columns} >> $STORAGE_CONFIGFILE

        echo "----------------------------------" >> $STORAGE_CONFIGFILE
        df -Th >> $STORAGE_CONFIGFILE
        echo -en "=================================\nMounted File Systems\n---------------------------------\n" >> $STORAGE_CONFIGFILE
        cat /etc/mtab | egrep -i ^/dev | tr -s ' ' ';' | awk -F ';' '{ printf "%-15s %-15s %-10s %-20s %s %s\n",$1,$2,$3,$4,$5,$6 }' >> $STORAGE_CONFIGFILE
        cat /etc/mtab | egrep -iv ^/dev | tr -s ' ' ';' | awk -F ';' '{ printf "%-15s %-15s %-10s %-20s %s %s\n",$1,$2,$3,$4,$5,$6 }' | sort >> $STORAGE_CONFIGFILE
        echo -en "=================================\nConfigured File Systems\n---------------------------------\n" >> $STORAGE_CONFIGFILE
        cat /etc/fstab | egrep -i ^/dev | tr -s [:blank:] ';' | awk -F ';' '{ printf "%-15s %-15s %-10s %-20s %s %s\n",$1,$2,$3,$4,$5,$6 }' | sort >> $STORAGE_CONFIGFILE
        cat /etc/fstab | egrep -iv ^/dev | grep ^[^#] | tr -s [:blank:] ';' | awk -F ';' '{ printf "%-15s %-15s %-10s %-20s %s %s\n",$1,$2,$3,$4,$5,$6 }' | sort >> $STORAGE_CONFIGFILE

}

function getfilelist()
{
    message "AppDynamics files list"
    # CSV columns are: filename; type; symbolic; octal; user; group; size (bytes); local mtime
    find $APPD_HOME -printf "%p;%y;%M;%m;%u;%g;%s;%Tc\n" | sort -t ';' -k1,1 | sed -e 's|;d;|;dir;|;s|;f;|;file;|;s|;l;|;link;|;s|;s;|;sock;|;s|;b;|;block;|;s|;c;|;char;|;s|;p;|;pipe;|' > $FILELIST
}

function getopenfiles()
{
        # Print list of open files
        message_format "%s" "Reading open files. "
        $LSOF -n -b -w -P -X > $OPENFILES
        message "Done!"
}

function getsyslogs()
{
    message_format "%s"  "Copying system logs"
    [ -d $SYSLOGS ] || mkdir $SYSLOGS
    [ $ROOT_MODE -eq 0 ] && message_format "%s"  " (very limited as you are not root). "
    # as a non-root user we will be able to get only some crumbs. let's get just everything we allowed to read...

    local _syslogdir="/var/log"

    for f in $(find $_syslogdir -type f -mtime -$SYSLOGDAYS ! -path "${_syslogdir}/journal/*" ! -path "${_syslogdir}/sa/*" ! -path "${_sysstatdir}/sysstat/*" -printf "%P\n" 2>/dev/null); do

        local _srcfile="${_syslogdir}/${f}"
        local _destfile="${SYSLOGS}${f}"
        local _destsubdir=$(dirname $_destfile)

        [ -d "$_destsubdir" ] || mkdir -p "$_destsubdir"
        if checkfilesize $_srcfile $MAX_FILE_SIZE; then
            log_message "Truncating $_srcfile due to size."
            tail -c $MAX_FILE_SIZE $_srcfile > "$_destfile"
        else
            $CP_CMD $_srcfile $_destfile
        fi
    done

    # Grab dmesg
    dmesg > $SYSLOGS/dmesg

    # We need whole sysstat dir
    local _sysstatdir="$SYSLOGS/sysstat"
    [ -d "$_sysstatdir" ] || mkdir $_sysstatdir
    $CP_CMD $_syslogdir/sa/* $_syslogdir/sysstat/*  $_sysstatdir

    # systemd journal
    if [ -x "$JOURNALCTL" ]; then
        $JOURNALCTL --no-pager --since "-$DAYS days" > $SYSLOGS/journal
    fi

    message "..Done!"
}

function getsystemd()
{
    if [ -x "$SYSTEMCTL" ]; then
        message  "Getting systemd info"
    else
        return 1
    fi

    while read cmd; do
        infoheader "$cmd" >> $SYSTEMD_INFO
        $cmd >> $SYSTEMD_INFO 2> /dev/null
    done <<EOF
systemctl status --all  --no-pager
systemctl show --all --no-pager
systemctl show *service --all --no-pager
systemctl list-units --no-pager
systemctl list-units --failed --no-pager
systemctl list-unit-files --no-pager
systemctl list-jobs --no-pager
systemctl list-dependencies --no-pager
systemctl list-timers --all --no-pager
systemctl list-machines --no-pager
systemctl show-environment --no-pager
systemd-delta
systemd-analyze
systemd-analyze blame
systemd-analyze dump
systemd-inhibit --list
journalctl --list-boots
journalctl --disk-usage
systemd-resolve --status
systemd-resolve --statistics
ls -lR /lib/systemd
EOF
}

function gettimeconfig()
{
    message "Checking time config"
    infoheader "current system date and time" >> $TIMECONFIG
    date >> $TIMECONFIG
    infoheader "current hardware clock date and time" >> $TIMECONFIG
    hwclock >> $TIMECONFIG
    # VMware time sync
    if [ -x "$VMWARE_TOOLBOX_CMD" ]; then
        infoheader "VMware details" >> $TIMECONFIG
        { echo -n "Host time: ";
          $VMWARE_TOOLBOX_CMD stat hosttime;
          echo -n "Host time-sync status: ";
          $VMWARE_TOOLBOX_CMD timesync status;
        } >> $TIMECONFIG
    fi
    # Good old ntpd
    if is_service_running ntpd || is_service_running ntp; then
        infoheader "Time sync: ntpd detected" >> $TIMECONFIG
        if [ -x "${NTPQ}" ]; then
            infosubheader "NTP peers" >> $TIMECONFIG
            $NTPQ -n -c peers >> $TIMECONFIG
            infosubheader "NTP associations" >> $TIMECONFIG
            $NTPQ -n -c as >> $TIMECONFIG
            infosubheader "NTP sysinfo" >> $TIMECONFIG
            $NTPQ -n -c sysinfo  >> $TIMECONFIG
        fi
    fi
    # simple systemd timesyncd
    if is_service_running systemd-timesyncd; then
        infoheader "Time sync: systemd-timesyncd detected" >> $TIMECONFIG
        if [ -x "${TIMEDATECTL}" ]; then
            infosubheader "current time settings" >> $TIMECONFIG
            $TIMEDATECTL status >> $TIMECONFIG
            infosubheader "properties of systemd-timedated" >> $TIMECONFIG
            $TIMEDATECTL show >> $TIMECONFIG
            infosubheader "status of systemd-timesyncd" >> $TIMECONFIG
            $TIMEDATECTL timesync-status >> $TIMECONFIG
            infosubheader "properties of systemd-timesyncd" >> $TIMECONFIG
            $TIMEDATECTL show-timesync --all >> $TIMECONFIG
            infosubheader "systemd-timesyncd configuration" >> $TIMECONFIG
            cat /etc/systemd/timesyncd.conf >> $TIMECONFIG
        fi
    fi
    # chronyd is a modern ntpd replacement
    if is_service_running chronyd || is_service_running chrony; then
        infoheader "Time sync: chronyd detected" >> $TIMECONFIG
        if [ -x "${CHRONYC}" ]; then
            infosubheader "system’s clock performance" >> $TIMECONFIG
            $CHRONYC tracking >> $TIMECONFIG
            infosubheader "current time sources" >> $TIMECONFIG
            $CHRONYC sources -v >> $TIMECONFIG
            infosubheader "time sources statistics" >> $TIMECONFIG
            $CHRONYC sourcestats -v >> $TIMECONFIG
            infosubheader "server statistics" >> $TIMECONFIG
            $CHRONYC serverstats >> $TIMECONFIG
            infosubheader "ntp specific details" >> $TIMECONFIG
            $CHRONYC ntpdata >> $TIMECONFIG
        fi
    fi



}

function getinitinfo()
{
	message "Init info"
        RUNLEVEL=$(runlevel | egrep -o [0-6abcs])
        echo "Current runlevel: $RUNLEVEL" > $INITSCRIPTS
        ls -l /etc/rc${RUNLEVEL}.d/* >> $INITSCRIPTS
}

function getprocesses()
{
	message_format "%s"  "Get processes. "
	ps xau > $PROCESSES
	message "Done!"
}

function gettop()
{
	message "Collecting TOP output"
	echo -e "\n---------- top report, CPU usage sorted ----------" >> $TOPREPORT
	$TOP -b -n3 -o +%CPU | head -35	 >> $TOPREPORT
	echo -e "\n---------- top report, MEM usage sorted ----------" >> $TOPREPORT
	$TOP -b -o +%MEM | head -35	 >> $TOPREPORT
	echo -e "\n---------- top report, TIME usage sorted ----------" >> $TOPREPORT
	$TOP -b -o TIME+ | head -35   >> $TOPREPORT
	
}


function subpath()
{
        echo "$1" |rev  | cut -d"/" -f $2- | rev
}

function appd_variables()
{
        APPD_CONTROLLER_GLASSFISH_PID=$(pgrep -f "s/glassfish.jar ")
        APPD_CONTROLLER_MYSQL_PID=$(pgrep -f "[d]b/bin/mysqld")

        if [[ -n $APPD_CONTROLLER_GLASSFISH_PID ]]; then
            # appserver running, piece of cake
            log_message "Found controller appserver PID $APPD_CONTROLLER_GLASSFISH_PID"
            APPD_HOME=$(subpath $(readlink /proc/$APPD_CONTROLLER_GLASSFISH_PID/cwd) 9)
            APPD_CONTROLLER_HOME=$(subpath $(readlink /proc/$APPD_CONTROLLER_GLASSFISH_PID/cwd) 6)
            APPD_CONTROLLER_JAVA_HOME=$(subpath $(readlink /proc/$APPD_CONTROLLER_GLASSFISH_PID/exe) 3)
            APPD_CONTROLLER_MYSQL_HOME="${APPD_CONTROLLER_HOME}/db"
        elif [[ -n $APPD_CONTROLLER_MYSQL_PID ]]; then
            # appserver not running, but we still got mysql, easy thing
            log_message "Found Controller mysqld PID $APPD_CONTROLLER_MYSQL_PID"
            # in /proc/$pid/cmdline args are oddly separated with NULL (\x0)
            # first substitution cuts all from line beginning up to --basedir=
            # second one cuts everything after subsequent NULL separator
            # what's left is mysql basedir path, we're looking for
            APPD_CONTROLLER_MYSQL_HOME=$(sed -e 's/.*--basedir=//' -e 's/\x0--.*$//' /proc/$APPD_CONTROLLER_MYSQL_PID/cmdline)
            # if controller is not running, but mysqld is up we can figure out paths differently
            log_warning "Controller apparently not running, but mysql is still up"
            APPD_HOME=$(subpath $APPD_CONTROLLER_MYSQL_HOME 5)
            APPD_CONTROLLER_HOME=$(subpath $APPD_CONTROLLER_MYSQL_HOME 2)
            APPD_CONTROLLER_JAVA_HOME=$(find_controller_java_home)
        else
            # controller and DB are not running. so sad... let's try our best
            log_warning "Could not find running mysql server either controller instance!"

            find_predicted_dirs
            if [ $ORCHA_NOT_FOUND -eq 1 ]; then
                # EC renames controller.sh to controller.sh-disabled on standby server
                local _dir=$(find / \( -name controller.sh -o -name controller.sh-disabled \) -print -quit 2>/dev/null)
            else
                local _dir=$(find $PREDICTED_APPD_DIRS \( -name controller.sh -o -name controller.sh-disabled \) -print -quit 2>/dev/null)
            fi
            # /appdynamics/platform/product/controller/bin/controller.sh
            APPD_HOME=$(subpath $_dir 6)
            APPD_CONTROLLER_HOME=$(subpath $_dir 3)
            APPD_CONTROLLER_JAVA_HOME=$(find_controller_java_home)
            APPD_CONTROLLER_MYSQL_HOME="${APPD_CONTROLLER_HOME}/db"
        fi

    APPD_CONTROLLER_MYSQL_VERSION=$(${APPD_CONTROLLER_MYSQL_HOME}/bin/mysqld --version | sed -ne 's/[^0-9]*\(\([0-9]\.\)\{0,4\}[0-9][^.]\).*/\1/p')
    APPD_CONTROLLER_INSTALL_USER=$(find_entry_in_mysql_dbconf "controller" "user")
    if id -u $APPD_CONTROLLER_INSTALL_USER >/dev/null 2>&1; then
        APPD_CONTROLLER_INSTALL_GROUP=$(id -gn $APPD_CONTROLLER_INSTALL_USER)
    else
        APPD_CONTROLLER_INSTALL_USER=${ROOT_USER}
        APPD_CONTROLLER_INSTALL_GROUP=${ROOT_GROUP}
    fi
    APPD_CONTROLLER_DB_INSTALL_PORT=$(find_entry_in_mysql_dbconf "controller" "port")
    if [ -z "${APPD_CONTROLLER_DB_INSTALL_PORT}" ] ; then
        APPD_CONTROLLER_DB_INSTALL_PORT=${MYSQL_PORT}
    fi
    # if the APPD_CONTROLLER_HOME was found, set the CONTROLLER_INSTALLED to 1 otherwise exit the function
	if [ -n "$APPD_CONTROLLER_HOME" ]; then
        CONTROLLER_INSTALLED=1
    else
		warning "No Controller installation was found on this host."
		return 1
	fi

    #variables for custom paths to mysql log files:
    APPD_CONTROLLER_MYSQL_ERR_LOG=$(find_entry_in_mysql_dbconf "controller" "log-error")
    APPD_CONTROLLER_MYSQL_SLOWLOG=$(find_entry_in_mysql_dbconf "controller" "slow_query_log_file")

    #variable for a custom path to mysql "data" directory:
    APPD_CONTROLLER_MYSQL_DATADIR=$(find_entry_in_mysql_dbconf "controller" "datadir")

    mkdir $APPD_CONTROLLER
    echo APPD_CONTROLLER_HOME $APPD_CONTROLLER_HOME
    echo APPD_CONTROLLER_JAVA_HOME $APPD_CONTROLLER_JAVA_HOME
    echo APPD_CONTROLLER_MYSQL_HOME $APPD_CONTROLLER_MYSQL_HOME
    echo APPD_CONTROLLER_MYSQL_DATADIR $APPD_CONTROLLER_MYSQL_DATADIR
    echo APPD_CONTROLLER_GLASSFISH_PID $APPD_CONTROLLER_GLASSFISH_PID
    echo APPD_CONTROLLER_MYSQL_PID $APPD_CONTROLLER_MYSQL_PID
    echo APPD_CONTROLLER_INSTALL_USER $APPD_CONTROLLER_INSTALL_USER
    echo APPD_CONTROLLER_DB_INSTALL_PORT $APPD_CONTROLLER_DB_INSTALL_PORT
}


function appd_EC_variables()
{
        APPD_EC_PID=$(pgrep -f "PlatformAdminApplication")
        APPD_EC_MYSQL_PID=$(ps xau | grep "[m]ysql/bin/mysqld" | grep 3377 | awk '{print $2}')
        if [[ -n $APPD_EC_PID ]]; then
            # EC running, piece of cake
            log_message "Found EC appserver PID $APPD_EC_PID"
            APPD_HOME2=$(subpath $(readlink /proc/$APPD_EC_PID/cwd) 3)
            APPD_EC_HOME=$(readlink /proc/$APPD_EC_PID/cwd)
            APPD_EC_JAVA_HOME=$(subpath $(readlink /proc/$APPD_EC_PID/exe) 3)
            APPD_EC_MYSQL_HOME=$(subpath $(readlink /proc/$APPD_EC_MYSQL_PID/cwd) 2)
        elif [[ -n $APPD_EC_MYSQL_PID ]]; then
          # appserver not running, but we still got EC mysql, easy thing
            log_message "Found EC mysqld PID $APPD_EC_MYSQL_PID"
            # in /proc/$pid/cmdline args are oddly separated with NULL (\x0)
            # first substitution cuts all from line beginning up to --basedir=
            # second one cuts everything after subsequent NULL separator
            # what's left is mysql basedir path, we're looking for
            APPD_EC_MYSQL_HOME=$(sed -e 's/.*--basedir=//' -e 's/\x0--.*$//' /proc/$APPD_EC_MYSQL_PID/cmdline)
            # if EC is not running, but mysqld is up we can figure out paths differently
            log_warning "EC apparently not running, but mysql is still up"
            APPD_HOME2=$(subpath $APPD_EC_MYSQL_HOME 3)
            APPD_EC_HOME=$(subpath $APPD_EC_MYSQL_HOME 2)"/platform-admin"
            APPD_EC_JAVA_HOME=$APPD_EC_JAVA_HOME"/jre"
        else
            # EC and its DB are not running. so sad... let's try our best
            log_warning "Could not find running mysql server either EC instance!"

            find_predicted_dirs
            if [ $ORCHA_NOT_FOUND -eq 1 ]; then
                # real live scenario - multiple directory backups with previous EC versions, before upgrade. Lets pick most recent version (determined by last access)
                local _dir=$(find / -name platform-admin.sh -printf "%A@ %Ac %p %h\n" 2>/dev/null | sort -n | tail -1 | awk '{print $NF}')
            else
                local _dir=$(find $PREDICTED_APPD_DIRS -name platform-admin.sh -printf "%A@ %Ac %p %h\n" 2>/dev/null | sort -n | tail -1 | awk '{print $NF}')
            fi
            APPD_HOME2=$(subpath $_dir 4)
            APPD_EC_HOME=$(subpath $_dir 2)
            APPD_EC_MYSQL_HOME=$(subpath $_dir 3)"/mysql"
            APPD_EC_JAVA_HOME="${APPD_EC_HOME}/jre"
        fi

    APPD_EC_INSTALL_USER=$(find_entry_in_mysql_dbconf "ec" "user")
    if id -u $APPD_EC_INSTALL_USER >/dev/null 2>&1; then
        APPD_EC_INSTALL_GROUP=$(id -gn $APPD_EC_INSTALL_USER)
    else
        APPD_EC_INSTALL_USER=${ROOT_USER}
        APPD_EC_INSTALL_GROUP=${ROOT_GROUP}
    fi
    # if the APPD_EC_HOME was found, set the EC_INSTALLED to 1 otherwise exit the function
    if [ -n "$APPD_EC_HOME" ]; then
        EC_INSTALLED=1
    else
        warning "No Enterprise Console installation was found on this host."
        return 1
    fi

mkdir $APPD_EC
echo APPD_EC_PID $APPD_EC_PID
echo APPD_EC_MYSQL_PID $APPD_EC_MYSQL_PID
echo APPD_HOME $APPD_HOME
echo APPD_HOME2 $APPD_HOME2
echo APPD_EC_HOME $APPD_EC_HOME
echo APPD_EC_JAVA_HOME $APPD_EC_JAVA_HOME
echo APPD_EC_MYSQL_HOME $APPD_EC_MYSQL_HOME
echo APPD_EC_INSTALL_USER $APPD_EC_INSTALL_USER

}

#
# find java version used by appserver, based on asenv.conf
# the idea stolen from HA/lib/status.sh
#
function find_controller_java_home()
{
    if [ -f $APPD_CONTROLLER_HOME/appserver/glassfish/config/asenv.conf ]; then
        local _as_java=$(grep ^AS_JAVA= $APPD_CONTROLLER_HOME/appserver/glassfish/config/asenv.conf | awk -F\= '{ gsub(/"/,"",$2); print $2 }')
    else
        log_warning "Could not find java path in appserver config, but trying in jre/"
    fi

    local _product_home=$(subpath $APPD_CONTROLLER_HOME 2)
    # if no executable in AS_JAVA, tries jre/*
    # TODO: * evaluation uses numeric sort, can we do it better?
    local _path=""
    for _path in $_as_java $_product_home/jre/* ; do
        if [ -x "$_path/bin/java" ] ; then
            echo $_path
            break;
        fi
    done
}

# Function takes a parameter - name of a component - Controller or EUM
function get_mysql_password()
{
    local _mysql_home
    local _mysql_password
    local _mysql_pid
    if [ "$1" == "controller" ]; then
        _mysql_home=$APPD_CONTROLLER_MYSQL_HOME
        _mysql_pid=$APPD_CONTROLLER_MYSQL_PID
        # password may already be set from CLI or ENV
        _mysql_password=$CONTROLLER_MYSQL_PASSWORD
    elif [ "$1" == "eum" ]; then
        _mysql_home=$APPD_EUM_MYSQL_HOME
        _mysql_pid=$APPD_EUM_MYSQL_PID
        _mysql_password=$EUM_MYSQL_PASSWORD
    fi
    MYSQL="${_mysql_home}/bin/mysql"

    if [ ! -x "$MYSQL" ]; then
        log_warning "Unable to find MySQL client in: ${_mysql_home}"
    fi

    if [[ -z "$_mysql_password" && -n "$_mysql_pid" ]]; then
        message "Provide "$1" MySQL root user password: "
        read -e -r -s -t15 _mysql_password
        echo ""
    fi

    [ $1 == "controller" ] && CONTROLLER_MYSQL_PASSWORD=$_mysql_password
    [ $1 == "eum" ] && EUM_MYSQL_PASSWORD=$_mysql_password
    mysql_exec "status" "$1"  2>&1 >/dev/null
    local _valid_password=$?
    # temporarily disable xtrace to prevent password logging
    set +x
    if [[ $_valid_password -eq 0  && "$1" == "controller" ]]; then
        HAVE_ACCESS_TO_CONTROLLER_DB=1
    elif [[ $_valid_password -eq 0  && "$1" == "eum" ]]; then
        HAVE_ACCESS_TO_EUM_DB=1
    elif [ ! -z $_mysql_password ]; then
        message "Unable to connect to the database - check your password or just hit enter to skip this step"
        unset _mysql_password
        # clear globals
        [ $1 == "controller" ] && CONTROLLER_MYSQL_PASSWORD=""
        [ $1 == "eum" ] && EUM_MYSQL_PASSWORD=""
        get_mysql_password "$1"
    fi
    # re-enable xtrace
    set -x
}

function get_controller_root_password()
{

    if [[ -z "$CONTROLLER_ROOT_PASSWORD" && -n "$APPD_CONTROLLER_GLASSFISH_PID" ]]; then
        message "Provide Controller root user password (hit enter to skip): "
        read -e -r -s -t15 CONTROLLER_ROOT_PASSWORD
        echo ""
    fi

    # TODO: check password is valid
    # temporarily disable xtrace to prevent password logging
    set +x
    if [ -n "$CONTROLLER_ROOT_PASSWORD" ]; then
        HAVE_ACCESS_TO_CONTROLLER_ROOT=1
    fi
    # re-enable xtrace
    set -x
}

function get_controller_mysql_data()
{
message "Collecting Controller SQL queries"

if [ $HAVE_ACCESS_TO_CONTROLLER_DB -eq 0 ]; then
    echo -e "No access to controller DB, or MySQL process is not running." >> $APPD_CONTROLLER_QUERIES
    return 1
fi
echo -e "\n---------- Controller Profile Information ---------- " >> $APPD_CONTROLLER_QUERIES

while read query; do
  # redirect both stderr and stdout to capture exact error
  mysql_exec "$query" "controller" &>> $APPD_CONTROLLER_QUERIES
# WARNING! in queries use only single quotes and escape \ with \\
done <<EOF
select version() mysql_version;
status;
show status like 'Conn%';
select name, value from global_configuration_cluster where name in ('schema.version', 'performance.profile','appserver.mode','ha.controller.type');
select from_unixtime(ts_min*60), NOW(), count(distinct(node_id)), count(*) from metricdata_min where ts_min > (select max(ts_min) - 10 from metricdata_min) group by 1 order by 1;
select from_unixtime(ts_min*60), NOW(), count(distinct(node_id)), count(*) metric_count from metricdata_hour where ts_min > (select max(ts_min) - 10080 from metricdata_hour) group by 1 ORDER BY metric_count DESC LIMIT 10;
SELECT table_name FROM   information_schema.key_column_usage WHERE  table_name LIKE 'metricdata%' AND table_name != 'metricdata_min' AND table_name != 'metricdata_min_agg' AND column_name = 'ts_min' AND ordinal_position = 1;
select count(*) from eventdata_min;
select event_type,count(*) as count from eventdata_min group by event_type order by count desc;
SELECT table_name FROM information_schema.key_column_usage WHERE table_name LIKE 'metricdata%' AND table_name != 'metricdata_min' AND table_name != 'metricdata_min_agg' AND column_name = 'ts_min' AND ordinal_position = 1;
show table status from controller where Create_options='partitioned';
show table status from controller where Create_options != 'partitioned';
SELECT table_schema as 'Database', table_name AS 'Table', round(((data_length + index_length) / 1024 / 1024), 2) 'Size in MB' FROM information_schema.TABLES  ORDER BY (data_length + index_length) DESC;
select * from notification_config\\\G;
select name,value from global_configuration;
show status;
EOF
}

# Function receives two parameters
# $1 - command to execute
# $2 - component value (e.g. Controller, EUM)
function mysql_exec()
{
    local _mysql_home
    local _db_install_port
    local _mysql_version
    local _mysql_password
    local _db_name
    if [ $2 == "controller" ]; then
        _mysql_home=$APPD_CONTROLLER_MYSQL_HOME
        _db_install_port=$APPD_CONTROLLER_DB_INSTALL_PORT
        _mysql_version=$APPD_CONTROLLER_MYSQL_VERSION
        _mysql_password=$CONTROLLER_MYSQL_PASSWORD
        _db_name="controller"
    elif [ $2 == "eum" ]; then
        _mysql_home=$APPD_EUM_MYSQL_HOME
        _db_install_port=$APPD_EUM_DB_INSTALL_PORT
        _mysql_version=$APPD_EUM_MYSQL_VERSION
        _mysql_password=$EUM_MYSQL_PASSWORD
        _db_name="eum_db"
    fi
    MYSQL="${_mysql_home}/bin/mysql"
    mysqlopts="-A -t -vvv --force --host=localhost --protocol=TCP --user=root --port=${_db_install_port}"

    # temporarily disable xtrace to prevent password logging
    set +x

    export MYSQL_PWD="$_mysql_password"
    # re-enable xtrace
    set -x

    local _return=1

    if compare_versions $_mysql_version ">=" "5.7"; then
        # That's for correct evaluation of $MYSQL_QUERY_TIMEOUT in quoted mysql option
        $MYSQL $mysqlopts --init-command="SET SESSION MAX_EXECUTION_TIME=${MYSQL_QUERY_TIMEOUT};" -e "$1" "$_db_name"
        _return=$?
     else
        # TODO:  do SomeThing(TM) with setting max execution time for older mysql 
        $MYSQL $mysqlopts -e "$1" "$_db_name"
        _return=$?
    fi

    unset MYSQL_PWD
    return $_return
}

function appd_getenvironment()
{
  message "Checking AppD environment"
    if [[ -n $APPD_CONTROLLER_GLASSFISH_PID ]]; then
        echo -e "\n---------- Controller Java PID ---------- " >> $APPD_CONTROLLER_JAVAINFO
        echo $APPD_CONTROLLER_GLASSFISH_PID >> $APPD_CONTROLLER_JAVAINFO
        echo -e "\n---------- Controller Java version ---------- " >> $APPD_CONTROLLER_JAVAINFO
		/proc/$APPD_CONTROLLER_GLASSFISH_PID/exe -version >> $APPD_CONTROLLER_JAVAINFO 2>&1
	 	echo -e "\n---------- Controller Java limits ---------- " >> $APPD_CONTROLLER_JAVAINFO
		cat /proc/$APPD_CONTROLLER_GLASSFISH_PID/limits >> $APPD_CONTROLLER_JAVAINFO
	 	echo -e "\n---------- Controller Java status ---------- " >> $APPD_CONTROLLER_JAVAINFO
		cat /proc/$APPD_CONTROLLER_GLASSFISH_PID/status >> $APPD_CONTROLLER_JAVAINFO
	 	echo -e "\n---------- Controller Java scheduler stats ---------- " >> $APPD_CONTROLLER_JAVAINFO
		 # use the source, Luke! 	kernel/sched/debug.c
		cat /proc/$APPD_CONTROLLER_GLASSFISH_PID/sched >> $APPD_CONTROLLER_JAVAINFO
	else
                echo -e "Controller Java process is not running." >> $APPD_CONTROLLER_JAVAINFO
	fi

	if [[ -n $APPD_CONTROLLER_MYSQL_PID ]]; then
	    echo -e "\n---------- Controller MySQL PID ---------- " >> $APPD_CONTROLLER_MYSQLINFO
        echo $APPD_CONTROLLER_MYSQL_PID >> $APPD_CONTROLLER_MYSQLINFO
        echo -e "\n---------- Controller MySQL version ---------- " >> $APPD_CONTROLLER_MYSQLINFO
		/proc/$APPD_CONTROLLER_MYSQL_PID/exe --version >> $APPD_CONTROLLER_MYSQLINFO 2>&1
	 	echo -e "\n---------- Controller MySQL limits ---------- " >> $APPD_CONTROLLER_MYSQLINFO
		cat /proc/$APPD_CONTROLLER_MYSQL_PID/limits >> $APPD_CONTROLLER_MYSQLINFO
	 	echo -e "\n---------- Controller MySQL status ---------- " >> $APPD_CONTROLLER_MYSQLINFO
		cat /proc/$APPD_CONTROLLER_MYSQL_PID/status >> $APPD_CONTROLLER_MYSQLINFO
	 	echo -e "\n---------- Controller MySQL scheduler stats ---------- " >> $APPD_CONTROLLER_MYSQLINFO
		 # use the source, Luke! 	kernel/sched/debug.c
		cat /proc/$APPD_CONTROLLER_MYSQL_PID/sched >> $APPD_CONTROLLER_MYSQLINFO
		
	else
                echo -e "Controller MySQL process is not running." >> $APPD_CONTROLLER_MYSQLINFO
	fi
		# some information about db size and files
		echo -e "\n---------- Controller MySQL files ---------- " >> $APPD_CONTROLLER_MYSQLINFO
		ls -la ${APPD_CONTROLLER_MYSQL_DATADIR} >> $APPD_CONTROLLER_MYSQLINFO
		echo -e "\n---------- Controller MySQL file size ---------- " >> $APPD_CONTROLLER_MYSQLINFO		
		du -hs ${APPD_CONTROLLER_MYSQL_DATADIR}/* >> $APPD_CONTROLLER_MYSQLINFO
}

function get_keystore_info()
{
	message "Controller Keystore content"
        echo -e "\n---------- Controller Keystore content ---------- " >> $APPD_CERTS
	$APPD_CONTROLLER_JAVA_HOME/bin/keytool -list --storepass "changeit" -rfc  -keystore ${APPD_CONTROLLER_HOME}/appserver/glassfish/domains/domain1/config/keystore.jks >> $APPD_CERTS
	$APPD_CONTROLLER_JAVA_HOME/bin/keytool -list --storepass "changeit" -v  -keystore ${APPD_CONTROLLER_HOME}/appserver/glassfish/domains/domain1/config/keystore.jks >> $APPD_CERTS
}

function getnumastats()
{
	message "Numa stats"
 	echo -e "\n---------- Numa inventory of available nodes on the system ---------- " >> $NUMAFILE
	numactl -H >> $NUMAFILE
 	echo -e "\n---------- per-NUMA-node memory statistics for operating system ---------- " >> $NUMAFILE
	numastat >> $NUMAFILE
	echo -e "\n---------- per-NUMA-node memory statistics for java and mysql processes ---------- " >> $NUMAFILE
	numastat -czmns java mysql  >> $NUMAFILE
}

function checkfilesize(){
    # filename=$1
    # allowedsize=$2
    [ $(stat -c%s $1) -ge $2 ]
}


function getcontrollerlogs()
{
    message "Controller logs"
    [ -d $CONTROLLERLOGS ] || mkdir $CONTROLLERLOGS

    for f in $(find $APPD_CONTROLLER_HOME/logs \( -name "*.log" -o -name "gc.log.0.current" \) ! -path "$APPD_CONTROLLER_HOME/logs/support-report/*" -type f); do
        if checkfilesize $f $MAX_FILE_SIZE; then
            tail -c $MAX_FILE_SIZE $f > "$CONTROLLERLOGS/$(basename $f)"
        else
            cp $f $CONTROLLERLOGS
        fi
    done

    message "Collecting rotating logs from $DAYS days"
    find $APPD_CONTROLLER_HOME/logs -name "*.log_*" ! -path "$APPD_CONTROLLER_HOME/logs/support-report/*" -mtime -$DAYS -exec cp -a {} $CONTROLLERLOGS \;
}

function getEClogs()
{
    message "EC logs"
    [ -d $ECLOGS ] || mkdir $ECLOGS

    for f in $(find $APPD_EC_HOME/logs -name "*.log" -type f); do
        if checkfilesize $f $MAX_FILE_SIZE; then
            tail -c $MAX_FILE_SIZE $f > "$ECLOGS/$(basename $f)"
        else
            cp $f $ECLOGS
        fi
    done

    message "Collecting rotating logs from $DAYS days"
    find $APPD_EC_HOME/logs -name "*.log*" -mtime -$DAYS -exec cp -a {} $ECLOGS \;
    mkdir $ECLOGS/tmp_install_logs/
    $CP_CMD /tmp/install4jError*.log $ECLOGS/tmp_install_logs/
}


function getmysqlcontrollerlogs()
{
    message "Mysql Controller logs"
    [ -d $CONTROLLERMYSQLLOGS ] || mkdir $CONTROLLERMYSQLLOGS
    for f in $APPD_CONTROLLER_MYSQL_ERR_LOG $APPD_CONTROLLER_MYSQL_SLOWLOG; do
        if checkfilesize $f $MAX_FILE_SIZE; then
            tail -c $MAX_FILE_SIZE $f > "$CONTROLLERMYSQLLOGS/$(basename $f)"
        else
            $CP_CMD $f $CONTROLLERMYSQLLOGS
        fi
    done
}

function getcontrollerreport()
{
    message "Controller report"
    [ -x $BASE64 ] || return 1

    if [ "$HAVE_ACCESS_TO_CONTROLLER_ROOT" -eq 1 ]; then
        # temporarily disable xtrace to prevent password logging
        set +x
        AUTH=$(echo -n "root@system:${CONTROLLER_ROOT_PASSWORD}" | $BASE64 )
        # re-enable xtrace
        set -x
    else
        log_warning "No root password to download controller report."
        return 1
    fi

    [ -d "$CONTROLLERREPORT" ] || mkdir "$CONTROLLERREPORT"

    local _temp_file="${CONTROLLERREPORT}/controller-report.zip.temp"
    local _chunk_file="${CONTROLLERREPORT}/controller-report.zip.chunks"
    local _out_file="${CONTROLLERREPORT}/controller-report.zip"

    local _report_url="http://localhost:8090/controller/private/operator/report/download"

    http_get_file $_report_url $_temp_file

    if [ ! -f $_temp_file ]; then
        log_warning "Controller report download failed."
        return 1
    else
        # get HTTP response header
        local _http=$(sed '0,/^\r$/!d' $_temp_file | grep '^HTTP')

        if [[ "$_http" != *"200"*  ]]; then
            warning "Controller report download failed with code: $_http"
            return 1
        fi

        # removes headers, but keeps first \r\n separator
        sed '/^\r$/,$!d' $_temp_file > $_chunk_file
        rm $_temp_file

        file_unchunk $_chunk_file $_out_file
    fi
}

function gethainfo()
{
    message "HA and DB replication status"
    infoheader "Controller high availability status" > $HA_INFO

    infosubheader "Init scripts" >> $HA_INFO
    if [ -x /etc/init.d/appdcontroller ]; then
        echo -e "\ninstalled" >> $HA_INFO
    else
        echo -e "\nnot installed" >> $HA_INFO
    fi

    infosubheader "HA status summary" >> $HA_INFO
    if [ -x "${APPD_CONTROLLER_HOME}/controller-ha/status_api.sh" ]; then
        ${APPD_CONTROLLER_HOME}/controller-ha/status_api.sh summary >> $HA_INFO
    else
        echo -e "\nstatus_api.sh not found" >> $HA_INFO
    fi

    infoheader "MySQL replication" >> $HA_INFO
    if [ $HAVE_ACCESS_TO_CONTROLLER_DB -eq 1 ]; then
        mysql_exec "SHOW SLAVE STATUS\G;" "controller" >> $HA_INFO
        mysql_exec "SHOW MASTER STATUS\G;" "controller" >> $HA_INFO
    else
        echo -e "\n not available. no access to db. " >> $HA_INFO
    fi
}

function getmysqlEClogs()
{
	message "Mysql EC logs"
        [ -d $ECMYSQLLOGS ] || mkdir $ECMYSQLLOGS
# just get all logs, normally should be small and probably older than 3 days        
        find $APPD_EC_MYSQL_HOME/logs/ -name "*.*" -exec cp -a {} $ECMYSQLLOGS \;
}


function getcontrollerconfigs()
{
	message "Controller configs"
#/appdynamics/platform/product/controller/appserver/glassfish/domains/domain1/config
        [ -d $CONTROLLERCONFIGS ] || mkdir $CONTROLLERCONFIGS
	find $APPD_CONTROLLER_HOME/appserver/glassfish/domains/domain1/config -name "*.*" -exec cp -a {} $CONTROLLERCONFIGS \;
	find $APPD_CONTROLLER_HOME/db/ -name "*.cnf" -exec cp -a {} $CONTROLLERCONFIGS \;
	find $APPD_CONTROLLER_HOME/ -name "*.lic" -exec cp -a {} $CONTROLLERCONFIGS \;
}

function getECconfigs()
{
	message "EC configs"
        [ -d $ECCONFIGS ] || mkdir $ECCONFIGS
	cp -a $APPD_EC_HOME/config $ECCONFIGS/
	cp -a $APPD_EC_HOME/conf $ECCONFIGS/
	cp -a $APPD_EC_HOME/playbooks $ECCONFIGS/	
	find $APPD_EC_MYSQL_HOME/ -name "*.cnf" -exec cp -a {} $ECCONFIGS \;
}


function getcontrollerinfo()
{
	message "Controller related information"
	echo -e "\n---------- Controller version information from README file ---------- " >> $APPD_CONTROLLER_INFO
	cat $APPD_CONTROLLER_HOME/README.txt >> $APPD_CONTROLLER_INFO

	echo -e "\n---------- Controller version information from MANIFEST file ---------- " >> $APPD_CONTROLLER_INFO
	cat $APPD_CONTROLLER_HOME/appserver/glassfish/domains/domain1/applications/controller/META-INF/MANIFEST.MF >> $APPD_CONTROLLER_INFO

	echo -e "\n---------- Controller SCHEMA information from database ---------- " >> $APPD_CONTROLLER_INFO
	if [ $HAVE_ACCESS_TO_CONTROLLER_DB -eq 1 ]; then
		mysql_exec "select name, value from global_configuration_cluster where name in ('schema.version', 'performance.profile','appserver.mode','ha.controller.type');" "controller" >> $APPD_CONTROLLER_INFO
	else
		echo -e "\n Not available. No access to DB. " >> $APPD_CONTROLLER_INFO
	fi

	echo -e "\n---------- Controller server status from API ---------- " >> $APPD_CONTROLLER_INFO
	http_query http://127.0.0.1:8090/controller/rest/serverstatus | sed '/<?xml/,$!d' >> $APPD_CONTROLLER_INFO
}


# strings platform/mysql/data/platform_admin/configuration_store.ibd | grep "JobcontrollerRootUserPassword" | tail -1 | awk -F'"' '{print $2}'^C
function getmysqlcontrollerpass()
{
	# root password for controller can be stored in few places. we will try to find it.
	# EC db
	[[ -f $APPD_HOME/platform/mysql/data/platform_admin/configuration_store.ibd ]] && pass=$(strings $APPD_HOME/platform/mysql/data/platform_admin/configuration_store.ibd | grep "JobcontrollerRootUserPassword" | tail -1 | awk -F'"' '{print $2}')
	echo $pass
}


function getloadstats()
{
                message "Measuring basic system load. It will take some time, more like an hour... Time for coffee break. "
#	        echo -en "=================================\nDisk IO usage\n---------------------------------\n" >> $PERFSTATS
                nohup $IOSTAT -myxd 5 720 >> $PERFSTATS-iostat.txt &
#	        echo -en "=================================\nCPU and interrupts usage\n---------------------------------\n" >> $PERFSTATS
                nohup $MPSTAT -A 5 720 >> $PERFSTATS-mpstat.txt &
#                echo -en "=================================\nMemory Utilization\n---------------------------------\n" >> $PERFSTATS
                nohup $VMSTAT -t -n -a 5 720 >> $PERFSTATS-vmstat.txt &
#                echo -en "=================================\nNetwork Utilization\n---------------------------------\n" >> $PERFSTATS
                nohup $SAR -n DEV 5 720 >> $PERFSTATS-sar-net.txt &
                message "done!"
}

function getuserenv()
{
    message "Fetching install user environment"
    infoheader "Install User" >> $APPD_INSTALL_USER_ENV
    echo $APPD_CONTROLLER_INSTALL_USER >> $APPD_INSTALL_USER_ENV
    if [ "$ROOT_MODE" -eq 1 ]; then
        infoheader "ulimits" >> $APPD_INSTALL_USER_ENV
        sudo --non-interactive su - $APPD_CONTROLLER_INSTALL_USER -c "ulimit -a" >> $APPD_INSTALL_USER_ENV
        infoheader "Runtime environment variables" >> $APPD_INSTALL_USER_ENV
        sudo --non-interactive su - $APPD_CONTROLLER_INSTALL_USER -c "set -o posix; set" >> $APPD_INSTALL_USER_ENV
    else
        infoheader "ulimits" >> $APPD_INSTALL_USER_ENV
        ulimit -a >> $APPD_INSTALL_USER_ENV
        infoheader "Runtime environment variables" >> $APPD_INSTALL_USER_ENV
        # to avoid side-effects, we're running set in sub-shell
        (set -o posix; set)>> $APPD_INSTALL_USER_ENV
    fi
}

function prepare_wkdir()
{
    _WKDIR=$(mktemp -d ${WKDIR}.XXXXXX || err "Could not create working directory $WKDIR")
    WKDIR=$_WKDIR
    cd $WKDIR
}

#
# Run after appd_variables()
#
function prepare_report_path()
{
    # we check the list of APP_<component>_HOME vars ordered by below priority
    for component_home in APPD_EC_HOME APPD_CONTROLLER_HOME APPD_EUM_HOME APPD_ES_HOME; do
        # referring to name of the variable by an indirection variable
        if [ -d "${!component_home}" ]; then
            local _component_report_path="${!component_home}/logs/support-report"
            # building component user/group variable names by replacing var name suffix
            # i.e. APPD_COMPONENT_HOME => APPD_COMPONENT_INSTALL_USER
            local _component_user_var=${component_home/%_HOME/_INSTALL_USER}
            local _component_group_var=${component_home/%_HOME/_INSTALL_GROUP}
            break
        fi
    done

    if [ -n "$OPT_REPORT_PATH" ]; then
        REPORT_PATH="${OPT_REPORT_PATH}"
        REPORT_USER=$(whoami)
        REPORT_GROUP=$(id -gn $REPORT_USER)
    elif [ -n "$_component_report_path" ]; then
        REPORT_PATH="$_component_report_path"
        # getting real values from indirect vars
        REPORT_USER="${!_component_user_var}"
        REPORT_GROUP="${!_component_group_var}"
    fi
    # else will keep default ${PWD}/support-report/
    log_message "Report will be saved to $REPORT_PATH"

    if [ ! -d $REPORT_PATH ]; then
        mkdir -p $REPORT_PATH
        chown ${REPORT_USER}:${REPORT_GROUP} ${REPORT_PATH}
    fi

    [ -d $REPORT_PATH ] || err "Could not create report directory $REPORT_PATH"
    [ -w $REPORT_PATH ] || err "Could write to report directory $REPORT_PATH. Check permissions."
}

function check_user()
{
    RUN_AS=$(whoami)
    case "$RUN_AS" in
        $ROOT_USER)
            ROOT_MODE=1
            ;;
        $APPD_CONTROLLER_INSTALL_USER|$APPD_EC_INSTALL_USER|$APPD_EUM_INSTALL_USER|$APPD_ES_INSTALL_USER)
            ROOT_MODE=0
            warning  "You should run this script as root. Only limited information will be available in report."
            ;;
        *)
            err "You must run this tool as root or as the same user who is running appd processes"
            ;;
    esac
}

function get_selinux_info()
{
    message "Getting selinux config"
    echo -en "=================================\nsestatus\n---------------------------------\n" >> $SELINUX_INFO
    echo -e "$(sestatus)" >> $SELINUX_INFO
    echo >> $SELINUX_INFO
    echo -en "=================================\n/etc/selinux/config\n---------------------------------\n" >> $SELINUX_INFO
    echo -e "$(cat /etc/selinux/config)\n" >> $SELINUX_INFO
    echo -en "=================================\n/etc/sestatus.conf\n---------------------------------\n" >> $SELINUX_INFO
    echo -e "$(cat /etc/sestatus.conf)\n" >> $SELINUX_INFO
}

# ======================================================================================================================
# ========================================= EVENTS SERVICE SECTION =====================================================
# ======================================================================================================================

function get_appd_es_variables() {
	APPD_ES_PID=$(pgrep -f "events-service-api-store")

	if [ -n "$APPD_ES_PID" ]; then
		# ES running.
		log_message "Found events-service PID $APPD_ES_PID"
		APPD_ES_HOME=$(subpath $(readlink /proc/$APPD_ES_PID/cwd) 2)
		APPD_ES_JAVA_HOME=$(subpath $(readlink /proc/$APPD_ES_PID/exe) 3)
	else
		# events-service is not running.
		log_warning "Could not find running events-service instance!"

        find_predicted_dirs
        if [ $ORCHA_NOT_FOUND -eq 1 ]; then
            # real live scenario - multiple directory backups with previous EC versions, before upgrade. Lets pick most recent version (determined by last access)
            local _dirlist=$(find / -name "events-service.sh" -print 2>/dev/null)
        else
            local _dirlist=$(find $PREDICTED_APPD_DIRS -name "events-service.sh" -print 2>/dev/null)
        fi

		local _dir
		for i in $_dirlist; do
			if [[ $i == */processor/* ]]; then
				_dir="$i"
				break
			fi
		done
		APPD_ES_HOME=$(subpath $_dir 4)
        APPD_ES_JAVA_HOME=$(find_java_home)

	fi

	# if the APPD_ES_HOME was found, set the ES_INSTALLED to 1 otherwise exit the function
	if [ -n "$APPD_ES_HOME" ]; then
        ES_INSTALLED=1
    else
		warning "No Events Service installation was found on this host."
		return 1
	fi

	APPD_ES_INSTALL_USER=$(stat -c %U $APPD_ES_HOME/processor)
	if id -u $APPD_ES_INSTALL_USER >/dev/null 2>&1; then
		APPD_ES_INSTALL_GROUP=$(id -gn $APPD_ES_INSTALL_USER)
	else
		APPD_ES_INSTALL_USER=${ROOT_USER}
		APPD_ES_INSTALL_GROUP=${ROOT_GROUP}
	fi

	mkdir $APPD_ES
	echo APPD_ES_HOME $APPD_ES_HOME
	echo APPD_ES_JAVA_HOME $APPD_ES_JAVA_HOME
	echo APPD_ES_PID $APPD_ES_PID
	echo APPD_ES_INSTALL_USER $APPD_ES_INSTALL_USER
	echo APPD_ES_INSTALL_GROUP $APPD_ES_INSTALL_GROUP
}

function get_appd_es_environment()
{
  message "Checking Events Service environment"
    if [ -n "$APPD_ES_PID" ]; then
        echo -e "\n---------- Events Service Java PID ---------- " >> $APPD_ES_JAVAINFO
        echo $APPD_ES_PID >> $APPD_ES_JAVAINFO
        echo -e "\n---------- Events Service Java version ---------- " >> $APPD_ES_JAVAINFO
		/proc/$APPD_ES_PID/exe -version >> $APPD_ES_JAVAINFO 2>&1
	 	echo -e "\n---------- Events Service Java limits ---------- " >> $APPD_ES_JAVAINFO
		cat /proc/$APPD_ES_PID/limits >> $APPD_ES_JAVAINFO
	 	echo -e "\n---------- Events Service Java status ---------- " >> $APPD_ES_JAVAINFO
		cat /proc/$APPD_ES_PID/status >> $APPD_ES_JAVAINFO
	 	echo -e "\n---------- Events Service Java scheduler stats ---------- " >> $APPD_ES_JAVAINFO
		 # use the source, Luke! 	kernel/sched/debug.c
		cat /proc/$APPD_ES_PID/sched >> $APPD_ES_JAVAINFO
	else
        echo -e "Events Service Java process is not running." >> $APPD_ES_JAVAINFO
	fi
}

function get_es_logs() {
	message "Events Service logs"
	[ -d "$ESLOGS" ] || mkdir $ESLOGS

	for f in $(find $APPD_ES_HOME/processor/logs -name "*.log" -o -name "*.log.?.current" -type f); do
		if checkfilesize $f $MAX_FILE_SIZE; then
			tail -c $MAX_FILE_SIZE $f >"$ESLOGS/$(basename $f)"
		else
			cp $f $ESLOGS
		fi
	done

	message "Collecting rotating logs from $DAYS days"
	find $APPD_ES_HOME/processor/logs -name "*.log*" -mtime -$DAYS -exec cp -a {} $ESLOGS \;
}

function get_es_configs() {
	message "Events Service configs"
	[ -d "$ESCONFIGS" ] || mkdir $ESCONFIGS
	find $APPD_ES_HOME/processor/conf -name "*.*" -exec cp -a {} $ESCONFIGS \;
	find $APPD_ES_HOME/processor/elasticsearch/config -name "*.*" -exec cp -a {} $ESCONFIGS \;
}

function get_es_keystore_info()
{
	message "Events Service Keystore content"
    echo -e "\n---------- Events Service Keystore content ---------- " >> $APPD_ES_CERTS
	$APPD_ES_JAVA_HOME/bin/keytool -list --storepass "changeit" -rfc  -keystore ${APPD_ES_JAVA_HOME}/lib/security/cacerts >> $APPD_ES_CERTS
	$APPD_ES_JAVA_HOME/bin/keytool -list --storepass "changeit" -v  -keystore ${APPD_ES_JAVA_HOME}/lib/security/cacerts >> $APPD_ES_CERTS
}

#
# Function to collect Elasticsearch and Events Service diagnostic outputs
# Works in case the Events Service process is running
function get_es_queries() {
	local _http_enabled=$(awk -F'=' '/ad.es.node.http.enabled/ {print $2}' $APPD_ES_HOME/processor/conf/events-service-api-store.properties)
	local _http_port=$(awk -F'=' '/ad.es.node.http.port/ {print $2}' $APPD_ES_HOME/processor/conf/events-service-api-store.properties)
	local _admin_port=$(awk -F'=' '/ad.dw.http.adminPort/ {print $2}' $APPD_ES_HOME/processor/conf/events-service-api-store.properties)
	[ -n "$APPD_ELASTICSEARCH_QUERIES" ] || touch $APPD_ELASTICSEARCH_QUERIES
	if [[ -n $APPD_ES_PID && $_http_enabled == 'true' ]]; then
		message "HTTP port is enabled, collecting diagnostic outputs"
		while read cmd; do
			infoheader "$cmd" >> $APPD_ELASTICSEARCH_QUERIES
			$cmd >> $APPD_ELASTICSEARCH_QUERIES
		done <<EOF
http_query http://localhost:${_http_port}/_cat/health?v
http_query http://localhost:${_http_port}/_cat/nodes?v
http_query http://localhost:${_http_port}/_cat/indices?v
http_query http://localhost:${_http_port}/_cat/aliases?v
http_query http://localhost:${_http_port}/_cat/shards?v
http_query http://localhost:${_http_port}/_cat/allocation?v
http_query http://localhost:${_http_port}/appdynamics_accounts/_search?pretty=true
http_query http://localhost:${_http_port}/appdynamics_accounts_v2/_search?pretty=true
http_query http://localhost:${_http_port}/event_type_metadata/event_type_metadata/_search?pretty=true
http_query http://localhost:${_http_port}/_cat/thread_pool?v
http_query http://localhost:${_admin_port}/healthcheck?pretty=true
EOF
	elif [[ -n "$APPD_ES_PID" && "$_http_enabled" != 'true' ]]; then
		message "HTTP port is disabled, collecting healthcheck only"
		infoheader "Healthcheck" >> $APPD_ELASTICSEARCH_QUERIES
		http_query "http://localhost:$_admin_port/healthcheck?pretty=true" >> $APPD_ELASTICSEARCH_QUERIES
	else 
		message "Events service is not running. Not able to collect diagnostic outputs."
		echo -en "The Events Service process wasn't running, not able to run queries" >> $APPD_ELASTICSEARCH_QUERIES
	fi
}

function get_es_info()
{
	message "Events Service related information"
	echo -e "\n---------- Events Service version information from version file ---------- " >> $APPD_ES_INFO
	cat $APPD_ES_HOME/processor/version.txt >> $APPD_ES_INFO
}

# ======================================================================================================================
# ========================================= EUM SECTION ================================================================
# ======================================================================================================================

function get_appd_eum_variables() {
    APPD_EUM_PID=$(pgrep -f "eum-processor")
    APPD_EUM_MYSQL_PID=$(ps xau | grep "[m]ysql/bin/mysqld" | grep 3388 | awk '{print $2}')

    # If MySQL PID is not located under this path, this can indicate that the DEMO EUM server installed and it is
    # sharing the MySQL with the Controller on the same host. So looking for MySQL instance there:
    if [[ -n "$APPD_EUM_PID" && "$CONTROLLER_INSTALLED" -eq 1 ]]; then
        echo -e "\nWARNING: Demo or inappropriate installation identified (Controller + EUM on the same host)!" >> $APPD_EUM_MYSQLINFO 
        if [ -z "$APPD_EUM_MYSQL_PID" ]; then # EUM MySQL engine is same as Controller, just different schema (EUM Demo)
	        APPD_EUM_MYSQL_HOME=$APPD_CONTROLLER_MYSQL_HOME
        fi
    fi
    # but still we have MySQL EUM running and confirmed it is correct MySQL, lets determine correct path
    if [ -n "$APPD_EUM_MYSQL_PID" ]; then
        APPD_EUM_MYSQL_HOME=$(sed -e 's/.*--basedir=//' -e 's/\x0--.*$//' /proc/$APPD_EUM_MYSQL_PID/cmdline)
    fi


	if [ -n "$APPD_EUM_PID" ]; then
		# EUM is running.
		log_message "Found EUM PID $APPD_EUM_PID"
		APPD_EUM_HOME=$(subpath $(readlink /proc/$APPD_EUM_PID/cwd) 2)
		APPD_EUM_JAVA_HOME=$(subpath $(readlink /proc/$APPD_EUM_PID/exe) 3)
        [ -z "$APPD_EUM_MYSQL_HOME" ] && APPD_EUM_MYSQL_HOME=$(subpath $(readlink /proc/$APPD_EUM_MYSQL_PID/exe) 3)
    elif [ -n "$APPD_EUM_MYSQL_PID" ]; then
        # appserver not running, but we still got mysql, easy thing
        log_message "Found EUM mysqld PID $APPD_EUM_MYSQL_PID"
        log_warning "EUM apparently not running, but mysql is still up"
        # in /proc/$pid/cmdline args are oddly separated with NULL (\x0)
        # first substitution cuts all from line beginning up to --basedir=
        # second one cuts everything after subsequent NULL separator
        # what's left is mysql basedir path, we're looking for
        [ -z "$APPD_EUM_MYSQL_HOME" ] && APPD_EUM_MYSQL_HOME=$(sed -e 's/.*--basedir=//' -e 's/\x0--.*$//' /proc/$APPD_EUM_MYSQL_PID/cmdline)
        # if EUM is not running, but mysqld is up we can figure out paths differently
        APPD_EUM_HOME=$(subpath $APPD_EUM_MYSQL_HOME 2)
	else
		# Neither EUM nor MySQL are running.
		log_warning "Could not find running EUM server instance!"
        find_predicted_dirs
        if [ $ORCHA_NOT_FOUND -eq 1 ]; then
            local _dir=$(find / -name "eum.sh" -print 2>/dev/null)
        else
            local _dir=$(find $PREDICTED_APPD_DIRS -name "eum.sh" -print 2>/dev/null)
        fi
		APPD_EUM_HOME=$(subpath $_dir 4)
	fi
    [ -z "$APPD_EUM_JAVA_HOME" ] && APPD_EUM_JAVA_HOME=$(find_java_home)
    # Mysql home is derivative from EUM home folder:
    [ -z "$APPD_EUM_MYSQL_HOME" ] && APPD_EUM_MYSQL_HOME="${APPD_EUM_HOME}/mysql"
    APPD_EUM_MYSQL_VERSION=$(${APPD_EUM_MYSQL_HOME}/bin/mysqld --version | sed -ne 's/[^0-9]*\(\([0-9]\.\)\{0,4\}[0-9][^.]\).*/\1/p')

	# if the APPD_EUM_HOME was found, set the EUM_INSTALLED to 1 otherwise exit the function
	if [ -n "$APPD_EUM_HOME" ]; then
        EUM_INSTALLED=1
    else
		warning "No EUM server installation was found on this host."
		return 1
	fi

	APPD_EUM_INSTALL_USER=$(find_entry_in_mysql_dbconf "eum" "user")
	if id -u $APPD_EUM_INSTALL_USER >/dev/null 2>&1; then
		APPD_EUM_INSTALL_GROUP=$(id -gn $APPD_EUM_INSTALL_USER)
	else
		APPD_EUM_INSTALL_USER=${ROOT_USER}
		APPD_EUM_INSTALL_GROUP=${ROOT_GROUP}
	fi
    APPD_EUM_DB_INSTALL_PORT=$(find_entry_in_mysql_dbconf "eum" "port")
    if [ -z "${APPD_EUM_DB_INSTALL_PORT}" ] ; then
        APPD_EUM_DB_INSTALL_PORT=${MYSQL_PORT}
    fi

    # variables for custom paths to EUM mysql log files:
    APPD_EUM_MYSQL_ERR_LOG=$(find_entry_in_mysql_dbconf "eum" "log-error")
    APPD_EUM_MYSQL_SLOWLOG=$(find_entry_in_mysql_dbconf "eum" "slow_query_log_file")

    # variable for a custom path to EUM mysql "data" directory:
    APPD_EUM_MYSQL_DATADIR=$(find_entry_in_mysql_dbconf "eum" "datadir")

	mkdir $APPD_EUM
	echo APPD_EUM_HOME $APPD_EUM_HOME
	echo APPD_EUM_JAVA_HOME $APPD_EUM_JAVA_HOME
	echo APPD_EUM_MYSQL_HOME $APPD_EUM_MYSQL_HOME
	echo APPD_EUM_PID $APPD_EUM_PID
    echo APPD_EUM_MYSQL_DATADIR $APPD_EUM_MYSQL_DATADIR
    echo APPD_EUM_MYSQL_PID $APPD_EUM_MYSQL_PID
    echo APPD_EUM_INSTALL_USER $APPD_EUM_INSTALL_USER
    echo APPD_EUM_DB_INSTALL_PORT $APPD_EUM_DB_INSTALL_PORT
}

function get_appd_eum_environment() {
  message "Checking EUM environment"
    if [ -n "$APPD_EUM_PID" ]; then
        echo -e "\n---------- EUM Java PID ---------- " >> $APPD_EUM_JAVAINFO
        echo $APPD_EUM_PID >> $APPD_EUM_JAVAINFO
        echo -e "\n---------- EUM Java version ---------- " >> $APPD_EUM_JAVAINFO
		/proc/$APPD_EUM_PID/exe -version >> $APPD_EUM_JAVAINFO 2>&1
	 	echo -e "\n---------- EUM Java limits ---------- " >> $APPD_EUM_JAVAINFO
		cat /proc/$APPD_EUM_PID/limits >> $APPD_EUM_JAVAINFO
	 	echo -e "\n---------- EUM Java status ---------- " >> $APPD_EUM_JAVAINFO
		cat /proc/$APPD_EUM_PID/status >> $APPD_EUM_JAVAINFO
	 	echo -e "\n---------- EUM Java scheduler stats ---------- " >> $APPD_EUM_JAVAINFO
		 # use the source, Luke! 	kernel/sched/debug.c
		cat /proc/$APPD_EUM_PID/sched >> $APPD_EUM_JAVAINFO
	else
        echo -e "EUM Java process is not running." >> $APPD_EUM_JAVAINFO
	fi

    if [ -n "$APPD_EUM_MYSQL_PID" ]; then
	    echo -e "\n---------- EUM MySQL PID ---------- " >> $APPD_EUM_MYSQLINFO
        echo $APPD_EUM_MYSQL_PID >> $APPD_EUM_MYSQLINFO
        echo -e "\n---------- EUM MySQL version ---------- " >> $APPD_EUM_MYSQLINFO
		/proc/$APPD_EUM_MYSQL_PID/exe --version >> $APPD_EUM_MYSQLINFO 2>&1
	 	echo -e "\n---------- EUM MySQL limits ---------- " >> $APPD_CONTROLLER_MYSQLINFO
		cat /proc/$APPD_EUM_MYSQL_PID/limits >> $APPD_EUM_MYSQLINFO
	 	echo -e "\n---------- EUM MySQL status ---------- " >> $APPD_EUM_MYSQLINFO
		cat /proc/$APPD_EUM_MYSQL_PID/status >> $APPD_EUM_MYSQLINFO
	 	echo -e "\n---------- EUM MySQL scheduler stats ---------- " >> $APPD_EUM_MYSQLINFO
		 # use the source, Luke! 	kernel/sched/debug.c
		cat /proc/$APPD_EUM_MYSQL_PID/sched >> $APPD_EUM_MYSQLINFO
		
	else
        echo -e "EUM MySQL process is not running." >> $APPD_EUM_MYSQLINFO
	fi
	# some information about db size and files
	echo -e "\n---------- EUM MySQL files ---------- " >> $APPD_EUM_MYSQLINFO
	ls -la ${APPD_EUM_MYSQL_DATADIR} >> $APPD_EUM_MYSQLINFO
	echo -e "\n---------- EUM MySQL file size ---------- " >> $APPD_EUM_MYSQLINFO		
	du -hs ${APPD_EUM_MYSQL_DATADIR}/* >> $APPD_EUM_MYSQLINFO
}

function get_eum_logs() {
	message "EUM logs"
	[ -d "$EUMLOGS" ] || mkdir $EUMLOGS

	for f in $(find $APPD_EUM_HOME/logs -name "*.log"); do
		if checkfilesize $f $MAX_FILE_SIZE; then
			tail -c $MAX_FILE_SIZE $f >"$EUMLOGS/$(basename $f)"
		else
			$CP_CMD $f $EUMLOGS
		fi
	done

	message "Collecting rotating logs from $DAYS days"
	find $APPD_EUM_HOME/logs -name "*.log*" -o -name "*.txt" -mtime -$DAYS -exec cp -a {} $EUMLOGS \;
}

function get_eum_mysq_logs()
{
    message "Mysql EUM logs"
    [ -d $EUMMYSQLLOGS ] || mkdir $EUMMYSQLLOGS
    for f in $APPD_EUM_MYSQL_ERR_LOG $APPD_EUM_MYSQL_SLOWLOG; do
        if checkfilesize $f $MAX_FILE_SIZE; then
            tail -c $MAX_FILE_SIZE $f > "$EUMMYSQLLOGS/$(basename $f)"
        else
            $CP_CMD $f $EUMMYSQLLOGS
        fi
    done
}

function get_eum_configs() {
	message "EUM configs"
	[ -d "$EUMCONFIGS" ] || mkdir $EUMCONFIGS
	find $APPD_EUM_HOME/eum-processor/conf -name "*.*" -exec cp -a {} $EUMCONFIGS \;
    find $APPD_EUM_HOME/mysql -name "*.cnf" -exec cp -a {} $EUMCONFIGS \;
	find $APPD_EUM_HOME/eum-processor/bin \( -name "*.properties" -o -name "*.xml" -o -name "*.vmoptions" \) -exec cp -a {} $EUMCONFIGS \;
}

# returns value from the eum.properties configuration file
# $1 parameter receives the key string (eg. "processorServer.httpPort")
function get_eum_property()
{
    echo $(awk -v var="$1" -F'=' '$0 ~ var  {print $2}' $APPD_EUM_HOME/eum-processor/bin/eum.properties)
}

function get_eum_keystore_info() {
	message "EUM Keystore content"
    echo -e "\n---------- EUM Keystore content ---------- " >> $APPD_EUM_CERTS
	$APPD_EUM_JAVA_HOME/bin/keytool -list --storepass "changeit" -rfc  -keystore ${APPD_EUM_JAVA_HOME}/lib/security/cacerts >> $APPD_EUM_CERTS
	$APPD_EUM_JAVA_HOME/bin/keytool -list --storepass "changeit" -v  -keystore ${APPD_EUM_JAVA_HOME}/lib/security/cacerts >> $APPD_EUM_CERTS
}

function get_eum_info()
{
	message "EUM related information"
	if [ -n "$APPD_EUM_PID" ]; then
    local _http_port=$(get_eum_property "processorServer.httpPort")
        echo -e "\n---------- EUM server version information from API ---------- " >> $APPD_EUM_INFO
        echo -e "------- get-version"  >> $APPD_EUM_INFO
        http_query "http://localhost:$_http_port/eumcollector/get-version" >> $APPD_EUM_INFO
        echo -e "\n------- ping"  >> $APPD_EUM_INFO        
        http_query "http://localhost:$_http_port/eumcollector/ping" >> $APPD_EUM_INFO
        echo -e "\n------- whoami"  >> $APPD_EUM_INFO        
	http_query "http://localhost:$_http_port/eumcollector/whoami" >> $APPD_EUM_INFO
        echo -e "\n------- beacons"  >> $APPD_EUM_INFO	
	http_query "http://localhost:$_http_port/eumcollector/beacons" >> $APPD_EUM_INFO
    else
        echo -e "\n---------- EUM server version information from version file ---------- " >> $APPD_EUM_INFO
        cat $APPD_EUM_HOME/README.txt >> $APPD_EUM_INFO
    fi
}

function get_eum_mysql_data()
{
    message "Collecting EUM SQL queries"

    if [ $HAVE_ACCESS_TO_EUM_DB -eq 0 ]; then
        echo -e "No access to EUM DB, or MySQL process is not running." >> $APPD_EUM_QUERIES
        return 1
    fi
    echo -e "\n---------- EUM DB Information ---------- " >> $APPD_EUM_QUERIES

    while read query; do
    # redirect both stderr and stdout to capture exact error
    mysql_exec "$query" "eum" &>> $APPD_EUM_QUERIES
    # WARNING! in queries use only single quotes and escape "\" with \\
    done <<EOF
SELECT version() mysql_version;
status;
show status like 'Conn%';
SELECT * FROM account_credential\\\G;
SELECT * FROM accounts\\\G;
SELECT table_schema as 'Database', table_name AS 'Table', round(((data_length + index_length) / 1024 / 1024), 2) 'Size in MB' FROM information_schema.TABLES  ORDER BY table_schema, (data_length + index_length) DESC;
show status;
EOF
}

# used as a fallback function to locate Java for ES and EUM installations
function find_java_home() {
    # as a process relies on JAVA_HOME variable to get the JRE for the process, will get the path from there
	if [ -n "$JAVA_HOME" ] && [ -x "$JAVA_HOME/bin/java" ]; then
        echo "$JAVA_HOME"
    # elsewise we look for system-wide java
    elif [ -x "$SYS_JAVA" ]; then
        local _sys_java_realpath=$(readlink -f $SYS_JAVA)
        echo ${_sys_java_realpath%/bin/java}
    # last resort, fallback to EC java
    else
        echo $APPD_EC_JAVA_HOME
    fi
}


#########################
# START MAIN
#########################

while getopts "acefpwlzxCEUSvd:P:o:" opt; do
        case $opt in
                a  )    GETCONTROLLERLOGS=0
                                ;;
                c  )    GETCONFIG=0
                                ;;
                e  )    ENCRYPT=1
                                ;;
                f  )    GETOPENFILES=1
                                ;;
                p  )    GETLOAD=1
                                ;;
                w  )    GETHARDWARE=0
                                ;;
                l  )    GETSYSLOGS=0
                                ;;
                z  )    ZIPREPORT=0
                                ;;
                d  )    DAYS=$OPTARG
                        SYSLOGDAYS=$OPTARG
                                ;;
                o  )    OPT_REPORT_PATH=$OPTARG
                                ;;
                x  )    DEBUG=1
                                ;;
                P  )    CONTROLLER_MYSQL_PASSWORD=$OPTARG
                                ;;
                C  )    SEARCH_CONTROLLER=1
                        SEARCHED_COMPONENTS+=("controller")
                                ;;
                E  )    SEARCH_EC=1
                        SEARCHED_COMPONENTS+=("ec")
                                ;;
                U  )    SEARCH_EUM=1
                        SEARCHED_COMPONENTS+=("eum")
                                ;;
                S  )    SEARCH_ES=1
                        SEARCHED_COMPONENTS+=("es")
                                ;;
                v  )    version
                                ;;
                *  )    usage
                                ;;
        esac
done

# Default mode without options given is controller
if [ ${#SEARCHED_COMPONENTS[@]} -eq 0 ]; then
    SEARCH_CONTROLLER=1
    SEARCHED_COMPONENTS=("controller")
fi


# dont allow to run more than one report collection at once
lock || err "Generation of support report in progress. Exiting."

# Welcome message
message "Determining system environment and configuration..."

# Setup work environment
find_wkdir
prepare_wkdir
prepare_paths
getlinuxflavour
[ $SEARCH_CONTROLLER -eq 1 ] && appd_variables
[ $SEARCH_EC -eq 1 ] && appd_EC_variables
[ $SEARCH_ES -eq 1 ] && get_appd_es_variables
[ $SEARCH_EUM -eq 1 ] && get_appd_eum_variables
# we need to know appd user already
check_user
prepare_report_path
[ $CONTROLLER_INSTALLED -eq 1 ] && get_mysql_password "controller"
[ $CONTROLLER_INSTALLED -eq 1 ] && get_controller_root_password
[ $EUM_INSTALLED -eq 1 ] && get_mysql_password "eum"
reportheader


# collect reports
[ $GETSYSTEM -eq 1 ] && getsystem
[ $GETVM -eq 1 ] && gethypervisor
[ $GETHARDWARE -eq 1 ] && gethardware
[ $GETMEMORY -eq 1 ] && getmemory
[ $GETSTORAGE -eq 1 ] && getstorage
[ $GETOPENFILES -eq 1 ] && getopenfiles
[ $GETSYSLOGS -eq 1 ] && getsyslogs
[ $GETSYSTEMD -eq 1 ] && getsystemd
[ $GETNETCONF -eq 1 ] && getnetconf
[ $GETINIINFO -eq 1 ] && getinitinfo
[ $GETTIMECONFIG -eq 1 ] && gettimeconfig
[ $GETAPPD -eq 1 ] && appd_getenvironment
[ $GETNUMA -eq 1 ] && getnumastats
[ $GETLOAD -eq  1 ] && getloadstats
[ $GETUSERENV -eq 1 ] && getuserenv
[ $GETPROCESSES -eq  1 ] && getprocesses
[ $GETTOP -eq  1 ] && gettop
[ $GETFILELIST -eq 1 ] && getfilelist
[ $GETSESTATUS -eq 1 ] && get_selinux_info

[[ $GETCONTROLLERLOGS -eq 1 && $CONTROLLER_INSTALLED -eq 1 ]] && getcontrollerlogs
[[ $GETCONTROLLERMYSQLLOGS -eq 1 && $CONTROLLER_INSTALLED -eq 1 ]] && getmysqlcontrollerlogs
[[ $GETCONTROLLERCONFIGS -eq 1 && $CONTROLLER_INSTALLED -eq 1 ]] && getcontrollerconfigs
[[ $GETECLOGS -eq 1 && $EC_INSTALLED -eq 1 ]] && getEClogs
[[ $GETECMYSQLLOGS -eq 1 && $EC_INSTALLED -eq 1 ]] && getmysqlEClogs
[[ $GETECCONFIGS -eq 1 && $EC_INSTALLED -eq 1 ]] && getECconfigs
[[ $GETCERTSINFO -eq  1 && $CONTROLLER_INSTALLED -eq 1 ]] && get_keystore_info
[[ $GETMYSQLQUERIES -eq  1 && $CONTROLLER_INSTALLED -eq 1 ]] && get_controller_mysql_data
[[ $GETCONTROLLERINFO -eq 1 && $CONTROLLER_INSTALLED -eq 1 ]] && getcontrollerinfo
[[ $GETCONTROLLERREPORT -eq 1 && $CONTROLLER_INSTALLED -eq 1 ]] && getcontrollerreport
[[ $GETHAINFO -eq 1 &&  $CONTROLLER_INSTALLED -eq 1 ]] && gethainfo

# ------- EVENTS SERVICE SECTION --------------
[[ $ES_INSTALLED -eq 1 ]] && get_es_info
[[ $GETAPPD -eq 1 && $ES_INSTALLED -eq 1 ]] && get_appd_es_environment
[[ $GETESLOGS -eq 1 && $ES_INSTALLED -eq 1 ]] && get_es_logs
[[ $GETESCONFIGS -eq 1 && $ES_INSTALLED -eq 1 ]] && get_es_configs
[[ $GETCERTSINFO -eq 1 && $ES_INSTALLED -eq 1 ]] && get_es_keystore_info
[[ $GETESQUERIES -eq 1 && $ES_INSTALLED -eq 1 ]] && get_es_queries

# --------------- EUM SECTION -------------------
[[ $EUM_INSTALLED -eq 1 ]] && get_eum_info
[[ $GETAPPD -eq 1 && $EUM_INSTALLED -eq 1 ]] && get_appd_eum_environment
[[ $GETEUMLOGS -eq 1 && $EUM_INSTALLED -eq 1 ]] && get_eum_logs
[[ $GETEUMCONFIGS -eq 1 && $EUM_INSTALLED -eq 1 ]] && get_eum_configs
[[ $GETCERTSINFO -eq 1 && $EUM_INSTALLED -eq 1 ]] && get_eum_keystore_info
[[ $GETEUMMYSQLLOGS -eq 1 && $EUM_INSTALLED -eq 1 ]] && get_eum_mysq_logs
[[ $GETMYSQLQUERIES -eq  1 && $EUM_INSTALLED -eq 1 ]] && get_eum_mysql_data

# Make all report files readable
chmod -R a+rX $WKDIR

# iostat and family are running in background, output is needed before we pack the archive
for job in `jobs -p`
do
message "waiting for job $job to finish..."
    wait $job 
done

log_variables
if [ $ZIPREPORT -eq 1 ]; then
    message -n "Creating report archive... "
    REPORT=$(zipreport)
    message "Done "
    ARTEFACT=${REPORTFILE}
    if [ $ENCRYPT -eq 1 ]; then
        message -n "Encrypting archive... "
        encryptreport
        if [ $? -eq 0 ]; then    
            ARTEFACT=${REPORTFILE}.enc
        fi
    fi
    message
    message "The support-report has been saved to:"
    message "   ${REPORT_PATH}/${ARTEFACT}"

    message "You will be directed where to submit this report by your technical support contact."
    message
else
    CLEANUP_WKDIR=0
    message -e "\nReport located in $WKDIR"
fi

clean_after_yourself
unlock

exit 0

#########################
# END MAIN
#########################
