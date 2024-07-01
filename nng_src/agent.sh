#!/bin/bash
# username, [getSrvLA | checkUser | getJobTime]
#echo "bash args: \"$@\""

cmd_UserName=$1
cmd_Selector=$2
#cmd_SrvIdx=$3

#if [ "$cmd_SrvIdx" ==  "srv1" ]; then
#  userList="/A-build/nng-demo/rdp-broker/user-list-1.txt"
#else
#  userList="/A-build/nng-demo/rdp-broker/user-list-2.txt"
#fi

case $cmd_Selector in
  getSrvLA )
	sesman_count=$(ps -ef | grep -c [x]rdp-sesman)
    srv_la=$(($sesman_count * 3))
    [ $srv_la -gt 100 ] && srv_la=100
    echo "$srv_la"
    ;;

  checkUser )
	for sesman_pid in $(ps -ef | grep [x]rdp-sesman | awk '{print $2}')
	do
		xrdp_session_exist=$(ps -ef | grep $sesman_pid | grep Xorg | awk '{print $1}' | grep -w -c $cmd_UserName)
		if [ $xrdp_session_exist -eq 1 ]; then
			echo "1"
			exit 0
		fi
	done
	
	echo "0"
    ;;

  getJobTime )
	for sesman_pid in $(ps -ef | grep [x]rdp-sesman | awk '{print $2}')
	do
		xrdp_session_exist=$(ps -ef | grep $sesman_pid | grep Xorg | awk '{print $1}' | grep -w -c $cmd_UserName)
		if [ $xrdp_session_exist -eq 1 ]; then
			xorg_pid=$(ps -ef | grep $sesman_pid | grep $cmd_UserName | grep Xorg | awk '{print $2}')
			work_time=$(ps -o etimes= -p $xorg_pid | tr -d " ")		
			echo "$work_time"
			exit 0
		fi
	done

	echo "0"
    ;;

  *)
    STATEMENTS
    ;;
esac
