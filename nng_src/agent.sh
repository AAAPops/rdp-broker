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
	xrdpX_count=$(find /var/run/xrdp/sockdir/ | grep -c xrdp_display)
    srv_la=$(($xrdpX_count * 3))
    [ $srv_la -gt 100 ] && srv_la=100
    echo "$srv_la"
    ;;

  checkUser )
	if [ ! $(id -u $cmd_UserName 2>/dev/null) ]; then
		echo "-1"
		exit 0
	fi  
  
	user_id=$(id -u $cmd_UserName)
	test=$(find /var/run/xrdp/sockdir/$user_id/ -name xrdp_display_* 2>/dev/null)
	if [ $(echo $test | grep -c xrdp_display) -eq 1 ]; then 
		echo "1"
	else
		echo "0"
	fi
    ;;

  getJobTime )
	if [ ! $(id -u $cmd_UserName 2>/dev/null) ]; then
		echo "0"
		exit 0
	fi  
  
	user_id=$(id -u $cmd_UserName)
	test=$(find /var/run/xrdp/sockdir/$user_id/ -name xrdp_display_* 2>/dev/null)
	if [ $(echo $test | grep -c xrdp_display) -eq 1 ]; then 
		work_time=$(find $test -printf "%T@\n" | awk '{print int(systime() - $1)}')		
		echo "$work_time"
	else
		echo "0"
	fi
    ;;

  *)
    echo "0"
    ;;
esac
