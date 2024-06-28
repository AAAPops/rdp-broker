#!/bin/bash
# username, [getSrvLA | checkUser | getJobTime], [srv1 | srv2]
#echo "bash args: \"$@\""

cmd_UserName=$1
cmd_Selector=$2
cmd_SrvIdx=$3

if [ "$cmd_SrvIdx" ==  "srv1" ]; then
  userList="/A-build/nng-demo/rdp-broker/user-list-1.txt"
else
  userList="/A-build/nng-demo/rdp-broker/user-list-2.txt"
fi

case $cmd_Selector in
  getSrvLA )
    echo $(($(cat $userList | wc -l) * 5))
    ;;

  checkUser )
    echo $(cat "$userList" | grep -c -w $cmd_UserName)
    ;;

  getJobTime )
    tmp_str=$(cat "$userList" | grep -w $cmd_UserName )
    [ -n "$tmp_str" ] && echo "$(echo $tmp_str | cut -d ':' -f2)" || echo 0
    ;;

  *)
    STATEMENTS
    ;;
esac
