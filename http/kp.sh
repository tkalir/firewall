#!/bin/bash
get_pid()
{
ret=$(sudo netstat -tulnp | grep $1| awk '{ print $7}'| sed "s/[/]/ /g" | awk '{ print $1}')
kill -9 $ret
}

get_pid $1

