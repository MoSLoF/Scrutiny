#!/bin/bash
rm -f /tmp/scrutiny_proc.out /tmp/scrutiny_target.pid
cd /mnt/d/06-WORKSPACE/GitHub/MoSLoF/Scrutiny
bin/targetProc2 > /tmp/scrutiny_proc.out 2>&1 &
echo $! > /tmp/scrutiny_target.pid
sleep 2
