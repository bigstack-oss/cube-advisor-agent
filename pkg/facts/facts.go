// Package facts holds the script that reads a node's inventory facts. The
// Advisor runs it in the read sandbox on a node with an agent, and host-ro
// facts runs it on a peer without one, so both report the same sections.
package facts

// Script prints each section under its own "##name" line (output may end
// without a newline), so a missing file leaves only its own section empty.
const Script = `printf '\n##version\n'; cat /etc/version 2>/dev/null
printf '\n##role\n'; sed -n 's/^cubesys\.role *= *//p' /etc/settings.txt 2>/dev/null
printf '\n##hostname\n'; sed -n 's/^net\.hostname *= *//p' /etc/settings.txt 2>/dev/null
printf '\n##cpu\n'; sed -n 's/^model name[[:space:]]*: *//p' /proc/cpuinfo | head -n1
printf '\n##cores\n'; nproc --all
printf '\n##mem\n'; sed -n 's/^MemTotal: *\([0-9]*\) kB/\1/p' /proc/meminfo
printf '\n##disks\n'; lsblk -J -b -d -o NAME,SIZE,ROTA,TYPE 2>/dev/null
printf '\n##cluster\n'; cat /etc/settings.cluster.json 2>/dev/null
printf '\n##fixpack\n'; base64 -w0 /var/appliance-db/fixpack.history 2>/dev/null; echo
printf '\n##up\n'; prom query 'up{job="node"}' 2>/dev/null
printf '\n##settings\n'; grep -E '^cubesys\.(ha|controller|controller\.ip|region) *=' /etc/settings.txt 2>/dev/null
printf '\n##inactive\n'; part=$(sed -n 's/.*BOOT_IMAGE=\/Part\([12]\)\/.*/\1/p' /proc/cmdline)
[ -n "$part" ] || part=$(sed -n "s/^PART\([12]\)_UUID=$(sed -n 's/.* root=UUID=\([^ ]*\).*/\1/p' /proc/cmdline)\$/\1/p" /boot/grub2/grubenv 2>/dev/null)
case "$part" in
  1) sed -n 's/^firmware_version *= *//p' /boot/grub2/info2 2>/dev/null ;;
  2) sed -n 's/^firmware_version *= *//p' /boot/grub2/info1 2>/dev/null ;;
esac`
