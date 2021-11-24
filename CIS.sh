#!/bin/bash

echo "##################################################"
echo "# 1.1.2 - Ensure /tmp is configured in the fstab #"
echo "##################################################"
if !(grep -E '\s/tmp\s' /etc/fstab | grep -E -v '^\s*#'); then
   echo "/dev/sdc1 /tmp ext4 defaults,rw,nosuid,nodev,noexec,relatime 0 0" >>/etc/fstab
   echo $(date) "Se configuro el archivo fstab para la particion tmp" >> /var/log/hardening.log
fi

echo "######################################################"
echo "# 1.1.3 - Ensure noexec option set on /tmp partition #"
echo "######################################################"
if !(cat /etc/fstab | grep /tmp | awk '{ print $4;}' | grep noexec); then
   sed -i "$(cat /etc/fstab | nl | grep /tmp | awk '{ print $1;}')d" /etc/fstab
   echo "/dev/sdc1 /tmp ext4 defaults,rw,nosuid,nodev,noexec,relatime 0 0" >>/etc/fstab
   mount -o remount,noexec /tmp
   echo $(date) "Se detecto que la particion /tmp no contaba con el parametro noexec y se agrego" >> /var/log/hardening.log
fi

echo "######################################################"
echo "# 1.1.4 - Ensure nodev option set on /tmp partition  #"
echo "######################################################"
if !(cat /etc/fstab | grep /tmp | awk '{ print $4;}' | grep nodev); then
   sed -i "$(cat /etc/fstab | nl | grep /tmp | awk '{ print $1;}')d" /etc/fstab
   echo "/dev/sdc1 /tmp ext4 defaults,rw,nosuid,nodev,noexec,relatime 0 0" >>/etc/fstab
   mount -o remount,nodev /tmp
   echo $(date) "Se detecto que la particion /tmp no contaba con el parametro nodev y se agrego" >> /var/log/hardening.log
fi

echo "######################################################"
echo "# 1.1.5 - Ensure nosuid option set on /tmp partition  #"
echo "######################################################"
if !(cat /etc/fstab | grep /tmp | awk '{ print $4;}' | grep nosuid); then
   sed -i "$(cat /etc/fstab | nl | grep /tmp | awk '{ print $1;}')d" /etc/fstab
   echo "/dev/sdc1 /tmp ext4 defaults,rw,nosuid,nodev,noexec,relatime 0 0" >>/etc/fstab
   mount -o remount,nosuid /tmp
   echo $(date) "Se detecto que la particion /tmp no contaba con el parametro nosuid y se agrego" >> /var/log/hardening.log
fi

if !(findmnt -n /tmp); then
    echo $(date) "Particion /tmp no se encuentra montada" >> /var/log/hardening.log
    mount -a
    echo $(date) "Particion /tmp se monto correctamente" >> /var/log/hardening.log
fi

if !(findmnt -n /tmp | grep "noexec") || !(findmnt -n /tmp | grep "nodev") || !(findmnt -n /tmp | grep "nosuid"); then
   echo $(date) "Particion /tmp no cuenta con alguno de los parametros remount,noexec,nodev,nosuid" >> /var/log/hardening.log
   umount /tmp
   mount -a
   echo $(date) "Se monto particion /tmp con los parametros remount,noexec,nodev,nosuid" >> /var/log/hardening.log
fi

echo "########################################################"
echo "#  1.5.1 Ensure core dumps are restricted              #"
echo "########################################################"
if !(cat /etc/security/limits.conf | grep "* hard core 0"); then
    echo "* hard core 0" >> /etc/security/limits.conf
    echo $(date) "Se detecto que el archivo /etc/security/limits.conf no contenia el valor de * hard core 0" >> /var/log/hardening.log
fi

if (cat  /etc/sysctl.conf | grep "fs.suid_dumpable/s*=/s*1"); then
    echo $(date) "Archivo /etc/sysctl.conf tiene establecido fs.suid_dumpable = 1" >> /var/log/hardening.log
    sed -i '/fs.suid_dumpable/s*=/s*1/d' /etc/sysctl.conf
    echo $(date) "Se elimino con exito el parametro fs.suid_dumpable = 1 del archivo /etc/sysctl.conf" >> /var/log/hardening.log 
fi

if !(cat  /etc/sysctl.conf | grep "fs.suid_dumpable/s*=/s*0"); then
    echo $(date) "No fue encontrado fs.suid_dumpable = 0 en el archivo /etc/sysctl.conf" >> /var/log/hardening.log
    echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
    echo $(date) "Se agrego con exito el parametro fs.suid_dumpable = 0 en el archivo /etc/sysctl.conf" >> /var/log/hardening.log
fi

if (sysctl fs.suid_dumpable | grep " =1"); then
    echo $(date) "Se detecto que el parametro del kernel fs.suid_dumpable tiene el valor de 1" >> /var/log/hardening.log
    sysctl -w fs.suid_dumpable=0
    echo $(date) "Se cambio con exito el valor de fs.suid_dumpable a 0" >> /var/log/hardening.log
fi

if !(cat /etc/systemd/coredump.conf | grep "Storage=none"); then
    echo "Storage=none" >> /etc/systemd/coredump.conf
    echo $(date) "Se agrego la linea Storage=none en el archivo /etc/systemd/coredump.conf" >> /var/log/hardening.log
fi
if !(cat /etc/systemd/coredump.conf | grep "ProcessSizeMax=0"); then
    echo "ProcessSizeMax=0" >> /etc/systemd/coredump.conf
    echo $(date) "Se agrego la linea ProcessSizeMax=0 en el archivo /etc/systemd/coredump.conf" >> /var/log/hardening.log
fi

echo "#####################################################"
echo "# 3.1.1 Disable IPv6				                  #"
echo "#####################################################"
if (sysctl net.ipv6.conf.all.disable_ipv6 | grep "= 0") || (sysctl net.ipv6.conf.default.disable_ipv6 | grep "= 0"); then

   if !(cat /etc/sysctl.conf | grep "net.ipv6.conf.all.disable_ipv6\s*=\s*1"); then
      echo $(date) "No se detecto net.ipv6.conf.all.disable_ipv6 = 1 en el archivo /etc/sysctl" >> /var/log/hardening.log
      echo "net.ipv6.conf.all.disable_ipv6 = 1" >>/etc/sysctl.conf
      echo $(date) "Se agrego con exito net.ipv6.conf.all.disable_ipv6 = 1 en el archivo /etc/sysctl" >> /var/log/hardening.log
   fi

   if !(cat /etc/sysctl.conf | grep "net.ipv6.conf.default.disable_ipv6\s*=\s*1"); then
      echo $(date) "No se detecto net.ipv6.conf.default.disable_ipv6 = 1 en el archivo /etc/sysctl" >> /var/log/hardening.log
      echo "net.ipv6.conf.default.disable_ipv6 = 1" >>/etc/sysctl.conf
      echo $(date) "Se agrego con exito net.ipv6.conf.default.disable_ipv6 = 1 en el archivo /etc/sysctl" >> /var/log/hardening.log
   fi
   sysctl -w net.ipv6.conf.all.disable_ipv6=1
   sysctl -w net.ipv6.conf.default.disable_ipv6=1
   sysctl -w net.ipv6.route.flush=1

else
   if !(cat /etc/sysctl.conf | grep "net.ipv6.conf.all.disable_ipv6\s*=\s*1"); then
      echo $(date) "No se detecto net.ipv6.conf.all.disable_ipv6 = 1 en el archivo /etc/sysctl" >> /var/log/hardening.log
      echo "net.ipv6.conf.all.disable_ipv6 = 1" >>/etc/sysctl.conf
      echo $(date) "Se agrego con exito net.ipv6.conf.all.disable_ipv6\s*=\s*1 en el archivo /etc/sysctl" >> /var/log/hardening.log
   fi
   if !(cat /etc/sysctl.conf | grep "net.ipv6.conf.default.disable_ipv6\s*=\s*1"); then
      echo $(date) "No se detecto net.ipv6.conf.default.disable_ipv6 = 1 en el archivo /etc/sysctl" >> /var/log/hardening.log
      echo "net.ipv6.conf.default.disable_ipv6 = 1" >>/etc/sysctl.conf
      echo $(date) "Se agrego con exito net.ipv6.conf.default.disable_ipv6 = 1 en el archivo /etc/sysctl" >> /var/log/hardening.log
   fi
fi

echo "#####################################################"
echo "#    3.2.1 Ensure IP forwarding is disabled         #"
echo "#####################################################"
if (cat /etc/sysctl.conf | grep -E "net.ipv4.ip_forward\s*=\s*1"); then
   echo $(date) "Se detecto net.ipv4.ip_forward con valor de 1 en el archivo /etc/sysctl" >> /var/log/hardening.log
   sed -i '/net.ipv4.ip_forward\s*=\s*1/d' /etc/sysctl.conf
   echo $(date) "Se elimino con exito net.ipv4.ip_forward = 1 del archivo /etc/sysctl" >> /var/log/hardening.log
fi

if !(cat /etc/sysctl.conf | grep -E "net.ipv4.ip_forward\s*=\s*0"); then
   echo $(date) "No se detecto net.ipv4.ip_forward = 0 en el archivo /etc/sysctl" >> /var/log/hardening.log
   echo "net.ipv4.ip_forward = 0" >>/etc/sysctl.conf
   echo $(date) "Se agrego con exito net.ipv4.ip_forward = 0 en el archivo /etc/sysctl" >> /var/log/hardening.log
fi

if (sysctl net.ipv4.ip_forward | grep "= 1"); then
   echo $(date) "Se detecto que el parametro net.ipv4.ip_forward se encuentra habilitado" >> /var/log/hardening.log
   sysctl -w net.ipv4.ip_forward=0
   sysctl -w net.ipv4.route.flush=1
   echo $(date) "El parametro net.ipv4.ip_forward fue deshabilitado con exito" >> /var/log/hardening.log
fi

if (cat /etc/sysctl.conf | grep -E "net.ipv6.conf.all.forwarding\s*=\s*1"); then
   sed -i '/net.ipv4.ip_forward\s*=\s*1/d' /etc/sysctl.conf
   echo $(date) "Fue eliminado con exito el net.ipv6.conf.all.forwarding = 1 " >> /var/log/hardening.log
fi

if !(cat /etc/sysctl.conf | grep -E "net.ipv6.conf.all.forwarding\s*=\s*0"); then
   echo "net.ipv6.conf.all.forwarding = 0" >>/etc/sysctl.conf
   echo $(date) "Se agrego net.ipv6.conf.all.forwarding = 0 al archivo /etc/sysctl.conf " >> /var/log/hardening.log
fi

if (sysctl net.ipv6.conf.all.forwarding | grep "= 1"); then
   sysctl -w net.ipv6.conf.all.forwarding=0
   sysctl -w net.ipv6.route.flush=1
   echo $(date) "Se deshabilito el parametro del kernel net.ipv6.conf.all.forwarding" >> /var/log/hardening.log
fi

echo "#####################################################"
echo "#    3.3.2 Ensure ICMP redirects are not accepted   #"
echo "#####################################################"
if (cat /etc/sysctl.conf | grep "net.ipv4.conf.all.accept_redirects\s*=\s*1\|net.ipv4.conf.default.accept_redirects\s*=\s*1"); then
   sed -i '/net.ipv4.conf.all.accept_redirects\s*=\s*1\|net.ipv4.conf.default.accept_redirects\s*=\s*1/d' /etc/sysctl.conf
   echo $(date) "Se eliminaron las lineas net.ipv4.conf.all.accept_redirects = 1 y net.ipv4.conf.default.accept_redirects = 1" >> /var/log/hardening.log
fi

if !(cat /etc/sysctl.conf | grep "net.ipv4.conf.all.accept_redirects\s*=\s*0"); then
   echo "net.ipv4.conf.all.accept_redirects = 0" >>/etc/sysctl.conf
   echo $(date) "Se agrego net.ipv4.conf.all.accept_redirects = 0 al archivo /etc/sysctl.conf" >> /var/log/hardening.log
fi

if !(cat /etc/sysctl.conf | grep "net.ipv4.conf.default.accept_redirects\s*=\s*0"); then
   echo "net.ipv4.conf.default.accept_redirects = 0" >>/etc/sysctl.conf
   echo $(date) "Se agrego net.ipv4.conf.default.accept_redirects = 0 al archivo /etc/sysctl.conf" >> /var/log/hardening.log
fi

if (sysctl net.ipv4.conf.all.accept_redirects | grep "= 1") || (sysctl net.ipv4.conf.default.accept_redirects | grep "= 1"); then
   sudo sysctl -w net.ipv4.conf.all.accept_redirects=0
   sudo sysctl -w net.ipv4.conf.default.accept_redirects=0
   sudo sysctl -w net.ipv4.route.flush=1
   echo "Se cambiaron los valor de los parametros net.ipv4.conf.all.accept_redirect y net.ipv4.conf.default.accept_redirects a 0" >>/etc/sysctl.conf
fi

if (cat /etc/sysctl.conf | grep "net.ipv6.conf.all.accept_redirects\s*=\s*1\|net.ipv6.conf.default.accept_redirects\s*=\s*1"); then
   sed -i '/net.ipv6.conf.all.accept_redirects\s*=\s*1\|net.ipv6.conf.default.accept_redirects\s*=\s*1/d' /etc/sysctl.conf
   echo $(date) "Se eliminaron las lineas net.ipv6.conf.all.accept_redirects = 1 y net.ipv6.conf.default.accept_redirects = 1" >> /var/log/hardening.log
fi

if (sysctl net.ipv6.conf.all.accept_redirects | grep "= 1") || (sysctl net.ipv6.conf.default.accept_redirects | grep "= 1"); then
   sysctl -w net.ipv6.conf.all.accept_redirects=0
   sysctl -w net.ipv6.conf.default.accept_redirects=0
   sysctl -w net.ipv6.route.flush=1
   echo "Se cambiaron los valor de los parametros net.ipv6.conf.all.accept_redirect y net.ipv6.conf.default.accept_redirects a 0" >>/etc/sysctl.conf
fi

if !(cat /etc/sysctl.conf | grep "net.ipv6.conf.all.accept_redirects\s*=\s*0"); then
   echo "net.ipv6.conf.all.accept_redirects = 0" >>/etc/sysctl.conf
   echo $(date) "Se agrego net.ipv6.conf.all.accept_redirects = 0 al archivo /etc/sysctl.conf" >> /var/log/hardening.log
fi

if !(cat /etc/sysctl.conf | grep "net.ipv6.conf.default.accept_redirects\s*=\s*0"); then
   echo "net.ipv6.conf.default.accept_redirects = 0" >>/etc/sysctl.conf
    echo $(date) "Se agrego net.ipv6.conf.default.accept_redirects = 0 al archivo /etc/sysctl.conf" >> /var/log/hardening.log
fi


echo "########################################################"
echo "#   3.3.5 Ensure broadcast ICMP requests are ignored   #"
echo "########################################################"
if (cat  /etc/sysctl.conf | grep "net.ipv4.icmp_echo_ignore_broadcasts\s*=\s*0"); then
   sed -i '/net.ipv4.icmp_echo_ignore_broadcasts\s*=\s*0/d' /etc/sysctl.conf
   echo $(date) "Se elimino net.ipv4.icmp_echo_ignore_broadcasts = 0 del archivo /etc/sysctl.conf" >> /var/log/hardening.log
fi

if !(cat  /etc/sysctl.conf | grep "net.ipv4.icmp_echo_ignore_broadcasts\s*=\s*1"); then
   echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
   echo $(date) "Se agrego net.ipv4.icmp_echo_ignore_broadcasts = 1 al archivo /etc/sysctl.conf" >> /var/log/hardening.log
fi

if (sysctl net.ipv4.icmp_echo_ignore_broadcasts | grep "= 0");
then 
   sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
   sysctl -w net.ipv4.route.flush=1
   echo $(date) "Se cambio el valor del parametro net.ipv4.icmp_echo_ignore_broadcasts a 1 " >> /var/log/hardening.log

fi

echo "########################################################"
echo "#  3.3.6 Ensure bogus ICMP responses are ignored       #"
echo "########################################################"
if (cat  /etc/sysctl.conf | grep "net.ipv4.icmp_ignore_bogus_error_responses\s*=\s*0"); then
    sed -i "/net.ipv4.icmp_echo_ignore_broadcasts\s*=\s*0/d" /etc/sysctl.conf
    echo $(date) "Se elimino net.ipv4.icmp_ignore_bogus_error_responses = 0 del archivo /etc/sysctl.conf" >> /var/log/hardening.log
fi

if !(cat  /etc/sysctl.conf | grep "net.ipv4.icmp_ignore_bogus_error_responses\s*=\s*1"); then
   echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
   echo $(date) "Se agrego net.ipv4.icmp_ignore_bogus_error_responses = 1 al archivo /etc/sysctl.conf" >> /var/log/hardening.log

fi

if (sysctl net.ipv4.icmp_ignore_bogus_error_responses | grep "= 0");
then
   sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
   sysctl -w net.ipv4.route.flush=1
   echo $(date) "Se cambio el valor del parametro net.ipv4.icmp_ignore_bogus_error_responses" >> /var/log/hardening.log
fi

echo "########################################################"
echo "#  3.3.8 Ensure TCP SYN Cookies is enabled             #"
echo "########################################################"
if (cat  /etc/sysctl.conf | grep "net.ipv4.tcp_syncookies\s*=\s*0"); then
   sed -i '/net.ipv4.tcp_syncookies\s*=\s*0/d' /etc/sysctl.conf
    echo $(date) "Se elimino net.ipv4.tcp_syncookies = 0 del archivo /etc/sysctl.conf" >> /var/log/hardening.log 
fi

if !(cat  /etc/sysctl.conf | grep "net.ipv4.tcp_syncookies\s*=\s*1"); then
   echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
   echo $(date) "Se agrego net.ipv4.tcp_syncookies = 1 al archivo /etc/sysctl.conf" >> /var/log/hardening.log
fi

if (sysctl net.ipv4.tcp_syncookies | grep "= 0");
then
    sysctl -w net.ipv4.tcp_syncookies=1
    sysctl -w net.ipv4.route.flush=1
   echo $(date) "Se cambio el valor del parametro net.ipv4.tcp_syncookies a 1" >> /var/log/hardening.log
fi
