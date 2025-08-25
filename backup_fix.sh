

1. rm -Rf /16t_elkbackup/*
 

2. Go to fiile
 /etc/ssh/sshd_config
with value 
AllowTcpForwarding no

this has to be change to 'yes'
AllowTcpForwarding yes

3. Change that file first then restart SSHD service
sudo exportfs -ra
sudo systemctl restart sshd
 make sure that NFS service is still working on server:

sudo netstat -tulpn | grep 2049
tcp        0      0 0.0.0.0:2049            0.0.0.0:*               LISTEN      -
tcp6       0      0 :::2049                 :::*                    LISTEN      -

sudo ps aux | grep nfs
root        1265  0.0  0.0  50076  2828 ?        Ss   Jun11   0:00 /usr/sbin/nfsdcld
root        1733  0.0  0.0      0     0 ?        S    Jun11   0:00 [nfsd]

4. On each client node restart autossh-nfs-tunnel service
sudo service autossh-nfs-tunnel restart

5. And Mount NFS mountpoint
sudo mount -vvv -t nfs4 -o port=3335,proto=tcp localhost:/elkbackup /16t_elkbackup

6. run command to verify that catalog is not empty 
ls -lt /16t_elkbackup
and move on to next node client, basically go through all elasticsearch nodes. 
