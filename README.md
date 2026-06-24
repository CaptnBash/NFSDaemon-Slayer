# NFSDaemon Slayer

## Disclaimer
This exploit is for educational and authorized testing purposes only. 

## About

A remote DoS exploit for Linux NFS servers vulnerable to specially crafted SETATTR 
requests using ONE_STATEID. This vulnerability was introduced in kernel version `6.14.1`.

I wrote a blog post about it [here](https://captnbash.ch/blog/crashing-nfsd-with-one_stateid/).

## Patching
   - Upgrade kernel once patch is included in a release
   - Disable NFS if not needed: `systemctl disable --now nfs-server`
   - Restrict NFS access with firewall rules

## V1 - C Version
Compile and run with a target IP:
```bash
gcc V1/main.c -o nfsd-slayer
./nfsd-slayer 
```

## V2 - Python Version
Uses 20 threads for rapid thread pool depletion:
```bash
python3 V2/main.py 
```

## Set up a NFS server
To install and set up a NFS server on machine/VM simply run the `setup.sh` script. 

It does not have a check for the kernel version so verify first what kernel version you are using to see if the NFS server should be vulnerable or not.

## Verify NFS is running in a VM

Check NFS is listening
```bash
sudo ss -tlnp | grep 2049
```

Check exports are active
```bash
sudo exportfs -v
```

Or from another machine, try to see the shares
```bash
showmount -e <your-vm-ip>
```

## Monitor the crash
To monitor the NFS server crashing you can monitor the kernel ring with:
```bash
dmesg -w
```

To see the NFSD threads disappearing you can use
```bash
watch -n 1 'ps aux | grep nfsd | grep -v grep'
```
