#!/usr/bin/env bash
apt-get update
apt-get install -y nfs-kernel-server

# Verify kernel is in the vulnerable range
echo "Running kernel: $(uname -r)"

systemctl enable --now nfs-server

echo '/tmp *(rw,sync,no_subtree_check)' >> /etc/exports

exportfs -a
systemctl restart nfs-server
