apt update
apt upgrade -y
reboot
systemctl status restic-backup.timer
vi /etc/systemd/system/restic-backup.service
systemctl daemon-reload
systemctl enable --now restic-backup.timer
systemctl list-timers
restic -r /srv/backup/fs01 init
restic -r /srv/backup/dc01 init
vi /usr/local/bin/restic-backup.sh
chmod 750 /usr/local/bin/restic-backup.sh
/usr/local/bin/restic-backup.sh
df -h
exit
systemctl stop restic-backup.timer
systemctl disable restic-backup.timer
rm -rf /srv/backup/fs01/*
rm -rf /srv/backup/dc01/*
exit
