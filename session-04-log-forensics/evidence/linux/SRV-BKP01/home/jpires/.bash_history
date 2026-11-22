sudo apt update
sudo apt upgrade -y
sudo systemctl status restic-backup.timer
exit
sudo journalctl -u restic-backup --since yesterday
sudo df -h /srv/backup
exit
sudo restic -r /srv/backup/fs01 snapshots --latest 3
exit
sudo apt list --upgradable
sudo systemctl list-timers restic-backup.timer
exit
sudo journalctl -u restic-backup --since today
exit
