restic -r /srv/backup/fs01 snapshots
restic -r /srv/backup/dc01 snapshots
restic -r /srv/backup/fs01 check
crontab -l
crontab -e
crontab -l
restic -r /srv/backup/fs01 snapshots
restic -r /srv/backup/fs01 restore latest --target /tmp/restore-test --include "/mnt/fs01/Finance/Contas a Pagar"
ls -la "/tmp/restore-test/mnt/fs01/Finance/Contas a Pagar"
du -sh /tmp/restore-test
rm -rf /tmp/restore-test
exit
