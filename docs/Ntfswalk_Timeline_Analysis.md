# Ntfswalk Time Analysis Documentation

## Commands to push data to Elasticsearch
There are six files I used to push data to Elasticsearch on the linux systems brought up by AWS. The following six linux commands correspond to ingesting those files to ES:

Windows app event logs
```
/usr/share/logstash/bin/logstash -f /home/ec2-user/git-volastic/Logstash/eventlog_configs/linux/windows_app_event.conf
```

Windows security event logs
```
/usr/share/logstash/bin/logstash -f /home/ec2-user/git-volastic/Logstash/eventlog_configs/linux/windows_sec_event.conf
```

Windows system event logs
```
/usr/share/logstash/bin/logstash -f /home/ec2-user/git-volastic/Logstash/eventlog_configs/linux/windows_sys_event.conf
```

Registry system hives
```
/usr/share/logstash/bin/logstash -f /home/ec2-user/git-volastic/Logstash/registry_configs/linux/reg_system.conf
```

Registry sam hives
```
/usr/share/logstash/bin/logstash -f /home/ec2-user/git-volastic/Logstash/registry_configs/linux/reg_sam.conf
```

Registry ntuser hive
```
/usr/share/logstash/bin/logstash -f /home/ec2-user/git-volastic/Logstash/registry_configs/linux/reg_caster_ntuser.conf
```