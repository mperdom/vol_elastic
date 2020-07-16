# Ntfswalk Time Analysis Documentation
Follow the inital Volastic ReadMe documentation for setting up the AWS environment, up until "Running Volatility", then follow the rest of the document here.

## Commands to push data to Elasticsearch
There are six files used to push data to Elasticsearch on the linux systems brought up by AWS. The following six linux commands correspond to ingesting those files to ES:

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