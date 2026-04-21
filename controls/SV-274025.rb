control 'SV-274025' do
  title 'Amazon Linux 2023 must routinely check the baseline configuration for unauthorized changes and notify the system administrator (SA) when anomalies in the operation of any security functions are discovered.'
  desc "Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to Amazon Linux 2023. Changes to operating system configurations can have unintended side effects, some of which may be relevant to security.

Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of Amazon Linux 2023. Amazon Linux 2023's information management officer (IMO)/information system security officer (ISSO), and SAs must be notified via email and/or monitoring system trap when there is an unauthorized modification of a configuration item.

Notifications provided by information systems include messages to local computer consoles and/or hardware indications, such as lights.

This must account for operational requirements for availability for selecting an appropriate response. The organization may choose to shut down or restart the information system upon detecting a security function anomaly.

In Amazon Linux 2023, cronie is not included by default. Therefore, support for crontab is no longer provided by default. AWS recommends migrating to systemd timers for this functionality."
  desc 'check', 'Verify Amazon Linux 2023 routinely executes a file integrity scan for changes to the system baseline. The commands used in the example will use a daily occurrence.

If using cron, check that the cronie service is running:

$ systemctl status crond
o crond.service - Command Scheduler
Loaded: loaded (/usr/lib/systemd/system/crond.service; enabled; preset: enabled)
Active: active (running) since Wed 2025-11-12 20:37:42 UTC; 7s ago

Check the cron directories for scripts controlling the execution and notification of results of the file integrity application. For example, if Advanced Intrusion Detection Environment (AIDE) is installed on the system, use the following commands:

$ ls -al /etc/cron.daily | grep aide
-rwxr-xr-x 1 root root 29 Nov 22 2015 aide

$ sudo grep aide /etc/crontab /var/spool/cron/root
/etc/crontab: 30 04 * * * root usr/sbin/aide
/var/spool/cron/root: 30 04 * * * root usr/sbin/aide

$ sudo more /etc/cron.daily/aide
#!/bin/bash
/usr/sbin/aide --check | /bin/mail -s "$HOSTNAME - Daily aide integrity check run" root@sysname.mil

If using systemd timers, ensure the aide timer is enabled:

$ systemctl status aide.timer
o aide.timer - Aide check every day at 1AM
     Loaded: loaded (/etc/systemd/system/aide.timer; enabled; preset: disabled)
     Active: active (waiting) since Thu 2025-11-20 15:23:24 UTC; 37s ago
    Trigger: Fri 2025-11-21 01:00:00 UTC; 9h left
   Triggers: o aide.service

If the timer unit file has a different name, list all available timers with the following command:

$ systemctl list-timers

If the file integrity application does not exist, or a script file controlling the execution of the file integrity application does not exist, or the file integrity application does not notify designated personnel of changes, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 so the file integrity tool runs automatically on the system at least weekly and notifies designated personnel if baseline configurations are changed in an unauthorized manner. The AIDE tool can be configured to email designated personnel using either the crond service or systemd timers.

If using cron, ensure the cronie package is installed and enabled:

$ sudo dnf install cronie
$ sudo systemctl enable crond
$ sudo systemctl start crond

The following example output is generic. It will set cron to run AIDE daily and to send an email upon completion of the analysis:

$ sudo more /etc/cron.daily/aide
#!/bin/bash
/usr/sbin/aide --check | /bin/mail -s "$HOSTNAME - Daily aide integrity check run" root@sysname.mil

If using systemd timers, create the file "/etc/systemd/system/aid.service" to run the "aide --check" command:

[Unit]
Description=Aide Check
[Service]
Type=simple
ExecStart=/usr/sbin/aide --check | /bin/mail -s "$HOSTNAME - Daily aide integrity check run"
[Install]
WantedBy=multi-user.target

Create the file "/etc/systemd/system/aide.timer" to run the AIDE check service at a specified time. The example below runs "aide --check" at 1:00 a.m. every day:

[Unit]
Description=Aide check every day at 1AM
[Timer]
OnCalendar=*-*-* 01:00:00
Unit=aide.service
[Install]
WantedBy=timers.target

Reload systemd:

$ sudo systemctl daemon-reload

Enabling the service will ensure the "aide --check" service will also start at boot time:

$ sudo systemctl enable aide.service

Start the timer:

$ sudo systemctl --now enable aide.timer'
  impact 0.5
  tag check_id: 'C-78116r1186394_chk'
  tag severity: 'medium'
  tag gid: 'V-274025'
  tag rid: 'SV-274025r1192649_rule'
  tag stig_id: 'AZLX-23-001065'
  tag gtitle: 'SRG-OS-000363-GPOS-00150'
  tag fix_id: 'F-78021r1184006_fix'
  tag satisfies: ['SRG-OS-000363-GPOS-00150', 'SRG-OS-000446-GPOS-00200', 'SRG-OS-000447-GPOS-00201']
  tag 'documentable'
  tag cci: ['CCI-001744', 'CCI-002699', 'CCI-002702']
  tag nist: ['CM-3 (5)', 'SI-6 b', 'SI-6 d']
  tag 'host'

  file_integrity_tool = input('file_integrity_tool')

  only_if('Control not applicable within a container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe package(file_integrity_tool) do
    it { should be_installed }
  end
  describe.one do
    describe file("/etc/cron.daily/#{file_integrity_tool}") do
      its('content') { should match %r{/bin/mail} }
    end
    describe file("/etc/cron.weekly/#{file_integrity_tool}") do
      its('content') { should match %r{/bin/mail} }
    end
    describe crontab('root').where { command =~ /#{file_integrity_tool}/ } do
      its('commands.flatten') { should include(match %r{/bin/mail}) }
    end
    if file("/etc/cron.d/#{file_integrity_tool}").exist?
      describe crontab(path: "/etc/cron.d/#{file_integrity_tool}") do
        its('commands') { should include(match %r{/bin/mail}) }
      end
    end
  end
end
