control 'SV-274108' do
  title 'Amazon Linux 2023 audit logs must be group-owned by root or by a restricted logging group to prevent unauthorized read access.'
  desc 'Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit operating system activity.'
  desc 'check', 'Verify Amazon Linux 2023 audit logs are group-owned by "root" or a restricted logging group. 

First determine if a group other than "root" has been assigned to the audit logs with the following command:

$ sudo grep log_group /etc/audit/auditd.conf
log_group = root

Then determine where the audit logs are stored with the following command:

$ sudo grep -iw log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Then using the location of the audit log file, determine if the audit log is group-owned by "root" using the following command:

$ sudo stat -c "%G %n" /var/log/audit/audit.log
root /var/log/audit/audit.log

If the audit log is not group-owned by "root" or the configured alternative logging group, this is a finding.'
  desc 'fix', %q(Configure Amazon Linux 2023 so that audit logs are group-owned by "root" or a restricted logging group.

Change the group of the directory of "/var/log/audit" to be owned by a correct group.

Identify the group that is configured to own audit log:

$ sudo grep -P '^[ ]*log_group[ ]+=.*$' /etc/audit/auditd.conf

Change the ownership to that group:

$ sudo chgrp ${GROUP} /var/log/audit)
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029', 'SRG-OS-000206-GPOS-00084']
  tag gid: 'V-274108'
  tag rid: 'SV-274108r1120312_rule'
  tag stig_id: 'AZLX-23-002225'
  tag fix_id: 'F-78104r1120311_fix'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164', 'CCI-001314']
  tag nist: ['AU-9', 'AU-9 a', 'SI-11 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }
  describe file(auditd_conf('/etc/audit/auditd.conf').log_file) do
    its('group') { should be_in input('var_log_audit_group') }
  end
end
