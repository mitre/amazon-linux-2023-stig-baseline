control 'SV-274116' do
  title 'Amazon Linux 2023 audit logs must be group-owned by root or by a restricted logging group to prevent unauthorized read access.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify Amazon Linux 2023 or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify Amazon Linux 2023 is configured so that the audit logs are group-owned by "root" or a restricted logging group. 

First determine if a group other than "root" has been assigned to the audit logs with the following command:

$ sudo grep log_group /etc/audit/auditd.conf

Then determine where the audit logs are stored with the following command:

$ sudo grep -iw log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Then using the location of the audit log file, determine if the audit log is group-owned by "root" using the following command:

$ sudo stat -c "%G %n" /var/log/audit/audit.log
root /var/log/audit/audit.log

If the audit log is not group-owned by "root" or the configured alternative logging group, this is a finding.'
  desc 'fix', %q(Configure Amazon Linux 2023 to change the group of the directory of "/var/log/audit" to be owned by a correct group.

Identify the group that is configured to own audit log:

$ sudo grep -P '^[ ]*log_group[ ]+=.*$' /etc/audit/auditd.conf

Change the ownership to that group:

$ sudo chgrp ${GROUP} /var/log/audit)
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag gid: 'V-274116'
  tag rid: 'SV-274116r1120336_rule'
  tag stig_id: 'AZLX-23-002265'
  tag fix_id: 'F-78112r1120335_fix'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
  tag 'host'
  tag 'container'

  describe file(auditd_conf('/etc/audit/auditd.conf').log_file) do
    its('group') { should be_in input('var_log_audit_group') }
  end
end
