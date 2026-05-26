control 'SV-274117' do
  title 'Amazon Linux 2023 must ensure the audit log directory be owned by root to prevent unauthorized read access.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify Amazon Linux 2023 or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', %q(Verify Amazon Linux 2023 is configured so that the audit logs directory is owned by "root". 

First determine where the audit logs are stored with the following command:

$ sudo grep -iw log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Then using the location of the audit log file, determine if the audit log directory is owned by "root" using the following command:

sudo stat -c '%U %n' /var/log/audit
root /var/log/audit

If the audit log directory is not owned by "root", this is a finding.)
  desc 'fix', 'Configure Amazon Linux 2023 audit logs to be protected from unauthorized read access by setting the correct owner as "root" with the following command:

$ sudo chown root /var/log/audit'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag gid: 'V-274117'
  tag rid: 'SV-274117r1120339_rule'
  tag stig_id: 'AZLX-23-002270'
  tag fix_id: 'F-78113r1120338_fix'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
  tag 'host'
  tag 'container'

  audit_log_dir = File.dirname(auditd_conf('/etc/audit/auditd.conf').log_file.to_s)

  describe directory(audit_log_dir) do
    it { should exist }
    it { should be_owned_by 'root' }
  end
end
