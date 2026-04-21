control 'SV-274115' do
  title 'Amazon Linux 2023 must produce audit records containing information to establish the identity of any individual or process associated with the event.'
  desc 'Without information that establishes the identity of the subjects (i.e., users or processes acting on behalf of users) associated with the events, security personnel cannot determine responsibility for the potentially harmful event.'
  desc 'check', 'Verify Amazon Linux 2023 is configured so that the audit system resolves audit information before writing to disk, with the following command:

$ sudo grep log_format /etc/audit/auditd.conf
log_format = ENRICHED

If the "log_format" option is not "ENRICHED", or the line is commented out, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 so that the audit system resolves audit information before writing to disk.

Edit the /etc/audit/auditd.conf file and add or update the "log_format" option:

log_format = ENRICHED

The audit daemon must be restarted for changes to take effect.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000255-GPOS-00096'
  tag gid: 'V-274115'
  tag rid: 'SV-274115r1120333_rule'
  tag stig_id: 'AZLX-23-002260'
  tag fix_id: 'F-78111r1120332_fix'
  tag cci: ['CCI-000366', 'CCI-001487']
  tag nist: ['CM-6 b', 'AU-3 f']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }
  describe parse_config_file('/etc/audit/auditd.conf') do
    its('log_format') { should eq 'ENRICHED' }
  end
end
