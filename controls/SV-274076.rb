control 'SV-274076' do
  title 'Amazon Linux 2023 must be configured to off-load audit records onto a different system from the system being audited via syslog.'
  desc 'The auditd service does not include the ability to send audit records to a centralized server for management directly. However, it can use a plug-in for audit event multiplexor (audispd) to pass audit records to the local syslog server.'
  desc 'check', 'Verify Amazon Linux 2023 is configured use the audisp-remote syslog service with the following command:

$ sudo grep active /etc/audit/plugins.d/syslog.conf 
active = yes

If the "active" keyword does not have a value of "yes", the line is commented out, or the line is missing, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to use the audisp-remote syslog service.

Edit the /etc/audit/plugins.d/syslog.conf file and add or update the "active" option:

active = yes

The audit daemon must be restarted for changes to take effect.'
  impact 0.5
  tag check_id: 'C-78167r1120214_chk'
  tag severity: 'medium'
  tag gid: 'V-274076'
  tag rid: 'SV-274076r1120216_rule'
  tag stig_id: 'AZLX-23-002060'
  tag gtitle: 'SRG-OS-000479-GPOS-00224'
  tag fix_id: 'F-78072r1120215_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  plugin_file = file('/etc/audit/plugins.d/syslog.conf').exist?
  
  if plugin_file
    describe parse_config_file('/etc/audit/plugins.d/syslog.conf') do
      its('active') { should cmp 'yes' }
    end
  else
    describe file('/etc/audit/plugins.d/syslog.conf') do
      it { should exist }
    end
  end
end
