control 'SV-274070' do
  title 'Amazon Linux 2023 must take appropriate action when the internal event queue is full.'
  desc 'The audit system should have an action setup in the event the internal event queue becomes full so that no data is lost. Information stored in one location is vulnerable to accidental or incidental deletion or alteration.'
  desc 'check', 'Verify Amazon Linux 2023 audit system is configured to take an appropriate action when the internal event queue is full:

$ sudo grep -i overflow_action /etc/audit/auditd.conf 
overflow_action = syslog

If the value of the "overflow_action" option is not set to "syslog", "single", "halt" or the line is commented out, ask the system administrator (SA) to indicate how the audit logs are off-loaded to a different system or media.

If there is no evidence that the transfer of the audit logs being off-loaded to another system or media takes appropriate action if the internal event queue becomes full, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 so that the audit system takes an appropriate action when the internal event queue is full.

Edit the /etc/audit/auditd.conf file and add or update the "overflow_action" option:

overflow_action = syslog

The audit daemon must be restarted for changes to take effect.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag satisfies: ['SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224']
  tag gid: 'V-274070'
  tag rid: 'SV-274070r1120198_rule'
  tag stig_id: 'AZLX-23-002030'
  tag fix_id: 'F-78066r1120197_fix'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if input('alternative_logging_method').to_s.empty?
    describe parse_config_file('/etc/audit/auditd.conf') do
      its('overflow_action') { should match(/syslog$|single$|halt$/i) }
    end
  else
    describe 'auditd overflow_action (manual review)' do
      skip "input('alternative_logging_method') is set to '#{input('alternative_logging_method')}'; ask the administrator to confirm what action the alternative logging implementation takes when the internal event queue fills."
    end
  end
end
