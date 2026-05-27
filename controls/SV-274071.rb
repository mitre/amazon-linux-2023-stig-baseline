control 'SV-274071' do
  title 'Amazon Linux 2023 must take action when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity.'
  desc 'If security personnel are not notified immediately when storage volume reaches 75 percent utilization, they are unable to plan for audit record storage capacity expansion.'
  desc 'check', 'Verify Amazon Linux 2023 takes action when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity with the following command:

$ sudo grep -w space_left /etc/audit/auditd.conf
space_left = 25%

If the value of the "space_left" keyword is not set to 25 percent of the storage volume allocated to audit logs, or if the line is commented out, ask the system administrator (SA) to indicate how the system is providing real-time alerts to the SA and information system security officer (ISSO). If the "space_left" value is not configured to the correct value, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to take action when the audit log storage volume reaches 75 percent of the maximum storage capacity.

Edit "/etc/audit/auditd.conf" and ensure the parameter "space_left = 25%" is configured.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000343-GPOS-00134'
  tag gid: 'V-274071'
  tag rid: 'SV-274071r1184023_rule'
  tag stig_id: 'AZLX-23-002035'
  tag fix_id: 'F-78067r1184022_fix'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if input('alternative_logging_method').to_s.empty?
    describe auditd_conf do
      its('space_left.to_i') { should cmp >= input('audit_storage_threshold') }
    end
  else
    describe 'auditd space_left (manual review)' do
      skip "input('alternative_logging_method') is set to '#{input('alternative_logging_method')}'; ask the administrator to confirm what storage threshold and alerting the alternative logging implementation uses."
    end
  end
end
