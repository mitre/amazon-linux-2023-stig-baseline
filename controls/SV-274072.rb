control 'SV-274072' do
  title 'Amazon Linux 2023 must notify the system administrator (SA) and information system security officer (ISSO) (at a minimum) when allocated audit record storage volume 75 percent utilization.'
  desc 'If security personnel are not notified immediately when storage volume reaches 75 percent utilization, they are unable to plan for audit record storage capacity expansion.'
  desc 'check', 'Verify Amazon Linux 2023 notifies the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity with the following command:

$ sudo grep -w space_left_action /etc/audit/auditd.conf
space_left_action = email

If the value of the "space_left_action" is not set to "email", or if the line is commented out, ask the SA to indicate how the system is providing real-time alerts to the SA and ISSO.

If there is no evidence that real-time alerts are configured on the system, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to initiate an action to notify the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity by adding/modifying the following line in the /etc/audit/auditd.conf file.

space_left_action = email'
  impact 0.5
  tag check_id: 'C-78163r1120202_chk'
  tag severity: 'medium'
  tag gid: 'V-274072'
  tag rid: 'SV-274072r1120204_rule'
  tag stig_id: 'AZLX-23-002040'
  tag gtitle: 'SRG-OS-000343-GPOS-00134'
  tag fix_id: 'F-78068r1120203_fix'
  tag 'documentable'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  space_left_action = input('space_left_action')

  describe auditd_conf do
    its('space_left_action') { should cmp space_left_action }
  end
end
