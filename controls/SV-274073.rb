control 'SV-274073' do
  title 'Amazon Linux 2023 must take action when allocated audit record storage volume reaches 95 percent of the audit record storage capacity.'
  desc 'If action is not taken when storage volume reaches 95 percent utilization, the auditing system may fail when the storage volume reaches capacity.'
  desc 'check', 'Verify Amazon Linux 2023 takes action when allocated audit record storage volume reaches 95 percent of the repository maximum audit record storage capacity with the following command:

$ sudo grep -w admin_space_left /etc/audit/auditd.conf
admin_space_left = 5%

If the value of the "admin_space_left" keyword is not set to 5 percent of the storage volume allocated to audit logs, or if the line is commented out, ask the system administrator (SA) to indicate how the system is taking action if the allocated storage is about to reach capacity. If the "space_left" value is not configured to the correct value, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to initiate an action when allocated audit record storage volume reaches 95 percent of the repository maximum audit record storage capacity by adding/modifying the following line in the /etc/audit/auditd.conf file.

admin_space_left = 5%'
  impact 0.5
  tag check_id: 'C-78164r1120205_chk'
  tag severity: 'medium'
  tag gid: 'V-274073'
  tag rid: 'SV-274073r1120207_rule'
  tag stig_id: 'AZLX-23-002045'
  tag gtitle: 'SRG-OS-000343-GPOS-00134'
  tag fix_id: 'F-78069r1120206_fix'
  tag 'documentable'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  admin_space_left = input('admin_space_left')

  describe auditd_conf do
    its('admin_space_left') { should cmp admin_space_left }
  end
end
