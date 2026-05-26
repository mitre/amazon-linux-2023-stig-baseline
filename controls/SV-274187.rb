control 'SV-274187' do
  title 'Amazon Linux 2023 audit system must protect logon user identifiers (UIDs) from unauthorized change.'
  desc 'If modification of login UIDs is not prevented, they can be changed by nonprivileged users and make auditing complicated or impossible.'
  desc 'check', 'Verify Amazon Linux 2023 is configured so that the audit system prevents unauthorized changes to login UIDs with the following command:

$ sudo grep -i immutable /etc/audit/audit.rules
--loginuid-immutable

If the "--loginuid-immutable" option is not returned in the "/etc/audit/audit.rules", or the line is commented out, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 auditing to prevent modification of login UIDs once they are set by adding the following line to /etc/audit/rules.d/audit.rules:

--loginuid-immutable

To load the rules to the kernel immediately, use the following command: 

$ sudo augenrules --load'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000462-GPOS-00206'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000475-GPOS-00220']
  tag gid: 'V-274187'
  tag rid: 'SV-274187r1120715_rule'
  tag stig_id: 'AZLX-23-005000'
  tag fix_id: 'F-78183r1120548_fix'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164', 'CCI-000172']
  tag nist: ['AU-9', 'AU-9 a', 'AU-12 c']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }
  describe command('grep -i immutable /etc/audit/audit.rules') do
    its('stdout') { should match(/^\s*--loginuid-immutable\s*$/) }
  end
end
