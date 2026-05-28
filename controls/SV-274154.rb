control 'SV-274154' do
  title 'Amazon Linux 2023 must automatically lock an account when three unsuccessful logon attempts occur.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', %q(Verify Amazon Linux 2023 is configured to lock an account after three unsuccessful logon attempts with the command:

$ grep 'deny =' /etc/security/faillock.conf
deny = 3

If the "deny" option is not set to "3" or less (but not "0"), is missing or commented out, this is a finding.)
  desc 'fix', 'Configure Amazon Linux 2023 to lock an account when three unsuccessful logon attempts occur.

Add/modify the "/etc/security/faillock.conf" file to match the following line:

deny = 3'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000329-GPOS-00128'
  tag satisfies: ['SRG-OS-000021-GPOS-00005', 'SRG-OS-000329-GPOS-00128']
  tag gid: 'V-274154'
  tag rid: 'SV-274154r1120450_rule'
  tag stig_id: 'AZLX-23-002455'
  tag fix_id: 'F-78150r1120449_fix'
  tag cci: ['CCI-000044', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe parse_config_file('/etc/security/faillock.conf') do
    its('deny') { should cmp <= input('unsuccessful_attempts') }
    its('deny') { should_not cmp 0 }
  end
end
