control 'SV-274157' do
  title 'Amazon Linux 2023 must maintain an account lock until the locked account is released by an administrator.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', %q(Verify Amazon Linux 2023 is configured to lock an account until released by an administrator after three unsuccessful logon attempts with the command:

$ grep 'unlock_time =' /etc/security/faillock.conf
unlock_time = 0

If the "unlock_time" option is not set to "0", the line is missing, or commented out, this is a finding.)
  desc 'fix', 'Configure Amazon Linux 2023 to lock an account until released by an administrator after three unsuccessful logon attempts with the command:
 
$ authselect enable-feature with-faillock 

Then edit the "/etc/security/faillock.conf" file as follows:

unlock_time = 0'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000329-GPOS-00128'
  tag satisfies: ['SRG-OS-000021-GPOS-00005', 'SRG-OS-000329-GPOS-00128']
  tag gid: 'V-274157'
  tag rid: 'SV-274157r1120459_rule'
  tag stig_id: 'AZLX-23-002470'
  tag fix_id: 'F-78153r1120458_fix'
  tag cci: ['CCI-000044', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b']
  tag 'host'
  tag 'container'

  if input('centralized_account_mgmt')
    impact 0.0
    describe 'N/A' do
      skip 'The system is using a centralized account mangement method; this control is Not Applicable'
    end
  else
    describe parse_config_file(input('security_faillock_conf')) do
      its('unlock_time') { should cmp 0 }
    end
  end
end
