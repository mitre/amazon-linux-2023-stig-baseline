control 'SV-274156' do
  title 'Amazon Linux 2023 must automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes occur.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'Verify Amazon Linux 2023 locks an account after three unsuccessful logon attempts within a 15-minute period with the following command:

$ grep fail_interval /etc/security/faillock.conf 
fail_interval = 900

If the "fail_interval" option is not set to "900" or less (but not "0"), the line is commented out, or the line is missing, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to automatically lock an account after three unsuccessful logon attempts in 15-minutes.

First, ensure that the system is configured with authselect, i.e., using sssd profiles:

$ sudo authselect select sssd [--force]

Then, enable the faillock feature:

$ sudo authselect enable-feature with-faillock

Then edit the "/etc/security/faillock.conf" file as follows:

fail_interval = 900'
  impact 0.5
  tag check_id: 'C-78247r1184028_chk'
  tag severity: 'medium'
  tag gid: 'V-274156'
  tag rid: 'SV-274156r1184029_rule'
  tag stig_id: 'AZLX-23-002465'
  tag gtitle: 'SRG-OS-000329-GPOS-00128'
  tag fix_id: 'F-78152r1120455_fix'
  tag satisfies: ['SRG-OS-000329-GPOS-00128', 'SRG-OS-000021-GPOS-00005']
  tag 'documentable'
  tag cci: ['CCI-000044', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b']
  tag 'host'
  tag 'container'

  lockout_time = input('lockout_time')

  describe parse_config_file('/etc/security/faillock.conf') do
    its('unlock_time') { should cmp lockout_time }
  end
end
