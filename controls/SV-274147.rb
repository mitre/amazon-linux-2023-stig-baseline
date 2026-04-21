control 'SV-274147' do
  title 'Amazon Linux 2023 must automatically lock an account when three unsuccessful logon attempts occur.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.

Amazon Linux 2023 can utilize the "pam_faillock.so" for this purpose. Note that manual changes to the listed files may be overwritten by the "authselect" program.

From "Pam_Faillock" man pages: Note that the default directory that "pam_faillock" uses is usually cleared on system boot so the access will be re-enabled after system reboot. If that is undesirable, a different tally directory must be set with the "dir" option.'
  desc 'check', 'Verify Amazon Linux 2023 locks an account after three unsuccessful logon attempts with the following commands:

Note: If the system administrator (SA) demonstrates the use of an approved centralized account management method that locks an account after three unsuccessful logon attempts within a period of 15 minutes, this requirement is met by that method.

$ sudo grep pam_faillock.so /etc/pam.d/password-auth /etc/pam.d/system-auth
auth required pam_faillock.so preauth dir=/var/log/faillock silent audit deny=3 even_deny_root fail_interval=900 unlock_time=0
auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=0
account required pam_faillock.so

If the "deny" option is not set to "3" or less (but not "0") on the "preauth" line with the "pam_faillock.so" module, or is missing from this line, if any of the lines are commented out or are missing, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to lock an account when three unsuccessful logon attempts occur.

Add/Modify the appropriate sections of the "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" files to match the following lines:

auth required pam_faillock.so preauth dir=/var/log/faillock silent audit deny=3 even_deny_root fail_interval=900 unlock_time=0
auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=0
account required pam_faillock.so

The "sssd" service must be restarted for the changes to take effect. To restart the "sssd" service, run the following command:

$ sudo systemctl restart sssd.service'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag satisfies: ['SRG-OS-000021-GPOS-00005', 'SRG-OS-000329-GPOS-00128']
  tag gid: 'V-274147'
  tag rid: 'SV-274147r1184027_rule'
  tag stig_id: 'AZLX-23-002420'
  tag fix_id: 'F-78143r1120428_fix'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
  tag 'host'
  tag 'container'

  describe parse_config_file('/etc/security/faillock.conf') do
    its('audit') { should_not be_nil }
  end
end
