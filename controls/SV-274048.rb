control 'SV-274048' do
  title 'Amazon Linux 2023 SSHD must not allow blank passwords.'
  desc 'If an account has an empty password, anyone could log on and run commands with the privileges of that account. Accounts with empty passwords must never be used in operational environments.'
  desc 'check', 'Verify Amazon Linux 2023 remote access using SSH prevents logging on with a blank password with the following command:

$ sudo grep -ir PermitEmptyPasswords /etc/ssh/sshd_config /etc/ssh/sshd_config.d/
/etc/ssh/sshd_config:PermitEmptyPasswords no

If the "PermitEmptyPassword" keyword is set to "yes", is missing, or is commented out, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to prevent SSH users from logging on with blank passwords.

Edit the following line in "etc/ssh/sshd_config" or in a file in "/etc/ssh/sshd_config.d":

PermitEmptyPasswords no

Restart the SSH daemon for the settings to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-78139r1120130_chk'
  tag severity: 'medium'
  tag gid: 'V-274048'
  tag rid: 'SV-274048r1120132_rule'
  tag stig_id: 'AZLX-23-001235'
  tag gtitle: 'SRG-OS-000106-GPOS-00053'
  tag fix_id: 'F-78044r1120131_fix'
  tag satisfies: ['SRG-OS-000106-GPOS-00053', 'SRG-OS-000480-GPOS-00229', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000766']
  tag nist: ['CM-6 b', 'IA-2 (2)']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers without SSH installed', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !directory('/etc/ssh').exist?)
  }

  describe sshd_config do
    its('PermitEmptyPasswords') { should cmp 'no' }
  end
end
