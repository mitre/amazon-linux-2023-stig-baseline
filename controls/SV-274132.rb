control 'SV-274132' do
  title 'Amazon Linux 2023 system commands must be group-owned by root or a system account.'
  desc 'If Amazon Linux 2023 were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs which execute with escalated privileges. Only qualified and authorized individuals shall be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', 'Verify Amazon Linux 2023 system commands contained in the following directories are group-owned by "root", or a required system account, with the following command:

$ sudo find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -exec ls -l {} \\;

If any system commands are returned and is not group-owned by a required system account, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 so that system commands are protected from unauthorized access.

Run the following command, replacing "[FILE]" with any system command file not group-owned by "root" or a required system account.

$ sudo chgrp root [FILE]'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag gid: 'V-274132'
  tag rid: 'SV-274132r1120384_rule'
  tag stig_id: 'AZLX-23-002350'
  tag fix_id: 'F-78128r1120383_fix'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
  tag 'host'
  tag 'container'

  required_system_account_caveats = input('required_system_accounts').map { |acct| "-group #{acct}" }.join(' ')

  failing_files = command("find -L #{input('system_command_dirs').join(' ')} ! #{required_system_account_caveats}").stdout.split("\n")

  describe 'System commands' do
    it 'should be group-owned by root' do
      expect(failing_files).to be_empty, "Files not group-owned by root:\n\t- #{failing_files.join("\n\t- ")}"
    end
  end
end
