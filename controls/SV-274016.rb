control 'SV-274016' do
  title 'Amazon Linux 2023 must require users to provide a password for privilege escalation.'
  desc 'Without reauthentication, users may access resources or perform tasks for which they do not have authorization.'
  desc 'check', 'Verify Amazon Linux 2023 requires users to provide a password for privilege escalation.

Ensure that "/etc/sudoers" has no occurrences of "NOPASSWD" with the following command:

$ sudo grep -ri nopasswd /etc/sudoers /etc/sudoers.d/

If any occurrences of "NOPASSWD" are returned, this is a finding.'
  desc 'fix', %q(Configure Amazon Linux 2023 to not allow users to execute privileged actions without authenticating with a password.

Remove any occurrence of "NOPASSWD" found in "/etc/sudoers" file or files in the "/etc/sudoers.d" directory.

$ sudo sed -i '/NOPASSWD/ s/^/# /g' /etc/sudoers /etc/sudoers.d/*)
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-274016'
  tag rid: 'SV-274016r1120036_rule'
  tag stig_id: 'AZLX-23-001020'
  tag fix_id: 'F-78012r1120035_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers without sudo installed', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !command('sudo').exist?)
  }

  bad_sudoers_rules = sudoers(input('sudoers_config_files').join(' ')).rules.where {
    users == 'ALL' &&
      hosts == 'ALL' &&
      run_as.start_with?('ALL') &&
      commands == 'ALL'
  }

  describe 'Sudoers file(s)' do
    it 'should not contain any unrestricted sudo rules' do
      expect(bad_sudoers_rules.entries).to be_empty, "Unrestricted sudo rules found; check sudoers file(s):\n\t- #{input('sudoers_config_files').join("\n\t- ")}"
    end
  end
end
