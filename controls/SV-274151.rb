control 'SV-274151' do
  title 'Amazon Linux 2023 must restrict the use of the "su" command.'
  desc 'The "su" program allows to run commands with a substitute user and group ID. It is commonly used to run commands as the root user. Limiting access to such commands is considered a good security practice.'
  desc 'check', 'Verify Amazon Linux 2023 requires uses to be members of the "wheel" group with the following command:

$ grep pam_wheel /etc/pam.d/su 
auth required pam_wheel.so use_uid 

If a line for "pam_wheel.so" does not exist, or is commented out, this is a finding.'
  desc 'fix', %q(Configure Amazon Linux 2023 to require users to be in the "wheel" group to run "su" command.

In file "/etc/pam.d/su", uncomment the following line:

"#auth required pam_wheel.so use_uid"

$ sudo sed '/^[[:space:]]*#[[:space:]]*auth[[:space:]]\+required[[:space:]]\+pam_wheel\.so[[:space:]]\+use_uid$/s/^[[:space:]]*#//' -i /etc/pam.d/su

If necessary, create a "wheel" group and add administrative users to the group.)
  impact 0.5
  tag check_id: 'C-78242r1120439_chk'
  tag severity: 'medium'
  tag gid: 'V-274151'
  tag rid: 'SV-274151r1120441_rule'
  tag stig_id: 'AZLX-23-002440'
  tag gtitle: 'SRG-OS-000312-GPOS-00123'
  tag fix_id: 'F-78147r1120440_fix'
  tag 'documentable'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  pam_string = 'pam_wheel'
  pam_file = '/etc/pam.d/su'

  pam_rules_check = command("grep #{pam_string} #{pam_file}").stdout.strip.split("\n")

  describe 'PAM rules' do
    it "should include an instance of #{pam_string} in #{pam_file}" do
      expect(pam_rules_check).not_to be_empty
    end
  end
end
