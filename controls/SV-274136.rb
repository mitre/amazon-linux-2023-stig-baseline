control 'SV-274136' do
  title 'Amazon Linux 2023 must require the change of at least 50 percent of the total number of characters when passwords are changed.'
  desc 'If Amazon Linux 2023 allows the user to consecutively reuse extensive portions of passwords, this increases the chances of password compromise by increasing the window of opportunity for attempts at guessing and brute-force attacks.

The number of changed characters refers to the number of changes required with respect to the total number of positions in the current password. In other words, characters may be the same within the two passwords; however, the positions of the like characters must be different.

If the password length is an odd number then number of changed characters must be rounded up. For example, a password length of 15 characters must require the change of at least 8 characters.'
  desc 'check', 'Verify Amazon Linux 2023 enforces password complexity by requiring that at least a change of at least eight characters when passwords are changed with the following command:

$ sudo grep difok /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 
difok = 8
 
If the value of "difok" is set to less than "8", or is commented out, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to require the change of at least eight (with a 15 character password) of the total number of characters when passwords are changed by setting the "difok" option.

Add or update the following line in the "/etc/security/pwquality.conf" file or a configuration file in the "/etc/security/pwquality.conf.d/" directory to contain the "difok" parameter:

difok = 8

Remove any configurations that conflict with the above value. This value can be customized based on desired password length.'
  impact 0.5
  tag check_id: 'C-78227r1120394_chk'
  tag severity: 'medium'
  tag gid: 'V-274136'
  tag rid: 'SV-274136r1120697_rule'
  tag stig_id: 'AZLX-23-002370'
  tag gtitle: 'SRG-OS-000072-GPOS-00040'
  tag fix_id: 'F-78132r1120696_fix'
  tag 'documentable'
  tag cci: ['CCI-000195', 'CCI-004066', 'CCI-004064']
  tag nist: ['IA-5 (1) (b)', 'IA-5 (1) (h)', 'IA-5 (1) (f)']
  tag 'host'
  tag 'container'

  setting = 'difok'
  expected_value = input('difok')

  pattern = /^[^#]*#{setting}\s*=\s*(?<value>\d+)$/
  setting_check = command("grep #{setting} /etc/security/pwquality.conf /etc/security/pwquality.conf/*.conf").stdout.strip.scan(pattern).flatten

  describe 'Password settings for the root account' do
    it 'should be set' do
      expect(setting_check).to_not be_empty, "'#{setting}' not found (or commented out) in conf file(s)"
    end
    it 'should only be set once' do
      expect(setting_check.length).to eq(1), "'#{setting}' set more than once in conf file(s)"
    end
    it "should be set to be >= #{expected_value}" do
      expect(setting_check.first.to_i).to be >= expected_value, "'#{setting}' set to less than '#{expected_value}' in conf file(s)"
    end
  end
end
