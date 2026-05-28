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
  expected_min = input('difok')
  pwquality_files = ['/etc/security/pwquality.conf'] + Dir.glob('/etc/security/pwquality.conf.d/*.conf')

  values_found = pwquality_files.flat_map do |path|
    next [] unless file(path).exist?
    parsed = parse_config_file(path).params
    parsed.key?(setting) ? [[path, parsed[setting].to_i]] : []
  end

  low_values = values_found.select { |_path, v| v < expected_min }

  describe "Password quality setting '#{setting}'" do
    it 'should be configured in at least one pwquality config file' do
      expect(values_found).not_to be_empty,
        "'#{setting}' not found (or commented out) in any pwquality file. Searched:\n\t- #{pwquality_files.join("\n\t- ")}"
    end
    it "should be >= #{expected_min} wherever it is set" do
      expect(low_values).to be_empty,
        "Files with '#{setting}' < #{expected_min}:\n\t- #{low_values.map { |p, v| "#{p} (#{v})" }.join("\n\t- ")}"
    end
  end
end
