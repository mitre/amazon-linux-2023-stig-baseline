control 'SV-274137' do
  title 'Amazon Linux 2023 must enforce a minimum 15-character password length.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Verify Amazon Linux 2023 enforces a minimum 15-character password length with the following command:

$ sudo grep -rs minlen /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf
/etc/security/pwquality.conf: minlen = 15

If the command does not return a "minlen" value of 15 or greater, or the line is commented out, this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to enforce a minimum 15-character password length.

Add or update the following line in the "/etc/security/pwquality.conf" file or a configuration file in the "/etc/security/pwquality.conf.d/" directory to contain the "minlen" parameter:

minlen = 15

Remove any configurations that conflict with the above value.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag gid: 'V-274137'
  tag rid: 'SV-274137r1120725_rule'
  tag stig_id: 'AZLX-23-002375'
  tag fix_id: 'F-78133r1120398_fix'
  tag cci: ['CCI-000205', 'CCI-004066', 'CCI-004064']
  tag nist: ['IA-5 (1) (a)', 'IA-5 (1) (h)', 'IA-5 (1) (f)']
  tag 'host'
  tag 'container'

  setting = 'minlen'
  expected_min = input('pass_min_len')
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
