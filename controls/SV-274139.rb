control 'SV-274139' do
  title 'Amazon Linux 2023 must enforce password complexity rules for the root account.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Verify Amazon Linux 2023 enforces password complexity rules for the root account with the following command:

$ sudo grep -rs enforce_for_root /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf
/etc/security/pwquality.conf:enforce_for_root

If "enforce_for_root" is commented or missing, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to enforce password complexity on the root account.

Add or update the following line in the "/etc/security/pwquality.conf" file or a configuration file in the "/etc/security/pwquality.conf.d/" directory to contain the "enforce_for_root" parameter:

enforce_for_root'
  impact 0.5
  tag check_id: 'C-78230r1120403_chk'
  tag severity: 'medium'
  tag gid: 'V-274139'
  tag rid: 'SV-274139r1120405_rule'
  tag stig_id: 'AZLX-23-002385'
  tag gtitle: 'SRG-OS-000072-GPOS-00040'
  tag fix_id: 'F-78135r1120404_fix'
  tag satisfies: ['SRG-OS-000072-GPOS-00040', 'SRG-OS-000071-GPOS-00039', 'SRG-OS-000070-GPOS-00038', 'SRG-OS-000266-GPOS-00101', 'SRG-OS-000078-GPOS-00046', 'SRG-OS-000480-GPOS-00225', 'SRG-OS-000069-GPOS-00037']
  tag 'documentable'
  tag cci: ['CCI-000192', 'CCI-000193', 'CCI-000194', 'CCI-000195', 'CCI-000205', 'CCI-000366', 'CCI-001619', 'CCI-004066']
  tag nist: ['IA-5 (1) (a)', 'IA-5 (1) (b)', 'CM-6 b', 'IA-5 (1) (h)']
  tag 'host'
  tag 'container'

  setting = 'enforce_for_root'
  pwquality_files = ['/etc/security/pwquality.conf'] + Dir.glob('/etc/security/pwquality.conf.d/*.conf')

  files_setting_active = pwquality_files.select do |path|
    f = file(path)
    f.exist? && f.content.lines.map(&:strip).reject { |l| l.empty? || l.start_with?('#') }.include?(setting)
  end

  describe "Password quality setting '#{setting}'" do
    it 'should be active (uncommented) in at least one pwquality config file' do
      expect(files_setting_active).not_to be_empty, "No pwquality config file has an active '#{setting}' line. Searched:\n\t- #{pwquality_files.join("\n\t- ")}"
    end
  end
end
