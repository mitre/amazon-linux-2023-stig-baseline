control 'SV-274140' do
  title 'Amazon Linux 2023 must prevent the use of dictionary words for passwords.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If Amazon Linux 2023 allows the user to select passwords based on dictionary words, this increases the chances of password compromise by increasing the opportunity for successful guesses, and brute-force attacks.'
  desc 'check', 'Verify Amazon Linux 2023 prevents the use of dictionary words for passwords with the following command:

$ sudo grep -rs dictcheck /etc/security/pwquality.conf /etc/pwquality.conf.d/*.conf 
/etc/security/pwquality.conf:dictcheck=1 

If the "dictcheck" parameter is not set to "1", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to prevent the use of dictionary words for passwords.

Add or update the following line in the "/etc/security/pwquality.conf" file or a configuration file in the /etc/pwquality.conf.d/ directory to contain the "dictcheck" parameter:

dictcheck=1'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00225'
  tag gid: 'V-274140'
  tag rid: 'SV-274140r1120408_rule'
  tag stig_id: 'AZLX-23-002390'
  tag fix_id: 'F-78136r1120407_fix'
  tag cci: ['CCI-000366', 'CCI-004061']
  tag nist: ['CM-6 b', 'IA-5 (1) (b)']
  tag 'host'
  tag 'container'

  describe parse_config_file('/etc/security/pwquality.conf') do
    its('dictcheck') { should eq '1' }
  end
end
