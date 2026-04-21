control 'SV-274133' do
  title 'Amazon Linux 2023 must enforce password complexity by requiring that at least one uppercase character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Verify Amazon Linux 2023 enforces password complexity by requiring that at least one uppercase character with the following command:

$ sudo grep ucredit /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 
ucredit = -1 

If the value of "ucredit" is a positive number or is commented out, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to enforce password complexity by requiring that at least one uppercase character be used by setting the "ucredit" option.

Add or update the following line in the "/etc/security/pwquality.conf" file or a configuration file in the "/etc/security/pwquality.conf.d/" directory to contain the "ucredit" parameter:

ucredit = -1

Remove any configurations that conflict with the above value.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag gid: 'V-274133'
  tag rid: 'SV-274133r1120387_rule'
  tag stig_id: 'AZLX-23-002355'
  tag fix_id: 'F-78129r1120386_fix'
  tag cci: ['CCI-000192', 'CCI-004066', 'CCI-004064']
  tag nist: ['IA-5 (1) (a)', 'IA-5 (1) (h)', 'IA-5 (1) (f)']
  tag 'host'
  tag 'container'

  describe 'pwquality.conf:' do
    let(:config) { parse_config_file('/etc/security/pwquality.conf', multiple_values: true) }
    let(:setting) { 'ucredit' }
    let(:value) { Array(config.params[setting]) }

    it 'has `ucredit` set' do
      expect(value).not_to be_empty, 'ucredit is not set in pwquality.conf'
    end

    it 'only sets `ucredit` once' do
      expect(value.length).to eq(1), 'ucredit is commented or set more than once in pwquality.conf'
    end

    it 'does not set `ucredit` to a positive value' do
      expect(value.first.to_i).to cmp < 0, 'ucredit is not set to a negative value in pwquality.conf'
    end
  end
end
