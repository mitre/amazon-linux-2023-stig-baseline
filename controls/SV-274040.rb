control 'SV-274040' do
  title 'Amazon Linux 2023 must have the crypto-policies package installed.'
  desc 'Centralized cryptographic policies simplify applying secure ciphers across an operating system and the applications that run on that operating system. Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data.'
  desc 'check', 'Verify Amazon Linux 2023 crypto-policies package is installed with the following command:

$ dnf list --installed crypto-policies
Installed Packages
crypto-policies.noarch          20240828-2.git626aa59.amzn2023.0.1          @System

If the "crypto-policies" package is not installed, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to have the crypto-policies package installed with the following command:

$ sudo dnf install -y crypto-policies'
  impact 0.7
  tag check_id: 'C-78131r1120106_chk'
  tag severity: 'high'
  tag gid: 'V-274040'
  tag rid: 'SV-274040r1184011_rule'
  tag stig_id: 'AZLX-23-001195'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag fix_id: 'F-78036r1120107_fix'
  tag satisfies: ['SRG-OS-000396-GPOS-00176', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000424-GPOS-00188']
  tag 'documentable'
  tag cci: ['CCI-002450', 'CCI-002890', 'CCI-003123', 'CCI-002421']
  tag nist: ['SC-13 b', 'MA-4 (6)', 'SC-8 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe package('crypto-policies') do
    it { should be_installed }
  end
end
