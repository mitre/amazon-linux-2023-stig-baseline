control 'SV-274034' do
  title 'Amazon Linux 2023 must have the pcsc-lite package installed.'
  desc 'The pcsc-lite package must be installed if it is to be available for multifactor authentication using smart cards.'
  desc 'check', 'Verify Amazon Linux 2023 has the pcsc-lite package installed with the following command:

$ dnf list --installed pcsc-lite
Installed Packages
pcsc-lite.x86_64          1.9.1-1.amzn2023.0.4          @amazonlinux

If the "pcsc-lite" package is not installed, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to have the pcsc-lite package installed with the following command:
 
$ sudo dnf install -y pcsc-lite'
  impact 0.5
  tag check_id: 'C-78125r1120088_chk'
  tag severity: 'medium'
  tag gid: 'V-274034'
  tag rid: 'SV-274034r1120090_rule'
  tag stig_id: 'AZLX-23-001115'
  tag gtitle: 'SRG-OS-000375-GPOS-00160'
  tag fix_id: 'F-78030r1120089_fix'
  tag 'documentable'
  tag cci: ['CCI-001948', 'CCI-004046']
  tag nist: ['IA-2 (11)', 'IA-2 (6) (a)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  only_if('MFA is not required on this system per documented ISSO/AO exemption', impact: 0.0) {
    input('mfa_required') == true
  }

  if input('smart_card_enabled')
    describe package('pcsc-lite') do
      it { should be_installed }
    end
  else
    impact 0.0
    describe 'The system is not smartcard enabled thus this control is Not Applicable' do
      skip 'The system is not using Smartcards / PIVs to fulfil the MFA requirement; this control is Not Applicable.'
    end
  end
end
