control 'SV-274036' do
  title 'Amazon Linux 2023 must have the opensc package installed.'
  desc 'The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.

The DOD has mandated the use of the Common Access Card (CAC) to support identity management and personal authentication for systems covered under Homeland Security Presidential Directive (HSPD) 12, as well as making the CAC a primary component of layered protection for national security systems.'
  desc 'check', 'Verify Amazon Linux 2023 has the opensc package installed with the following command:

$ sudo dnf list --installed opensc
Installed Packages
opensc.x86_64          0.24.0-1.amzn2023.0.4          @amazonlinux

If the "opensc" package is not installed, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to have the opensc package installed with the following command:
 
$ sudo dnf install -y opensc'
  impact 0.5
  tag check_id: 'C-78127r1120094_chk'
  tag severity: 'medium'
  tag gid: 'V-274036'
  tag rid: 'SV-274036r1120096_rule'
  tag stig_id: 'AZLX-23-001125'
  tag gtitle: 'SRG-OS-000375-GPOS-00160'
  tag fix_id: 'F-78032r1120095_fix'
  tag satisfies: ['SRG-OS-000375-GPOS-00160', 'SRG-OS-000376-GPOS-00161']
  tag 'documentable'
  tag cci: ['CCI-001948', 'CCI-001953', 'CCI-004046']
  tag nist: ['IA-2 (11)', 'IA-2 (12)', 'IA-2 (6) (a)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  only_if('MFA is not required on this system per documented ISSO/AO exemption', impact: 0.0) {
    input('mfa_required') == true
  }

  if input('smart_card_enabled')
    describe package('opensc') do
      it { should be_installed }
    end
  else
    impact 0.0
    describe 'The system is not smartcard enabled thus this control is Not Applicable' do
      skip 'The system is not using Smartcards / PIVs to fulfil the MFA requirement; this control is Not Applicable.'
    end
  end
end
