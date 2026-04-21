control 'SV-274037' do
  title 'Amazon Linux 2023 must have the openssl-pkcs11 package installed.'
  desc 'Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased. Multifactor authentication requires using two or more factors to achieve authentication. A privileged account is defined as an information system account with authorizations of a privileged user. The DOD Common Access Card (CAC) with DOD-approved PKI is an example of multifactor authentication.'
  desc 'check', 'Verify Amazon Linux 2023 has the openssl-pkcs11 package installed with the following command:

$ dnf list --installed openssl-pkcs11
Installed Packages
openssl-pkcs11.x86_64          0.4.12-3.amzn2023.0.1          @System

If the "openssl-pkcs11" package is not installed, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to have the openssl-pkcs11 package installed with the following command:
 
$ sudo dnf install -y openssl-pkcs11'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000375-GPOS-00160'
  tag satisfies: ['SRG-OS-000375-GPOS-00160', 'SRG-OS-000377-GPOS-00162', 'SRG-OS-000376-GPOS-00161']
  tag gid: 'V-274037'
  tag rid: 'SV-274037r1120099_rule'
  tag stig_id: 'AZLX-23-001130'
  tag fix_id: 'F-78033r1120098_fix'
  tag cci: ['CCI-001948', 'CCI-001954', 'CCI-004046', 'CCI-001953']
  tag nist: ['IA-2 (11)', 'IA-2 (12)', 'IA-2 (6) (a)']
  tag 'host'

  only_if('This requirement is Not Applicable inside the container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if input('alternate_mfa_method').nil?
    describe 'Manual Review' do
      skip "Alternate MFA method selected:\t\nConsult with ISSO to determine that alternate MFA method is approved; manually review system to ensure alternate MFA method is functioning"
    end
  else
    sssd_conf_files = input('sssd_conf_files')
    sssd_conf_contents = ini({ command: "cat #{input('sssd_conf_files').join(' ')}" })
    sssd_certificate_verification = input('sssd_certificate_verification')

    describe 'SSSD' do
      it 'should be installed and enabled' do
        expect(service('sssd')).to be_installed.and be_enabled
        expect(sssd_conf_contents.params).to_not be_empty, "SSSD configuration files not found or have no content; files checked:\n\t- #{sssd_conf_files.join("\n\t- ")}"
      end
      if sssd_conf_contents.params.nil?
        it "should configure certificate_verification to be '#{sssd_certificate_verification}'" do
          expect(sssd_conf_contents.sssd.certificate_verification).to eq(sssd_certificate_verification)
        end
      end
    end
  end
end
