control 'SV-274035' do
  title 'Amazon Linux 2023 must have the packages required for encrypting off-loaded audit logs installed.'
  desc 'Unapproved mechanisms used for authentication to the cryptographic module are not verified and therefore, cannot be relied upon to provide confidentiality or integrity, and DOD data may be compromised.

Operating systems utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules. 

FIPS 140-2/140-3 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DOD requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a general purpose computing system.'
  desc 'check', 'Verify Amazon Linux 2023 has the rsyslog-openssl package installed with the following command:

$ dnf list --installed rsyslog-openssl
Installed Packages
rsyslog-openssl.x86_64          8.2204.0-3.amzn2023.0.4          @amazonlinux

If the "rsyslog-openssl" package is not installed, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to have the rsyslog-openssl package installed with the following command:

$ sudo dnf install -y rsyslog-openssl'
  impact 0.5
  tag check_id: 'C-78126r1120091_chk'
  tag severity: 'medium'
  tag gid: 'V-274035'
  tag rid: 'SV-274035r1120093_rule'
  tag stig_id: 'AZLX-23-001120'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag fix_id: 'F-78031r1120092_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
  tag 'host'

  describe file('/etc/crypto-policies/back-ends/krb5.config') do
    its('link_path') { should match(%r{/usr/share/crypto-policies/FIPS}) }
  end
end
