control 'SV-274032' do
  title 'Amazon Linux 2023 must have the libreswan package installed.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore, cannot be relied upon to provide confidentiality or integrity, and DOD data may be compromised.

Operating systems utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules. 

FIPS 140-2/140-3 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DOD requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a general purpose computing system.'
  desc 'check', 'Note: If there is no operational need for libreswan to be installed, this rule is not applicable.

Verify Amazon Linux 2023 has the libreswan package installed with the following command:

$ dnf list --installed libreswan
Installed Packages
libreswan.x86_64          4.12-3.amzn2023.0.2          @amazonlinux

If the "libreswan" package is not installed, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to have the libreswan package installed with the following command:

$ sudo dnf install -y libreswan'
  impact 0.5
  tag check_id: 'C-78123r1184009_chk'
  tag severity: 'medium'
  tag gid: 'V-274032'
  tag rid: 'SV-274032r1184010_rule'
  tag stig_id: 'AZLX-23-001105'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag fix_id: 'F-78028r1120083_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
