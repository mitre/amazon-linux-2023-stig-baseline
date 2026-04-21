control 'SV-273997' do
  title 'Amazon Linux 2023 must check the GPG signature of software packages originating from external software repositories before installation.'
  desc 'Changes to any software components can have significant effects on the overall security of Amazon Linux 2023. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.

All software packages must be signed with a cryptographic key recognized and approved by the organization.

Verifying the authenticity of software prior to installation validates the integrity of the software package received from a vendor. This verifies the software has not been tampered with and that it has been provided by a trusted vendor.'
  desc 'check', 'Verify Amazon Linux 2023 is configured so that dnf always checks the GPG signature of software packages originating from external software repositories before installation:

$ grep -w gpgcheck /etc/dnf/dnf.conf
gpgcheck=1

If "gpgcheck" is not set to "1" or "True", or if the option is missing or commented out, ask the system administrator how the GPG signatures of software packages are being verified.

If there is no process to verify GPG signatures approved by the organization, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to always check the GPG signature of software packages originating from external software repositories before installation.

Add or update the following line in the [main] section of the /etc/dnf/dnf.conf file:

gpgcheck=1'
  impact 0.7
  tag check_id: 'C-78088r1119977_chk'
  tag severity: 'high'
  tag gid: 'V-273997'
  tag rid: 'SV-273997r1119979_rule'
  tag stig_id: 'AZLX-23-000120'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-77993r1119978_fix'
  tag 'documentable'
  tag cci: ['CCI-001749', 'CCI-003992']
  tag nist: ['CM-5 (3)', 'CM-14']
  tag 'host'
  tag 'container'

  describe 'DNF configuration should enforce GPG signature checking' do
    subject { parse_config_file('/etc/dnf/dnf.conf').params['main'] }
    its('gpgcheck') { should cmp 1 }
  end
end
