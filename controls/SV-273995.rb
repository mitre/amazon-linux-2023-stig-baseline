control 'SV-273995' do
  title 'Amazon Linux 2023 must ensure cryptographic verification of vendor software packages.'
  desc 'Cryptographic verification of vendor software packages ensures that all software packages are obtained from a valid source and protects against spoofing that could lead to installation of malware on the system. Amazon Linux cryptographically signs all software packages, which includes updates, with a GPG key to Verify they are valid.'
  desc 'check', 'Verify Amazon Linux 2023 package-signing keys are installed on the system and verify their fingerprints match vendor values.

Note: For Amazon Linux 2023 software packages, AWS uses GPG keys defined in key file "/etc/pki/rpm-gpg/RPM-GPG-KEY-amazon-linux-2023" by default.

List Amazon Linux GPG keys installed on the system:

$ sudo rpm -q gpg-pubkey --qf "%{NAME}-%{VERSION}-%{RELEASE} %{SUMMARY}\\n"
gpg-pubkey-d832c631-6515c85e Amazon Linux <amazon-linux@amazon.com> public key

If there is no Amazon Linux GPG key installed, this is a finding.

Extract the fingerprint from the key with this command:

$ sudo gpg -q --keyid-format short --with-fingerprint /etc/pki/rpm-gpg/RPM-GPG-KEY-amazon-linux-2023
pub  rsa4096/D832C631 2022-12-08 [SC]
     Key fingerprint = B21C 50FA 44A9 9720 EAA7 2F7F E951 904A D832 C631
uid           Amazon Linux <amazon-linux@amazon.com>

Compare the Key fingerprint with the key fingerprint from Amazon Documentation and instructions at https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/verify-keys.html

If key fingerprints do not match, or the key file is missing, this is a finding.'
  desc 'fix', %q(Configure Amazon Linux 2023 to have the public key for verifying RPM packages to be installed with the "system-release" package. 

Install the system-release installation with the following command:
$ sudo dnf install -y system-release

Ensure cryptographic verification of software packages is enabled by editing /etc/dnf/dnf.conf and under '[main]' in the configuration file add: 

gpgcheck=1)
  impact 0.5
  tag check_id: 'C-78086r1119971_chk'
  tag severity: 'medium'
  tag gid: 'V-273995'
  tag rid: 'SV-273995r1119973_rule'
  tag stig_id: 'AZLX-23-000110'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-77991r1119972_fix'
  tag 'documentable'
  tag cci: ['CCI-001749', 'CCI-003992']
  tag nist: ['CM-5 (3)', 'CM-14']
  tag 'host'
  tag 'container'

  rpm_gpg_file = input('rpm_gpg_file')
  rpm_gpg_keys = input('rpm_gpg_keys')

  describe file(rpm_gpg_file) do
    it { should exist }
  end
  rpm_gpg_keys.each do |k, v|
    describe "Installed RPM GPG public key: #{k}" do
      subject { command(%(rpm -q --queryformat "%{SUMMARY}\\n" gpg-pubkey)).stdout }
      it { should include k.to_s }
    end
    next unless file(rpm_gpg_file).exist?

    describe "GPG fingerprint for #{k} in #{rpm_gpg_file}" do
      subject { command("gpg -q --keyid-format short --with-fingerprint #{rpm_gpg_file}").stdout }
      it { should include v }
    end
  end
end
