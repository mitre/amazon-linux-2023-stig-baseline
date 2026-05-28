control 'SV-274058' do
  title 'Amazon Linux 2023 crypto policy must not be overridden.'
  desc 'Centralized cryptographic policies simplify applying secure ciphers across an operating system and the applications that run on that operating system. Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data.'
  desc 'check', 'Verify Amazon Linux 2023 custom crypto policies are loaded correctly with the following command:

$ ls -l /etc/crypto-policies/back-ends/
lrwxrwxrwx. 1 root root 40 Mar 7 19:22 bind.config -> /usr/share/crypto-policies/FIPS/bind.txt
lrwxrwxrwx. 1 root root 42 Mar 7 19:22 gnutls.config -> /usr/share/crypto-policies/FIPS/gnutls.txt
lrwxrwxrwx. 1 root root 40 Mar 7 19:22 java.config -> /usr/share/crypto-policies/FIPS/java.txt
lrwxrwxrwx. 1 root root 46 Mar 7 19:22 javasystem.config -> /usr/share/crypto-policies/FIPS/javasystem.txt
lrwxrwxrwx. 1 root root 40 Mar 7 19:22 krb5.config -> /usr/share/crypto-policies/FIPS/krb5.txt
lrwxrwxrwx. 1 root root 45 Mar 7 19:22 libreswan.config -> /usr/share/crypto-policies/FIPS/libreswan.txt
lrwxrwxrwx. 1 root root 42 Mar 7 19:22 libssh.config -> /usr/share/crypto-policies/FIPS/libssh.txt
-rw-r--r--. 1 root root 398 Mar 7 19:22 nss.config
lrwxrwxrwx. 1 root root 43 Mar 7 19:22 openssh.config -> /usr/share/crypto-policies/FIPS/openssh.txt
lrwxrwxrwx. 1 root root 49 Mar 7 19:22 opensshserver.config -> /usr/share/crypto-policies/FIPS/opensshserver.txt
lrwxrwxrwx. 1 root root 43 Mar 7 19:22 openssl.config -> /usr/share/crypto-policies/FIPS/openssl.txt
lrwxrwxrwx. 1 root root 48 Mar 7 19:22 openssl_fips.config -> /usr/share/crypto-policies/FIPS/openssl_fips.txt
lrwxrwxrwx. 1 root root 46 Mar 7 19:22 opensslcnf.config -> /usr/share/crypto-policies/FIPS/opensslcnf.txt

If the paths do not point to the respective files under /usr/share/crypto-policies/FIPS path, this is a finding.
Note: nss.config must not be hyperlinked.'
  desc 'fix', 'Configure Amazon Linux 2023 to correctly implement the systemwide cryptographic policies by reinstalling the crypto-policies package contents.

Reinstall crypto-policies with the following command:

$ sudo dnf -y reinstall crypto-policies

Set the crypto-policy to FIPS with the following command:

$ sudo update-crypto-policies --set FIPS
Setting system policy to FIPS

Note: Systemwide crypto policies are applied on application startup. It is recommended to restart the system for the change of policies to fully take place.'
  impact 0.7
  tag check_id: 'C-78149r1120160_chk'
  tag severity: 'high'
  tag gid: 'V-274058'
  tag rid: 'SV-274058r1186176_rule'
  tag stig_id: 'AZLX-23-001285'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag fix_id: 'F-78054r1120161_fix'
  tag satisfies: ['SRG-OS-000396-GPOS-00176', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000424-GPOS-00188', 'SRG-OS-000073-GPOS-00041', 'SRG-OS-000120-GPOS-00061']
  tag 'documentable'
  tag cci: ['CCI-002450', 'CCI-002890', 'CCI-003123', 'CCI-002421', 'CCI-004062', 'CCI-000803']
  tag nist: ['SC-13 b', 'MA-4 (6)', 'SC-8 (1)', 'IA-5 (1) (d)', 'IA-7']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  crypto_policies_dir = '/etc/crypto-policies/back-ends'
  expected_link_path_dir = '/usr/share/crypto-policies/FIPS'

  crypto_policy_files = Dir.glob("#{crypto_policies_dir}/*").map { |p| File.basename(p) }

  failing_crypto_policies = {}

  crypto_policy_files.each do |crypto_policy|
    # Per STIG check text: "nss.config must not be hyperlinked" — it is the
    # only entry expected to be a regular file rather than a symlink.
    next if crypto_policy == 'nss.config'

    service = "#{crypto_policies_dir}/#{crypto_policy}"
    link_path = file(service).link_path

    if link_path.nil?
      failing_crypto_policies[service] = 'not a symlink (expected symlink into FIPS/)'
    elsif !link_path.match?(/^#{expected_link_path_dir}/)
      failing_crypto_policies[service] = link_path
    end
  end

  describe 'Crypto policies (/etc/crypto-policies/back-ends)' do
    it "should link to files under #{expected_link_path_dir}" do
      failure_message = "Crypto policy symlinks not pointing into #{expected_link_path_dir}:\n\t- " +
                        failing_crypto_policies.map { |k, v| "#{k} -> #{v}" }.join("\n\t- ")
      expect(failing_crypto_policies).to be_empty, failure_message
    end
  end

  output = command('update-crypto-policies --check 2>&1 && echo PASS').stdout.strip
  last_line = output.lines.map(&:strip).reject(&:empty?).last.to_s

  describe 'System cryptographic policy must match the generated policy' do
    subject { last_line }
    it { should cmp 'PASS' }
  end
end
