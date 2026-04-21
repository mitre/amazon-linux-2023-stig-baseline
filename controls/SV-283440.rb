control 'SV-283440' do
  title 'Amazon Linux 2023 must implement DOD-approved encryption in the bind package.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

Amazon Linux 2023 incorporates system-wide crypto policies by default. The employed algorithms can be viewed in the /etc/crypto-policies/back-ends/ directory.'
  desc 'check', %q(Verify that Amazon Linux 2023 configures BIND to use the system crypto policy with the following command:

Note: If the "bind" package is not installed, this requirement is Not Applicable.

$ sudo grep include /etc/named.conf 

include "/etc/crypto-policies/back-ends/bind.config";' 

If BIND is installed and the BIND config file doesn't contain the  include "/etc/crypto-policies/back-ends/bind.config" directive, or the line is commented out, this is a finding.)
  desc 'fix', 'Configure Amazon Linux 2023 so that BIND uses the system crypto policy.

Add the following line to the "options" section in "/etc/named.conf":

include "/etc/crypto-policies/back-ends/bind.config";'
  impact 0.7
  tag check_id: 'C-88005r1192647_chk'
  tag severity: 'high'
  tag gid: 'V-283440'
  tag rid: 'SV-283440r1192648_rule'
  tag stig_id: 'AZLX-23-001286'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-87910r1188392_fix'
  tag satisfies: ['SRG-OS-000423-GPOS-00187', 'SRG-OS-000426-GPOS-00190']
  tag 'documentable'
  tag cci: ['CCI-002418', 'CCI-002422']
  tag nist: ['SC-8', 'SC-8 (2)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }
  only_if('This control is Not Applicable since bind is not installed', impact: 0.0) {
    package('bind').installed?
  }

  describe file('/etc/named.conf') do
    it { should exist }
  end

  bind_grep = command('grep include /etc/named.conf').stdout.lines.map(&:strip)
  bind_conf = bind_grep.any? { |line| line.match?(%r{/etc/crypto-policies/back-ends/bind.config}i) }

  describe 'Bind config file' do
    it 'should include system-wide crypto policies' do
      expect(bind_conf).to eq(true), 'Bind conf files do not include /etc/crypto-policies/back-ends/bind.config'
    end
  end
end
