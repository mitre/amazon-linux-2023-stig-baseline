control 'SV-274047' do
  title 'Amazon Linux 2023 SSHD must accept public key authentication.'
  desc 'Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased.

Multifactor authentication requires using two or more factors to achieve authentication.

Factors include: 
1. Something a user knows (e.g., password/PIN);
2. Something a user has (e.g., cryptographic identification device, token); and
3. Something a user is (e.g., biometric).

A privileged account is defined as an information system account with authorizations of a privileged user.

Network access is defined as access to an information system by a user (or a process acting on behalf of a user) communicating through a network (e.g., local area network, wide area network, or the internet).

The DOD Common Access Card (CAC) with DOD-approved PKI is an example of multifactor authentication.'
  desc 'check', 'Verify Amazon Linux 2023 is configured so that the SSH daemon accepts public key encryption with the following command:
 
$ sudo grep -ir PubkeyAuthentication /etc/ssh/sshd_config /etc/ssh/sshd_config.d/
/etc/ssh/sshd_config:#PubkeyAuthentication yes
/etc/ssh/sshd_config.d/90-PubkeyAuth:PubkeyAuthentication yes
 
If "PubkeyAuthentication" is set to no, the line is commented out, or the line is missing, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to use public key authentication for SSHD by adding or modifying the following line in "/etc/ssh/sshd_config" or in a file in "/etc/ssh/sshd_config.d".

PubkeyAuthentication yes

Restart the SSH daemon for the settings to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-78138r1120127_chk'
  tag severity: 'medium'
  tag gid: 'V-274047'
  tag rid: 'SV-274047r1120129_rule'
  tag stig_id: 'AZLX-23-001230'
  tag gtitle: 'SRG-OS-000105-GPOS-00052'
  tag fix_id: 'F-78043r1120128_fix'
  tag satisfies: ['SRG-OS-000105-GPOS-00052', 'SRG-OS-000106-GPOS-00053', 'SRG-OS-000107-GPOS-00054', 'SRG-OS-000108-GPOS-00055']
  tag 'documentable'
  tag cci: ['CCI-000765', 'CCI-000766', 'CCI-000767', 'CCI-000768']
  tag nist: ['IA-2 (1)', 'IA-2 (2)', 'IA-2 (3)', 'IA-2 (4)']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers without SSH installed', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !directory('/etc/ssh').exist?)
  }

  describe sshd_config do
    its('PubkeyAuthentication') { should cmp 'yes' }
  end
end
