control 'SV-274039' do
  title 'Amazon Linux 2023 must implement SSH to protect the confidentiality and integrity of transmitted and received information, as well as information during preparation for transmission.'
  desc 'Encrypting information for transmission protects information from unauthorized disclosure and modification. Cryptographic mechanisms implemented to protect information integrity include, for example, cryptographic hash functions that have common application in digital signatures, checksums, and message authentication codes. 

Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, operating systems need to leverage transmission protection mechanisms such as TLS, SSL VPNs, or IPSec.'
  desc 'check', 'Verify Amazon Linux 2023 has "sshd" set to active with the following command:

$ systemctl is-active sshd
active

If the "sshd" service is not active, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to enable the sshd service run the following command:

$ sudo systemctl enable --now sshd'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000112-GPOS-00057'
  tag satisfies: ['SRG-OS-000423-GPOS-00187', 'SRG-OS-000424-GPOS-00188', 'SRG-OS-000425-GPOS-00189', 'SRG-OS-000426-GPOS-00190', 'SRG-OS-000112-GPOS-00057', 'SRG-OS-000113-GPOS-00058']
  tag gid: 'V-274039'
  tag rid: 'SV-274039r1120105_rule'
  tag stig_id: 'AZLX-23-001185'
  tag fix_id: 'F-78035r1120104_fix'
  tag cci: ['CCI-002418', 'CCI-002420', 'CCI-002421', 'CCI-002422', 'CCI-001941']
  tag nist: ['SC-8', 'SC-8 (2)', 'SC-8 (1)', 'IA-2 (8)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe systemd_service('sshd.service') do
    it { should be_running }
  end
end
