control 'SV-274000' do
  title 'Amazon Linux 2023 systemd-journald service must be enabled.'
  desc 'Failure to a known state can address safety or security in accordance with the mission/business needs of the organization. Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. 

Preserving operating system state information helps to facilitate operating system restart and return to the operational mode of the organization with least disruption to mission/business processes.'
  desc 'check', 'Verify Amazon Linux 2023 is configured so that "systemd-journald" is active with the following command:

$ systemctl is-active systemd-journald
active

If the systemd-journald service is not active, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to enable the systemd-journald service with the following command:

$ sudo systemctl enable --now systemd-journald'
  impact 0.5
  tag check_id: 'C-78091r1119986_chk'
  tag severity: 'medium'
  tag gid: 'V-274000'
  tag rid: 'SV-274000r1119988_rule'
  tag stig_id: 'AZLX-23-000135'
  tag gtitle: 'SRG-OS-000269-GPOS-00103'
  tag fix_id: 'F-77996r1119987_fix'
  tag 'documentable'
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
  tag 'host'

  only_if('Control not applicable within a container without sudo enabled', impact: 0.0) do
    !virtualization.system.eql?('docker')
  end

  describe service('systemd-journald') do
    it { should be_enabled }
    it { should be_running }
  end
end
