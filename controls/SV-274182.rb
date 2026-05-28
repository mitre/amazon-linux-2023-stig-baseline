control 'SV-274182' do
  title 'Amazon Linux 2023 file system automount function must be disabled unless required.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

Peripherals include, but are not limited to, such devices as flash drives, external storage, and printers.'
  desc 'check', 'Verify Amazon Linux 2023 disables the file system automount function with the following command:

$ sudo systemctl is-enabled autofs
masked

If the returned value is not "masked", "disabled", "Failed to get unit file state for autofs.service for autofs", or "enabled", and is not documented as operational requirement with the information system security officer (ISSO), this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to disable the ability to automount devices.

The autofs service can be disabled with the following command:

$ sudo systemctl mask --now autofs.service'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000378-GPOS-00163'
  tag gid: 'V-274182'
  tag rid: 'SV-274182r1120729_rule'
  tag stig_id: 'AZLX-23-002600'
  tag fix_id: 'F-78178r1120533_fix'
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if service('autofs').installed?
    describe service('autofs') do
      it { should_not be_enabled }
      it { should_not be_running }
    end
  else
    describe 'autofs service' do
      it 'is not installed' do
        expect(service('autofs').installed?).to eq(false)
      end
    end
  end
end
