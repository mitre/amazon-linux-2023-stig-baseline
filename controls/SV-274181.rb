control 'SV-274181' do
  title 'Amazon Linux 2023 must ensure the pcscd service is active.'
  desc 'The information system ensures that even if the information system is compromised, that compromise will not affect credentials stored on the authentication device.

The daemon program for pcsc-lite and the MuscleCard framework is pcscd. It is a resource manager that coordinates communications with smart card readers and smart cards and cryptographic tokens connected to the system.'
  desc 'check', 'Verify Amazon Linux 2023 is configured so that the "pcscd" service is active with the following command:

$ systemctl is-active pcscd
active

If the pcscdservice is not active, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 so that the "pcscd" service is active with the following command:

$ sudo systemctl enable --now pcscd'
  impact 0.5
  tag check_id: 'C-78272r1120529_chk'
  tag severity: 'medium'
  tag gid: 'V-274181'
  tag rid: 'SV-274181r1120531_rule'
  tag stig_id: 'AZLX-23-002595'
  tag gtitle: 'SRG-OS-000375-GPOS-00160'
  tag fix_id: 'F-78177r1120530_fix'
  tag 'documentable'
  tag cci: ['CCI-001948', 'CCI-004046']
  tag nist: ['IA-2 (11)', 'IA-2 (6) (a)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if input('smart_card_enabled')
    describe service('pcscd') do
      it { should be_enabled }
      it { should be_running }
    end
  else
    impact 0.0
    describe 'The system is not smartcard enabled thus this control is Not Applicable' do
      skip 'The system is not using Smartcards / PIVs to fulfil the MFA requirement; this control is Not Applicable.'
    end
  end
end
