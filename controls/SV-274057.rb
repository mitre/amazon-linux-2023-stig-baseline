control 'SV-274057' do
  title 'Amazon Linux 2023 must enable FIPS mode.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. Amazon Linux 2023 must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', 'Verify Amazon Linux 2023 is in FIPS mode with the following command:

$ sudo fips-mode-setup --check
FIPS mode is enabled.

If FIPS mode is not enabled, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to implement FIPS mode with the following commands:

$ sudo fips-mode-setup --enable

Reboot the system for the changes to take effect.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000125-GPOS-00065', 'SRG-OS-000396-GPOS-00176', 'SRG-OS-000423-GPOS-00187', 'SRG-OS-000478-GPOS-00223']
  tag gid: 'V-274057'
  tag rid: 'SV-274057r1120159_rule'
  tag stig_id: 'AZLX-23-001280'
  tag fix_id: 'F-78053r1120158_fix'
  tag cci: ['CCI-000068', 'CCI-000877', 'CCI-002418', 'CCI-002450']
  tag nist: ['AC-17 (2)', 'MA-4 c', 'SC-8', 'SC-13 b']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable in a container' do
      skip 'The host OS controls the FIPS mode settings. The host OS should also be scanned with the applicable OS validation profile.'
    end
  elsif input('use_fips') == false
    impact 0.0
    describe 'This control is Not Applicable as FIPS is not required for this system' do
      skip 'This control is Not Applicable as FIPS is not required for this system'
    end
  else
    describe command('fips-mode-setup --check') do
      its('stdout.strip') { should match(/FIPS mode is enabled/) }
    end
  end
end
