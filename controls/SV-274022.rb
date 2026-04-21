control 'SV-274022' do
  title 'Amazon Linux 2023 must have the chrony package installed.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.'
  desc 'check', 'Verify Amazon Linux 2023 has the chrony package installed with the following command:

$ sudo dnf list --installed chrony
Installed Packages
chrony.x86_64          4.3-1.amzn2023.0.5          @System

If the "chrony" package is not installed, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to have the chrony package installed.

The chrony package can be installed with the following command:
 
$ sudo dnf install -y chrony'
  impact 0.5
  tag check_id: 'C-78113r1120052_chk'
  tag severity: 'medium'
  tag gid: 'V-274022'
  tag rid: 'SV-274022r1120054_rule'
  tag stig_id: 'AZLX-23-001050'
  tag gtitle: 'SRG-OS-000355-GPOS-00143'
  tag fix_id: 'F-78018r1120053_fix'
  tag 'documentable'
  tag cci: ['CCI-001891', 'CCI-004923']
  tag nist: ['AU-8 (1) (a)', 'SC-45 (1) (a)']
  tag 'host'
  tag 'container'

  describe package('chrony') do
    it { should be_installed }
  end
end
