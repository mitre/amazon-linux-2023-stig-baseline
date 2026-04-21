control 'SV-274019' do
  title 'Amazon Linux 2023 audispd-plugins package must be installed.'
  desc 'The "audispd-plugins" package provides plugins for the real-time interface to the audit subsystem, "audispd". These plugins can, for example, relay events to remote machines or analyze events for suspicious behavior.'
  desc 'check', 'Verify Amazon Linux 2023 has the audispd-plugins package installed with the following command:

$ sudo dnf list --installed audispd-plugins
Installed Packages
audispd-plugins.x86_64          3.0.6-1.amzn2023.0.2          @amazonlinux

If the "audispd-plugins" package is not installed, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to have the audispd-plugins package installed.

Install the audispd-plugins package with the following command:
 
$ sudo dnf install -y audispd-plugins'
  impact 0.5
  tag check_id: 'C-78110r1120043_chk'
  tag severity: 'medium'
  tag gid: 'V-274019'
  tag rid: 'SV-274019r1120045_rule'
  tag stig_id: 'AZLX-23-001035'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-78015r1120044_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe package('audispd-plugins') do
    it { should be_installed }
  end
end
