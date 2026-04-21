control 'SV-274012' do
  title 'Amazon Linux 2023 must have the sudo package installed.'
  desc 'The "sudo" program is designed to allow a system administrator to give limited root privileges to users and log root activity. The basic philosophy is to give as few privileges as possible but still allow system users to get their work done.'
  desc 'check', 'Verify Amazon Linux 2023 has the sudo package installed with the following command:

$ dnf list --installed sudo
Installed Packages
sudo.x86_64          1.9.15-1.p5.amzn2023.0.1          @System

If the "sudo" package is not installed, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to have the sudo package installed with the following command:

$ sudo dnf install -y sudo'
  impact 0.5
  tag check_id: 'C-78103r1120709_chk'
  tag severity: 'medium'
  tag gid: 'V-274012'
  tag rid: 'SV-274012r1120710_rule'
  tag stig_id: 'AZLX-23-001000'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-78008r1120023_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !file('/etc/ssh/sshd_config').exist?)
  }

  describe package('sudo') do
    it { should be_installed }
  end
end
