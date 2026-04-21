control 'SV-274031' do
  title 'Amazon Linux 2023 must have the s-nail package installed.'
  desc 'The "s-nail" package provides the mail command required to allow sending email notifications of unauthorized configuration changes to designated personnel.'
  desc 'check', 'Verify Amazon Linux 2023 has the "s-nail" package is installed on the system with the following command:

$ dnf list --installed s-nail
Installed Packages
s-nail.x86_64          14.9.24-6.amzn2023          @amazonlinux

If the "s-nail" package is not installed, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to have the s-nail package installed with the following command:

$ sudo dnf install -y s-nail'
  impact 0.5
  tag check_id: 'C-78122r1120079_chk'
  tag severity: 'medium'
  tag gid: 'V-274031'
  tag rid: 'SV-274031r1120081_rule'
  tag stig_id: 'AZLX-23-001095'
  tag gtitle: 'SRG-OS-000363-GPOS-00150'
  tag fix_id: 'F-78027r1120080_fix'
  tag 'documentable'
  tag cci: ['CCI-001744']
  tag nist: ['CM-3 (5)']
  tag 'host'
  tag 'container'

  mail_package = input('mail_package')

  describe package(mail_package) do
    it { should be_installed }
  end
end
