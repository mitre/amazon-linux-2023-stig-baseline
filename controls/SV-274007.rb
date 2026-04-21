control 'SV-274007' do
  title 'Amazon Linux 2023 must not have the vsftpd package installed.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore, may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Examples of nonessential capabilities include, but are not limited to, games, software packages, tools, and demonstration software, not related to requirements or providing a wide array of functionality not required for every mission, but which cannot be disabled.'
  desc 'check', 'Verify Amazon Linux 2023 does not have the vsftpd package installed with the following command:

$ dnf list --installed vsftpd
Error: No matching Packages to list

If the "vsftpd" package is installed, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to not have the vsftpd package installed with the following command:

$ sudo dnf -y remove vsftpd'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag gid: 'V-274007'
  tag rid: 'SV-274007r1120009_rule'
  tag stig_id: 'AZLX-23-000300'
  tag fix_id: 'F-78003r1120008_fix'
  tag cci: ['CCI-000366', 'CCI-000197', 'CCI-000381']
  tag nist: ['CM-6 b', 'IA-5 (1) (c)', 'CM-7 a']
  tag 'host'
  tag 'container'

  if input('ftp_required')
    describe package('vsftpd') do
      it { should be_installed }
    end
  else
    describe package('vsftpd') do
      it { should_not be_installed }
    end
  end
end
