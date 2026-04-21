control 'SV-274010' do
  title 'Amazon Linux 2023 must not have the telnet-server package installed.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore, may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Examples of nonessential capabilities include, but are not limited to, games, software packages, tools, and demonstration software, not related to requirements or providing a wide array of functionality not required for every mission, but which cannot be disabled.'
  desc 'check', 'Verify Amazon Linux 2023 does not have the telnet-server package installed with the following command:

$ dnf list --installed telnet-server
Error: No matching Packages to list 

If the "telnet-server" package is installed, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to not have the telnet-server package installed with the following command:

$ sudo dnf -y remove telnet-server'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag gid: 'V-274010'
  tag rid: 'SV-274010r1120018_rule'
  tag stig_id: 'AZLX-23-000315'
  tag fix_id: 'F-78006r1120017_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
  tag 'host'
  tag 'container'

  describe package('telnet-server') do
    it { should_not be_installed }
  end
end
