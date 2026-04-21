control 'SV-274011' do
  title 'Amazon Linux 2023 must not have the gssproxy package installed.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Examples of nonessential capabilities include, but are not limited to, games, software packages, tools, and demonstration software, not related to requirements or providing a wide array of functionality not required for every mission, but which cannot be disabled.'
  desc 'check', 'Note: If NFS mounts are authorized and in use on the system, this control is not applicable.

Verify Amazon Linux 2023 does not have the gssproxy package installed with the following command:

$ dnf list --installed gssproxy
Error: No matching Packages to list 

If the "gssproxy" package is installed, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to not have the gssproxy package installed.

The gssproxy package can be removed with the following command:

$ sudo dnf -y remove gssproxy'
  impact 0.5
  tag check_id: 'C-78102r1183999_chk'
  tag severity: 'medium'
  tag gid: 'V-274011'
  tag rid: 'SV-274011r1184000_rule'
  tag stig_id: 'AZLX-23-000320'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-78007r1120020_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
  tag 'host'
  tag 'container'

  describe command('dnf -q repolist --enabled') do
    its('stdout') { should_not match(/epel/i) }
  end
end
