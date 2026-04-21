control 'SV-274027' do
  title 'Amazon Linux 2023 must have the firewalld package installed.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component.

To support the requirements and principles of least functionality, Amazon Linux 2023 must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.'
  desc 'check', 'Verify Amazon Linux 2023 has the firewalld package installed with the following command:

$ dnf list --installed firewalld
Installed Packages
firewalld.noarch          1.2.3-1.amzn2023          @amazonlinux

If the "firewalld" package is not installed, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to have the firewalld package installed with the following command:

$ sudo dnf install -y firewalld'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag gid: 'V-274027'
  tag rid: 'SV-274027r1120069_rule'
  tag stig_id: 'AZLX-23-001075'
  tag fix_id: 'F-78023r1120068_fix'
  tag cci: ['CCI-002314', 'CCI-000366', 'CCI-000382', 'CCI-002322', 'CCI-000015']
  tag nist: ['AC-17 (1)', 'CM-6 b', 'CM-7 b', 'AC-17 (9)', 'AC-2 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  alternate_firewall_tool = input('alternate_firewall_tool')

  if alternate_firewall_tool == ''
    describe package('firewalld') do
      it { should be_installed }
    end
  else
    describe package(alternate_firewall_tool) do
      it { should be_installed }
    end
  end
end
