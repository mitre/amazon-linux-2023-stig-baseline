control 'SV-274028' do
  title 'Amazon Linux 2023 must have the firewalld service active.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Operating systems are capable of providing a variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component.

To support the requirements and principles of least functionality, Amazon Linux 2023 must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.'
  desc 'check', 'Verify Amazon Linux 2023 firewalld service is active with the following command:

$ systemctl is-active firewalld 
active

If the "firewalld" service is not active, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to enable the firewalld service with the following command:

$ sudo systemctl enable --now firewalld'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag gid: 'V-274028'
  tag rid: 'SV-274028r1190806_rule'
  tag stig_id: 'AZLX-23-001080'
  tag fix_id: 'F-78024r1120071_fix'
  tag cci: ['CCI-002314', 'CCI-000366', 'CCI-000382', 'CCI-002322', 'CCI-000015']
  tag nist: ['AC-17 (1)', 'CM-6 b', 'CM-7 b', 'AC-17 (9)', 'AC-2 (1)']

  only_if('This requirment is Not Applicable in the container, the container management platform manages the firewall service', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if input('external_firewall')
    message = 'This system uses an externally managed firewall service, verify with the system administrator that the firewall is configured to requirements'
    describe message do
      skip message
    end
  else
    describe package('firewalld') do
      it { should be_installed }
    end
    describe firewalld do
      it { should be_installed }
      it { should be_running }
    end
  end
end
