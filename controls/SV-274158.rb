control 'SV-274158' do
  title 'Amazon Linux 2023 must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL) and vulnerability assessments.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Operating systems are capable of providing a variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component.

To support the requirements and principles of least functionality, Amazon Linux 2023 must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.'
  desc 'check', 'Verify Amazon Linux 2023 firewall is configured to block unregistered ports, protocols, and services. 

Inspect the list of enabled firewall ports and verify they are configured correctly by running the following command:

$ sudo firewall-cmd --list-all 

Ask the system administrator for the site or program PPSM Component Local Service Assessment (CLSA). Verify the services allowed by the firewall match the PPSM CLSA. 

If there are additional ports, protocols, or services that are not in the PPSM CLSA, or there are ports, protocols, or services that are prohibited by the PPSM CAL, or there are no firewall rules configured, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to prohibit/restrict Functions, Ports, Protocols, and Services. Use firewall-cmd to manage firewalld. 

To open a port for a service, configure firewalld using the following command:

$ sudo firewall-cmd --permanent --add-port=port_number/tcp
or
$ sudo firewall-cmd --permanent --add-service=service_name'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag gid: 'V-274158'
  tag rid: 'SV-274158r1184031_rule'
  tag stig_id: 'AZLX-23-002475'
  tag fix_id: 'F-78154r1184030_fix'
  tag cci: ['CCI-000381', 'CCI-000382', 'CCI-002314']
  tag nist: ['CM-7 a', 'CM-7 b', 'AC-17 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !file('/etc/chrony.conf').exist?)
  }

  chrony_conf = ntp_conf('/etc/chrony.conf')

  describe chrony_conf do
    its('cmdport') { should cmp 0 }
  end
end
