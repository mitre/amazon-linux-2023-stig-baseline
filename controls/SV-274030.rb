control 'SV-274030' do
  title 'Amazon Linux 2023 must manage excess capacity, bandwidth, or other redundancy to limit the effects of information flooding types of denial-of-service (DoS) attacks.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity. 

Managing excess capacity ensures that sufficient capacity is available to counter flooding attacks. Employing increased capacity and service redundancy may reduce the susceptibility to some DoS attacks. Managing excess capacity may include, for example, establishing selected usage priorities, quotas, or partitioning.'
  desc 'check', 'Verify Amazon Linux 2023 manages excess capacity, bandwidth, or other redundancy to limit the effects of information flooding types of DoS attacks. 

Verify nftables is configured to allow rate limits on any connection to the system with the following command:

$ sudo grep -i firewallbackend /etc/firewalld/firewalld.conf
FirewallBackend=nftables'
  desc 'fix', 'Configure Amazon Linux 2023 to manage excess capacity, bandwidth, or other redundancy to limit the effects of information flooding types of DoS attacks.

Configure "nftables" to be the default "firewallbackend" for "firewalld" by adding or editing the following line in "etc/firewalld/firewalld.conf":

FirewallBackend=nftables

Establish rate-limiting rules based on organization-defined types of DoS attacks on impacted network interfaces.'
  impact 0.5
  tag check_id: 'C-78121r1120076_chk'
  tag severity: 'medium'
  tag gid: 'V-274030'
  tag rid: 'SV-274030r1120078_rule'
  tag stig_id: 'AZLX-23-001090'
  tag gtitle: 'SRG-OS-000142-GPOS-00071'
  tag fix_id: 'F-78026r1120077_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe parse_config_file('/etc/firewalld/firewalld.conf') do
    its('FirewallBackend') { should eq 'nftables' }
  end
end
