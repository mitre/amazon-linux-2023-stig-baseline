control 'SV-274183' do
  title 'Amazon Linux 2023 must protect against or limit the effects of denial-of-service (DoS) attacks by ensuring rate-limiting measures are configured on impacted network interfaces.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of Amazon Linux 2023 to mitigate the impact of DoS attacks that have occurred or are ongoing on system availability. For each system, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or establishing memory partitions). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.'
  desc 'check', 'Verify Amazon Linux 2023 is implementing rate-limiting measures on network interfaces to protect against DoS attacks. 

Access the AWS Management Console:

Sign in to the AWS Management Console and navigate to the EC2 service.

To locate the Application Load Balancer (ALB) in the EC2 dashboard, go to the "Load Balancers" section and find the ALB. 

Check the ALB configuration: Click on the ALB to view its details. The listener configuration for the ALB is located in the "Listener" tab. 

Look for the rate limiting settings: Scroll down to the "Rules" section. If rate limiting is enabled, a rule with the "Rate Limit" action will be displayed.'
  desc 'fix', 'Configure Amazon Linux 2023 to use the AWS ALB rate limiting feature using its built-in rate limiting capabilities. This allows the user to set rate limits at the ALB level, which will apply to all traffic passing through the load balancer.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag gid: 'V-274183'
  tag rid: 'SV-274183r1120714_rule'
  tag stig_id: 'AZLX-23-002605'
  tag fix_id: 'F-78179r1120536_fix'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5', 'SC-5 a']
  tag 'host'

  # TODO - can we tell this from static config on host, or only through the EC2 console in browser?

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe parse_config_file('/etc/firewalld/firewalld.conf') do
    its('FirewallBackend') { should eq 'nftables' }
  end
end
