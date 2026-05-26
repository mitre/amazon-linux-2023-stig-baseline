control 'SV-274069' do
  title 'Amazon Linux 2023 must label all off-loaded audit logs before sending them to the central log server.'
  desc 'Enriched logging is needed to determine who, what, and when events occur on a system. Without this, determining root cause of an event will be much more difficult.'
  desc 'check', 'Verify Amazon Linux 2023 is configured so that the Audit Daemon labels all off-loaded audit logs with the following command:

$ sudo grep name_format /etc/audit/auditd.conf
name_format = hostname

If the "name_format" option is not "hostname", "fqd", or "numeric", or the line is commented out, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to be configured so that the Audit Daemon labels all off-loaded audit logs.

Edit the /etc/audit/auditd.conf file and add or update the "name_format" option:

name_format = hostname

The audit daemon must be restarted for changes to take effect.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag satisfies: ['SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224']
  tag gid: 'V-274069'
  tag rid: 'SV-274069r1120195_rule'
  tag stig_id: 'AZLX-23-002025'
  tag fix_id: 'F-78065r1120194_fix'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if input('alternative_logging_method') == ''
    describe parse_config_file('/etc/audit/auditd.conf') do
      its('name_format') { should be_in %w[hostname fqd numeric] }
    end
  else
    describe 'manual check' do
      skip 'Manual check required. Ask the administrator to indicate how logging is done for this system.'
    end
  end
end
