control 'SV-274125' do
  title 'Amazon Linux 2023 must ensure the /var/log directory have mode "0755" or less permissive.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify Amazon Linux 2023 or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', %q(Verify Amazon Linux 2023 is configured so that the "/var/log" directory has a mode of "0755" or less permissive with the following command:

$ stat -c '%a %n' /var/log
755 /var/log

If "/var/log" does not have a mode of "0755" or less permissive, this is a finding.)
  desc 'fix', 'Configure Amazon Linux 2023 so that the "/var/log" directory has a mode of "0755" by running the following command:

$ sudo chmod 0755 /var/log'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag gid: 'V-274125'
  tag rid: 'SV-274125r1120363_rule'
  tag stig_id: 'AZLX-23-002315'
  tag fix_id: 'F-78121r1120362_fix'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
  tag 'host'
  tag 'container'

  describe directory('/var/log') do
    it { should exist }
    it { should_not be_more_permissive_than('0755') }
  end
end
