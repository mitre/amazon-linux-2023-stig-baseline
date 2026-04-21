control 'SV-274129' do
  title 'Amazon Linux 2023 must ensure the /var/log/messages file be group-owned by root.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify Amazon Linux 2023 or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify Amazon Linux 2023 is configured so that the "/var/log/messages" file is group-owned by root with the following command:

$ stat -c "%G %n" /var/log/messages
root /var/log/messages

If "/var/log/messages" does not have a group owner of "root", this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 so that the "/var/log/messages" file is group-owned "root" with the following command:

$ sudo chgrp root /var/log/messages'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag gid: 'V-274129'
  tag rid: 'SV-274129r1120375_rule'
  tag stig_id: 'AZLX-23-002335'
  tag fix_id: 'F-78125r1120374_fix'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe.one do
    describe file('/var/log/messages') do
      its('group') { should be_in input('var_log_messages_group') }
    end
    describe file('/var/log/messages') do
      it { should_not exist }
    end
  end
end
