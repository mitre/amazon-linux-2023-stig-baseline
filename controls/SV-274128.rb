control 'SV-274128' do
  title 'Amazon Linux 2023 must ensure the /var/log/messages file have mode "0640" or less permissive.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify Amazon Linux 2023 or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', %q(Verify Amazon Linux 2023 is configured so that the "/var/log/messages" file has a mode of "0640" or less permissive with the following command:

$ stat -c '%a %n' /var/log/messages
600 /var/log/messages

If "/var/log/messages" does not have a mode of "0640" or less permissive, this is a finding.)
  desc 'fix', 'Configure Amazon Linux 2023 so that the "/var/log/messages" file has a mode of "0640" with the following command:

$ sudo chmod 0640 /var/log/messages'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag gid: 'V-274128'
  tag rid: 'SV-274128r1120372_rule'
  tag stig_id: 'AZLX-23-002330'
  tag fix_id: 'F-78124r1120371_fix'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe.one do
    describe file('/var/log/messages') do
      it { should_not be_more_permissive_than('0640') }
    end
    describe file('/var/log/messages') do
      it { should_not exist }
    end
  end
end
