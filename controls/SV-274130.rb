control 'SV-274130' do
  title 'Amazon Linux 2023 must ensure the /var/log/messages file be owned by root.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify Amazon Linux 2023 or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify Amazon Linux 2023 is configured so that the "/var/log/messages" file is owned by root with the following command:

$ stat -c "%U %n" /var/log/messages
root /var/log/messages

If "/var/log/messages" does not have an owner of "root", this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 so that the "/var/log/messages" file is owned by "root" with the following command:

$ sudo chown root /var/log/messages'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag gid: 'V-274130'
  tag rid: 'SV-274130r1120378_rule'
  tag stig_id: 'AZLX-23-002340'
  tag fix_id: 'F-78126r1120377_fix'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe.one do
    describe file('/var/log/messages') do
      it { should be_owned_by 'root' }
    end
    describe file('/var/log/messages') do
      it { should_not exist }
    end
  end
end
