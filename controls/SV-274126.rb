control 'SV-274126' do
  title 'Amazon Linux 2023 must ensure the /var/log directory be owned by root.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify Amazon Linux 2023 or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify Amazon Linux 2023 is configured so that the "/var/log" directory is owned by root with the following command:

$ stat -c "%U %n" /var/log
root /var/log

If "/var/log" does not have an owner of "root", this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 so that the directory "/var/log" is owned by "root" with the following command:

$ sudo chown root /var/log'
  impact 0.5
  tag check_id: 'C-78217r1120364_chk'
  tag severity: 'medium'
  tag gid: 'V-274126'
  tag rid: 'SV-274126r1120366_rule'
  tag stig_id: 'AZLX-23-002320'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-78122r1120365_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
  tag 'host'
  tag 'container'

  describe directory('/var/log') do
    it { should exist }
    it { should be_owned_by('root') }
  end
end
