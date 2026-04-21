control 'SV-274127' do
  title 'Amazon Linux 2023 must ensure the /var/log directory be group-owned by root.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify Amazon Linux 2023 or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify Amazon Linux 2023 is configured so the "/var/log" directory is group-owned by root with the following command:

$ stat -c "%G %n" /var/log
root /var/log

If "/var/log" does not have a group owner of "root", this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 so that the "/var/log" is group-owned "root" with the following command:

$ sudo chgrp root /var/log'
  impact 0.5
  tag check_id: 'C-78218r1120367_chk'
  tag severity: 'medium'
  tag gid: 'V-274127'
  tag rid: 'SV-274127r1120369_rule'
  tag stig_id: 'AZLX-23-002325'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-78123r1120368_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
