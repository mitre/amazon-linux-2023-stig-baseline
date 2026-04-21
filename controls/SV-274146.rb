control 'SV-274146' do
  title 'Amazon Linux 2023 must automatically remove or disable temporary user accounts after 72 hours.'
  desc 'If temporary user accounts remain active when no longer needed or for an excessive period, these accounts may be used to gain unauthorized access. To mitigate this risk, automated termination of all temporary accounts must be set upon account creation.'
  desc 'check', 'Verify Amazon Linux 2023 temporary accounts have been provisioned with an expiration date of 72 hours.

For every existing temporary account, run the following command to obtain its account expiration information.

$ sudo chage -l system_account_name

Verify each of these accounts has an expiration date set within 72 hours.

If any temporary accounts have no expiration date set or do not expire within 72 hours, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 temporary accounts to have an expiration date of 72 hours.

If a temporary account must be created configure the system to terminate the account after a 72 hour time period with the following command to set an expiration date on it. Substitute "system_account_name" with the account to be created.

$ sudo chage -E $(date -d +3days +%Y-%m-%d) system_account_name'
  impact 0.5
  tag check_id: 'C-78237r1120424_chk'
  tag severity: 'medium'
  tag gid: 'V-274146'
  tag rid: 'SV-274146r1120426_rule'
  tag stig_id: 'AZLX-23-002415'
  tag gtitle: 'SRG-OS-000002-GPOS-00002'
  tag fix_id: 'F-78142r1120425_fix'
  tag 'documentable'
  tag cci: ['CCI-000016']
  tag nist: ['AC-2 (2)']
end
