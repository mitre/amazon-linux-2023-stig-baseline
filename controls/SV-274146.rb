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
  tag 'host'
  tag 'container'

  tmp_users = input('temporary_accounts')

  # NOTE: that 274150 is extremely similar to this req, to the point where this input seems
  # appropriate to use for both of them
  tmp_max_days = input('temporary_account_max_days')

  if tmp_users.empty?
    describe 'Temporary accounts' do
      subject { tmp_users }
      it { should be_empty }
    end
  else
    # user has to specify what the tmp accounts are, so we will print a different pass message
    # if none of those tmp accounts even exist on the system for clarity
    tmp_users_existing = tmp_users.select { |u| user(u).exists? }
    failing_users = tmp_users_existing.select { |u| user(u).warndays > tmp_max_days }

    describe 'Temporary accounts' do
      if tmp_users_existing.nil?
        it "should have expiration times less than or equal to '#{tmp_max_days}' days" do
          expect(failing_users).to be_empty, "Failing users:\n\t- #{failing_users.join("\n\t- ")}"
        end
      else
        it "(input as '#{tmp_users.join("', '")}') were not found on this system" do
          expect(tmp_users_existing).to be_empty
        end
      end
    end
  end
end
