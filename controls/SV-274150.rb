control 'SV-274150' do
  title 'Amazon Linux 2023 must automatically expire temporary accounts within 72 hours.'
  desc 'Temporary accounts are privileged or nonprivileged accounts that are established during pressing circumstances, such as new software or hardware configuration or an incident response, where the need for prompt account activation requires bypassing normal account authorization procedures. If any inactive temporary accounts are left enabled on the system and are not either manually removed or automatically expired within 72 hours, the security posture of the system will be degraded and exposed to exploitation by unauthorized users or insider threat actors.

Temporary accounts are different from emergency accounts. Emergency accounts, also known as "last resort" or "break glass" accounts, are local logon accounts enabled on the system for emergency use by authorized system administrators to manage a system when standard logon methods are failing or not available. Emergency accounts are not subject to manual removal or scheduled expiration requirements.

The automatic expiration of temporary accounts may be extended as needed by the circumstances but it must not be extended indefinitely. A documented permanent account must be established for privileged users who need long-term maintenance accounts.'
  desc 'check', 'Verify Amazon Linux 2023 temporary accounts have been provisioned with an expiration date of 72 hours.

For every existing temporary account, run the following command to obtain its account expiration information:

$ sudo chage -l <temporary_account_name> | grep -i "account expires"

Verify each of these accounts has an expiration date set within 72 hours. 

If any temporary accounts have no expiration date set or do not expire within 72 hours, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to expire temporary accounts after 72 hours with the following command:

$ sudo chage -E $(date -d +3days +%Y-%m-%d) <temporary_account_name>'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000123-GPOS-00064'
  tag gid: 'V-274150'
  tag rid: 'SV-274150r1120438_rule'
  tag stig_id: 'AZLX-23-002435'
  tag fix_id: 'F-78146r1120437_fix'
  tag cci: ['CCI-001682', 'CCI-000016']
  tag nist: ['AC-2 (2)']
  tag 'host'
  tag 'container'

  # NOTE: SV-274146 is extremely similar; both consume the same inputs.
  tmp_users = input('temporary_accounts')
  tmp_max_days = input('temporary_account_max_days')

  # TODO(reviewer): see SV-274146 — same warndays-vs-account-expires concern.

  # Pass-when-empty: the STIG check text says "for every existing temporary
  # account... if any... has no expiration set, this is a finding." Zero temp
  # accounts → zero possible findings → vacuously pass. The check text does
  # not explicitly authorize Not Applicable, so we do not flip impact.
  tmp_users_existing = tmp_users.select { |u| user(u).exists? }
  failing_users = tmp_users_existing.select { |u| user(u).warndays > tmp_max_days }

  describe "Temporary accounts (input: #{tmp_users.empty? ? '(none configured)' : tmp_users.join(', ')}; present on system: #{tmp_users_existing.length})" do
    it "should have warndays <= #{tmp_max_days} for every temporary account that exists" do
      failure_message = "Accounts with warndays > #{tmp_max_days}:\n\t- " +
                        failing_users.map { |u| "#{u} (warndays=#{user(u).warndays})" }.join("\n\t- ")
      expect(failing_users).to be_empty, failure_message
    end
  end
end
