control 'SV-274143' do
  title 'Amazon Linux 2023 must enforce 24 hours/1 day as the minimum password lifetime.'
  desc "Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, then the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse."
  desc 'check', 'Verify Amazon Linux 2023 enforces 24 hours as the minimum password lifetime for new user accounts with the following command:

$ sudo grep -i pass_min_days /etc/login.defs
PASS_MIN_DAYS 1

If the "PASS_MIN_DAYS" parameter value is not "1" or greater, or is commented out, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to enforce 24 hours as the minimum password lifetime for new user accounts.

Add the following line in "/etc/login.defs" (or modify the line to have the required value):

PASS_MIN_DAYS 1'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000075-GPOS-00043'
  tag gid: 'V-274143'
  tag rid: 'SV-274143r1120417_rule'
  tag stig_id: 'AZLX-23-002400'
  tag fix_id: 'F-78139r1120416_fix'
  tag cci: ['CCI-000198', 'CCI-004066']
  tag nist: ['IA-5 (1) (d)', 'IA-5 (1) (h)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  # TODO: add inputs for a frequecny

  bad_users = users.where { uid >= 1000 }.where { mindays < 1 }.usernames
  in_scope_users = bad_users - input('exempt_home_users')

  describe 'Users should not' do
    it 'be able to change their password more then once a 24 hour period' do
      failure_message = "The following users can update their password more then once a day: #{in_scope_users.join(', ')}"
      expect(in_scope_users).to be_empty, failure_message
    end
  end
end
