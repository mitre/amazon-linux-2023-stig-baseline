control 'SV-274148' do
  title 'Amazon Linux 2023 must be able to enforce a 60-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If Amazon Linux 2023 does not limit the lifetime of passwords and force users to change their passwords, there is the risk that Amazon Linux 2023 passwords could be compromised.'
  desc 'check', %q(Verify Amazon Linux 2023 enforces the maximum time period for existing passwords is restricted to 60 days with the following commands:

$ sudo awk -F: '$5 > 60 {print $1 " " $5}' /etc/shadow

$ sudo awk -F: '$5 <= 0 {print $1 " " $5}' /etc/shadow

If any results are returned that are not associated with a system account, this is a finding.)
  desc 'fix', 'Configure Amazon Linux 2023 to set noncompliant accounts to enforce a 60-day maximum password lifetime restriction.

$ sudo chage -M 60 [user]'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag gid: 'V-274148'
  tag rid: 'SV-274148r1120432_rule'
  tag stig_id: 'AZLX-23-002425'
  tag fix_id: 'F-78144r1120431_fix'
  tag cci: ['CCI-000199', 'CCI-004066']
  tag nist: ['IA-5 (1) (d)', 'IA-5 (1) (h)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  expected_maxdays = input('pass_max_days')

  bad_users = users.where { uid >= 1000 }.where { maxdays.negative? || maxdays > expected_maxdays }.usernames
  in_scope_users = bad_users - input('exempt_home_users')

  describe 'Interactive users' do
    it "must have a maximum password age of #{expected_maxdays} days or fewer (and non-negative)" do
      failure_message = "The following users have a non-compliant maxdays (> #{expected_maxdays} or negative): #{in_scope_users.join(', ')}"
      expect(in_scope_users).to be_empty, failure_message
    end
  end
end
