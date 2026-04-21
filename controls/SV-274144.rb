control 'SV-274144' do
  title 'Amazon Linux 2023 must enforce a delay of at least four seconds between logon prompts following a failed logon attempt.'
  desc 'Increasing the time between a failed authentication attempt and re-prompting to enter credentials helps to slow a single-threaded brute force attack.'
  desc 'check', 'Verify Amazon Linux 2023 enforces a delay of at least four seconds between console logon prompts following a failed logon attempt with the following command:

$ sudo grep -i fail_delay /etc/login.defs
FAIL_DELAY 4

If the value of "FAIL_DELAY" is not set to "4" or greater, the line is commented out, or the line is missing, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to enforce a delay of at least four seconds between logon prompts following a failed console logon attempt.

Modify the "/etc/login.defs" file to set the "FAIL_DELAY" parameter to "4" or greater:

FAIL_DELAY 4'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00226'
  tag gid: 'V-274144'
  tag rid: 'SV-274144r1120420_rule'
  tag stig_id: 'AZLX-23-002405'
  tag fix_id: 'F-78140r1120419_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe login_defs do
    its('FAIL_DELAY.to_i') { should cmp >= input('login_prompt_delay') }
  end
end
