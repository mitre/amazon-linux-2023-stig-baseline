control 'SV-274159' do
  title 'Amazon Linux 2023 must insure all interactive users have a primary group that exists.'
  desc 'If a user is assigned the group identifier (GID) of a group that does not exist on the system, and a group with the GID is subsequently created, the user may have unintended rights to any files associated with the group.'
  desc 'check', 'Verify Amazon Linux 2023 interactive users have a valid GID with the following command:
 
$ sudo pwck -qr 
 
If the system has any interactive users with duplicate GIDs, this is a finding.'
  desc 'fix', %q(Configure Amazon Linux 2023 so that all GIDs are referenced in "/etc/passwd" are defined in "/etc/group".

Edit the file "/etc/passwd" and ensure that every user's GID is a valid GID.)
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag satisfies: ['SRG-OS-000104-GPOS-00051', 'SRG-OS-000121-GPOS-00062', 'SRG-OS-000042-GPOS-00020']
  tag gid: 'V-274159'
  tag rid: 'SV-274159r1120465_rule'
  tag stig_id: 'AZLX-23-002480'
  tag fix_id: 'F-78155r1120464_fix'
  tag cci: ['CCI-000764', 'CCI-000135', 'CCI-000804']
  tag nist: ['IA-2', 'AU-3 (1)', 'IA-8']
  tag 'host'
  tag 'container'

  ignore_shells = input('non_interactive_shells').join('|')
  interactive_users = passwd.where { uid.to_i >= 1000 && !shell.match(ignore_shells) }.users
  interactive_users_without_group = interactive_users.reject { |u| group(user(u).group).exists? }

  describe 'Interactive users' do
    it 'should have a valid primary group' do
      expect(interactive_users_without_group).to be_empty, "Interactive users without a valid primary group:\n\t- #{interactive_users_without_group.join("\n\t- ")}"
    end
  end
end
