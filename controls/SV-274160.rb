control 'SV-274160' do
  title 'Amazon Linux 2023 must ensure all interactive users have unique User IDs (UIDs).'
  desc 'To ensure accountability and prevent unauthenticated access, interactive users must be identified and authenticated to prevent potential misuse and compromise of the system.'
  desc 'check', %q(Verify Amazon Linux 2023 contains no duplicate UIDs for interactive users with the following command:

$ sudo awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd 

If output is produced and the accounts listed are interactive user accounts, this is a finding.)
  desc 'fix', 'Configure Amazon Linux 2023 to contain no duplicate UIDs for interactive users.

Edit the file "/etc/passwd" and provide each interactive user account that has a duplicate UID with a unique UID.'
  impact 0.5
  tag check_id: 'C-78251r1120466_chk'
  tag severity: 'medium'
  tag gid: 'V-274160'
  tag rid: 'SV-274160r1120663_rule'
  tag stig_id: 'AZLX-23-002485'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-78156r1120467_fix'
  tag 'documentable'
  tag cci: ['CCI-000764', 'CCI-000804', 'CCI-000135']
  tag nist: ['IA-2', 'IA-8', 'AU-3 (1)']
  tag 'host'
  tag 'container'

  user_count = passwd.where { uid.to_i >= 1000 }.entries.length

  describe "Count of interactive unique user IDs should match interactive user count (#{user_count}): UID count" do
    subject { passwd.where { uid.to_i >= 1000 }.uids.uniq.length }
    it { should eq user_count }
  end
end
