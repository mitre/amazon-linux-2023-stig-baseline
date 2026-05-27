control 'SV-274155' do
  title 'Amazon Linux 2023 must automatically lock the root account until the root account is released by an administrator when three unsuccessful logon attempts occur during a 15-minute time period.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'Verify Amazon Linux 2023 is configured to lock the root account after three unsuccessful logon attempts with the command:

$ grep even_deny_root /etc/security/faillock.conf
even_deny_root

If the "even_deny_root" option is not set, is missing or commented out, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to lock out the "root" account after a number of incorrect login attempts using "pam_faillock.so", first enable the feature using the following command:
 
$ sudo authselect enable-feature with-faillock 

Then edit the "/etc/security/faillock.conf" file as follows:
 
add or uncomment the following line:
even_deny_root'
  impact 0.5
  tag check_id: 'C-78246r1120451_chk'
  tag severity: 'medium'
  tag gid: 'V-274155'
  tag rid: 'SV-274155r1120453_rule'
  tag stig_id: 'AZLX-23-002460'
  tag gtitle: 'SRG-OS-000329-GPOS-00128'
  tag fix_id: 'F-78151r1120452_fix'
  tag satisfies: ['SRG-OS-000329-GPOS-00128', 'SRG-OS-000021-GPOS-00005']
  tag 'documentable'
  tag cci: ['CCI-000044', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  faillock_conf = file('/etc/security/faillock.conf')

  describe faillock_conf do
    it { should exist }
  end

  if faillock_conf.exist?
    active_lines = faillock_conf.content.lines.map(&:strip).reject { |l| l.empty? || l.start_with?('#') }
    describe '/etc/security/faillock.conf' do
      it 'should set "even_deny_root" (uncommented)' do
        expect(active_lines).to include('even_deny_root'), "Missing or commented out. Active lines:\n\t- #{active_lines.join("\n\t- ")}"
      end
    end
  end
end
