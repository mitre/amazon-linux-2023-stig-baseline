control 'SV-274096' do
  title 'Amazon Linux 2023 must generate audit records for all account creations, modifications, disabling, and termination events that affect /var/log/faillock.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.'
  desc 'check', 'Verify Amazon Linux 2023 generates audit records for all account creations, modifications, disabling, and termination events that affect "/var/log/faillock" with the following command:

$ sudo auditctl -l | grep /var/log/faillock
-w /var/log/faillock -p wa -k logins

If the command does not return a line, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to generate audit records for all account creations, modifications, disabling, and termination events that affect "/var/log/faillock".

Add or update the following file system rule to "/etc/audit/rules.d/audit.rules":

-w /var/log/faillock -p wa -k logins

To load the rules to the kernel immediately, use the following command: 

$ sudo augenrules --load'
  impact 0.5
  tag check_id: 'C-78187r1120274_chk'
  tag severity: 'medium'
  tag gid: 'V-274096'
  tag rid: 'SV-274096r1120276_rule'
  tag stig_id: 'AZLX-23-002160'
  tag gtitle: 'SRG-OS-000392-GPOS-00172'
  tag fix_id: 'F-78092r1120275_fix'
  tag satisfies: ['SRG-OS-000392-GPOS-00172', 'SRG-OS-000470-GPOS-00214', 'SRG-OS-000473-GPOS-00218']
  tag 'documentable'
  tag cci: ['CCI-000172', 'CCI-002884']
  tag nist: ['AU-12 c', 'MA-4 (1) (a)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  audit_command = '/var/log/faillock'

  describe 'Command' do
    it "#{audit_command} is audited properly" do
      audit_rule = auditd.file(audit_command)
      expect(audit_rule).to exist
      expect(audit_rule.permissions.flatten).to include('w', 'a')
      expect(audit_rule.key.uniq).to include(input('audit_rule_keynames').merge(input('audit_rule_keynames_overrides'))[audit_command])
    end
  end
end
