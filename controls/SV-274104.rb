control 'SV-274104' do
  title 'Amazon Linux 2023 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to create an account. Auditing account creation actions provides logging that can be used for forensic purposes.

'
  desc 'check', %q(Verify Amazon Linux 2023 generates audit records for all account creations, modifications, disabling, and termination events that affect "/etc/passwd" with the following command:

$ sudo auditctl -l | egrep '(/etc/passwd)' 
-w /etc/passwd -p wa -k identity

If the command does not return a line, or the line is commented out, this is a finding.)
  desc 'fix', 'Configure Amazon Linux 2023 to generate audit records for all account creations, modifications, disabling, and termination events that affect "/etc/passwd".

Enable the auditd daemon so that it can start at boot time:

$ sudo systemctl enable auditd

Add or update the following file system rule to "/etc/audit/rules.d/audit.rules":
-w /etc/passwd -p wa -k identity

Then, restart the auditd service for the changes to take effect:

$ sudo service auditd restart'
  impact 0.5
  tag check_id: 'C-78195r1120298_chk'
  tag severity: 'medium'
  tag gid: 'V-274104'
  tag rid: 'SV-274104r1120300_rule'
  tag stig_id: 'AZLX-23-002205'
  tag gtitle: 'SRG-OS-000004-GPOS-00004'
  tag fix_id: 'F-78100r1120299_fix'
  tag satisfies: ['SRG-OS-000004-GPOS-00004', 'SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000304-GPOS-00121', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000470-GPOS-00214', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000239-GPOS-00089', 'SRG-OS-000240-GPOS-00090', 'SRG-OS-000241-GPOS-00091', 'SRG-OS-000303-GPOS-00120', 'SRG-OS-000466-GPOS-00210', 'SRG-OS-000476-GPOS-00221', 'SRG-OS-000274-GPOS-00104', 'SRG-OS-000275-GPOS-00105', 'SRG-OS-000276-GPOS-00106', 'SRG-OS-000277-GPOS-00107']
  tag 'documentable'
  tag cci: ['CCI-000018', 'CCI-000130', 'CCI-000135', 'CCI-000169', 'CCI-000015', 'CCI-002884', 'CCI-000172', 'CCI-001403', 'CCI-001404', 'CCI-001405', 'CCI-002130']
  tag nist: ['AC-2 (4)', 'AU-3 a', 'AU-3 (1)', 'AU-12 a', 'AC-2 (1)', 'MA-4 (1) (a)', 'AU-12 c', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)']
  tag 'host'

  # Note that this requirement seems to be duplicative with SV-274113 in the source STIG document as of V1R3

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  audit_command = '/etc/passwd'

  describe 'Command' do
    it "#{audit_command} is audited properly" do
      audit_rule = auditd.file(audit_command)
      expect(audit_rule).to exist
      expect(audit_rule.permissions.flatten).to include('w', 'a')
      expect(audit_rule.key.uniq).to include(input('audit_rule_keynames').merge(input('audit_rule_keynames_overrides'))[audit_command])
    end
  end
end
