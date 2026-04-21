control 'SV-274100' do
  title 'Amazon Linux 2023 must audit all uses of the shutdown command.'
  desc 'Misuse of the shutdown command may cause availability issues for the system.'
  desc 'check', 'Verify Amazon Linux 2023 is configured to audit the execution of the "shutdown" command with the following command:

$ sudo auditctl -l | grep shutdown
-a always,exit -F path=/usr/sbin/shutdown -F perm=x -F auid>=1000 -F auid!=unset -k privileged-shutdown

If the command does not return a line, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 so that the audit system generates an audit event for any successful/unsuccessful uses of the "shutdown" command by adding or updating the following rule in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/sbin/shutdown -F perm=x -F auid>=1000 -F auid!=unset -k privileged-shutdown

To load the rules to the kernel immediately, use the following command: 

$ sudo augenrules --load'
  impact 0.5
  tag check_id: 'C-78191r1120286_chk'
  tag severity: 'medium'
  tag gid: 'V-274100'
  tag rid: 'SV-274100r1120288_rule'
  tag stig_id: 'AZLX-23-002185'
  tag gtitle: 'SRG-OS-000477-GPOS-00222'
  tag fix_id: 'F-78096r1120287_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
  tag 'host'

  audit_command = '/usr/sbin/shutdown'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe 'Command' do
    it "#{audit_command} is audited properly" do
      audit_rule = auditd.file(audit_command)
      expect(audit_rule).to exist
      expect(audit_rule.action.uniq).to cmp 'always'
      expect(audit_rule.list.uniq).to cmp 'exit'
      expect(audit_rule.fields.flatten).to include('perm=x', 'auid>=1000', 'auid!=-1')
      expect(audit_rule.key.uniq).to include(input('audit_rule_keynames').merge(input('audit_rule_keynames_overrides'))[audit_command])
      auditctl_output = command("sudo auditctl -l | grep #{audit_command}").stdout.strip
      expect(auditctl_output).to match(/-S\s+all\b/)
    end
  end
end
