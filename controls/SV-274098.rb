control 'SV-274098' do
  title 'Amazon Linux 2023 must audit all uses of the init command.'
  desc 'Misuse of the init command may cause availability issues for the system.'
  desc 'check', 'Verify Amazon Linux 2023 is configured to audit the execution of the "init" command with the following command:

$ sudo auditctl -l | grep init
-a always,exit -F path=/usr/sbin/init -F perm=x -F auid>=1000 -F auid!=unset -k privileged-init

If the command does not return a line, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 so that the audit system generates an audit event for any successful/unsuccessful uses of the "init" command by adding or updating the following rule in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/sbin/init -F perm=x -F auid>=1000 -F auid!=unset -k privileged-init

To load the rules to the kernel immediately, use the following command: 

$ sudo augenrules --load'
  impact 0.5
  tag check_id: 'C-78189r1120280_chk'
  tag severity: 'medium'
  tag gid: 'V-274098'
  tag rid: 'SV-274098r1120282_rule'
  tag stig_id: 'AZLX-23-002175'
  tag gtitle: 'SRG-OS-000477-GPOS-00222'
  tag fix_id: 'F-78094r1120281_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
  tag 'host'

  audit_command = '/usr/sbin/init'

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
