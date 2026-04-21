control 'SV-274101' do
  title 'Amazon Linux 2023 audit tools must have a mode of "0755" or less permissive.'
  desc 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

Operating systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys to make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'Verify Amazon Linux 2023 audit tools have a mode of "0755" or less with the following command:

$ stat -c "%a %n" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/rsyslogd /sbin/augenrules
755 /sbin/auditctl
755 /sbin/aureport
755 /sbin/ausearch
750 /sbin/autrace
755 /sbin/auditd
755 /sbin/rsyslogd
755 /sbin/augenrules

If any of the audit tool files have a mode more permissive than "0755", this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 audit tools to have a mode of "0755" by running the following command:

$ sudo chmod 0755 [audit_tool]

Replace "[audit_tool]" with each audit tool that has a more permissive mode than "0755".'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000256-GPOS-00097'
  tag gid: 'V-274101'
  tag rid: 'SV-274101r1120291_rule'
  tag stig_id: 'AZLX-23-002190'
  tag fix_id: 'F-78097r1120290_fix'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9', 'AU-9 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  audit_tools = input('audit_tools')

  failing_tools = audit_tools.select { |at| file(at).more_permissive_than?(input('audit_tool_mode')) }

  describe 'Audit executables' do
    it "should be no more permissive than '#{input('audit_tool_mode')}'" do
      expect(failing_tools).to be_empty, "Failing tools:\n\t- #{failing_tools.join("\n\t- ")}"
    end
  end
end
