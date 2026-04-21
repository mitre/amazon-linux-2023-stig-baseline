control 'SV-274111' do
  title 'Amazon Linux 2023 must allow only the information system security manager (ISSM) (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', 'Verify Amazon Linux 2023 is configured so that files in "/etc/audit/rules.d/" and the "/etc/audit/auditd.conf" file have a mode of "0640" or less permissive by using the following commands:

$ sudo find /etc/audit/rules.d/ /etc/audit/audit.rules /etc/audit/auditd.conf -type f -exec stat -c "%a %n" {} \\;
600 /etc/audit/rules.d/audit.rules
640 /etc/audit/audit.rules
640 /etc/audit/auditd.conf

If the files in the "/etc/audit/rules.d/" directory or the "/etc/audit/auditd.conf" file have a mode more permissive than "0640", this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 so that files in "/etc/audit/rules.d/" and the "/etc/audit/auditd.conf" file have a mode of "0640" or less permissive with the following commands:

$ sudo chmod 0640 /etc/audit/rules.d/audit.rules
$ sudo chmod 0640 /etc/audit/rules.d/[customrulesfile].rules
$ sudo chmod 0640 /etc/audit/auditd.conf'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000063-GPOS-00032'
  tag gid: 'V-274111'
  tag rid: 'SV-274111r1120321_rule'
  tag stig_id: 'AZLX-23-002240'
  tag fix_id: 'F-78107r1120320_fix'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  rules_files = bash('ls -d /etc/audit/rules.d/*.rules').stdout.strip.split.append('/etc/audit/auditd.conf')

  audit_conf_mode = input('audit_conf_mode')
  failing_files = rules_files.select { |rf| file(rf).more_permissive_than?(audit_conf_mode) }

  describe 'Audit configuration files' do
    it "should be no more permissive than '#{audit_conf_mode}'" do
      expect(failing_files).to be_empty, "Failing files:\n\t- #{failing_files.join("\n\t- ")}"
    end
  end
end
