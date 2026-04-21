control 'SV-274107' do
  title 'Amazon Linux 2023 must off-load audit records onto a different system in the event the audit storage volume is full.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Verify Amazon Linux 2023 takes the appropriate action when the audit storage volume is full using the following command:

$ sudo grep disk_full_action /etc/audit/auditd.conf
disk_full_action = SYSLOG

If the value of the "disk_full_action" option is not "SYSLOG", "SINGLE", or "HALT", or the line is commented out, ask the system administrator to indicate how the system takes appropriate action when an audit storage volume is full. If there is no evidence of appropriate action, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to off-load audit logs in the event the audit storage volume becomes full.

Add or update the following line (depending on configuration "disk_full_action" can be set to "SYSLOG" or "SINGLE" depending on configuration) in "/etc/audit/auditd.conf" file:

disk_full_action = SYSLOG'
  impact 0.5
  tag check_id: 'C-78198r1120307_chk'
  tag severity: 'medium'
  tag gid: 'V-274107'
  tag rid: 'SV-274107r1120309_rule'
  tag stig_id: 'AZLX-23-002220'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-78103r1120308_fix'
  tag satisfies: ['SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224']
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
  tag 'host'
  tag 'container'

  setting = 'DefaultNetstreamDriver'
  expected_value = 'gtls'

  pattern = /[^#]\$#{setting}\s*(?<value>\w+)$/
  setting_check = command("grep -i #{setting} /etc/rsyslog.conf /etc/rsyslog.d/*.conf").stdout.strip.scan(pattern).flatten

  describe 'Rsyslogd DefaultNetstreamDriver' do
    if setting_check.empty?
      it 'should be set' do
        expect(setting_check).to_not be_empty, "'#{setting}' not found (or commented out) in conf file(s)"
      end
    else
      it 'should only be set once' do
        expect(setting_check.length).to eq(1), "'#{setting}' set more than once in conf file(s)"
      end
      it "should be set to '#{expected_value}'" do
        expect(setting_check.first).to eq(expected_value), "'#{setting}' set to '#{setting_check.first}' in conf file(s)"
      end
    end
  end

  # netstream_driver = command('grep -i $DefaultNetstreamDriver /etc/rsyslog.conf /etc/rsyslog.d/*').stdout.strip

  # describe "Rsyslog config" do
  #   it "should encrypt audit records for transfer" do
  #     expect(modload).to be_empty, "ModLoad settings found:\n\t- #{modload.join("\n\t- ")}"
  #   end
  # end
end
