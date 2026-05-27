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

  # NOTE: The body delivered by saf-delta contained the rsyslog
  # $DefaultNetstreamDriver check from a different control. This control's
  # title and check text are about auditd's disk_full_action.
  allowed_actions = input('disk_full_action')

  describe 'auditd disk_full_action' do
    subject { auditd_conf.disk_full_action.to_s.upcase }
    it "should be one of: #{allowed_actions.join(', ')}" do
      expect(subject).to be_in(allowed_actions),
        "auditd_conf disk_full_action is '#{subject}'; expected one of #{allowed_actions.join(', ')}"
    end
  end
end
