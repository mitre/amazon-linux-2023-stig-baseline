control 'SV-274018' do
  title 'Amazon Linux 2023 must produce audit records containing information to establish what type of events occurred.'
  desc 'Without establishing what type of events occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in Amazon Linux 2023 audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured operating system.'
  desc 'check', 'Verify Amazon Linux 2023 is configured to produce audit records with the following command:

$ sudo systemctl status auditd.service
auditd.service - Security Auditing Service
 Loaded:loaded (/usr/lib/systemd/system/auditd.service; enabled; preset: enabled)
 Active: active (running) since Wed 2024-01-131 12:56:56 EST; 1 weeks 0 days ago

If the audit service is not "active" and "running", this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 so that the audit service to produce audit records containing the information needed to establish when an event occurred with the following commands:

$ sudo systemctl enable auditd.service

$ sudo systemctl start auditd.service'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag satisfies: ['SRG-OS-000062-GPOS-00031', 'SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000473-GPOS-00218', 'SRG-OS-000254-GPOS-00095', 'SRG-OS-000038-GPOS-00016', 'SRG-OS-000039-GPOS-00017', 'SRG-OS-000040-GPOS-00018', 'SRG-OS-000041-GPOS-00019', 'SRG-OS-000042-GPOS-00021', 'SRG-OS-000051-GPOS-00024', 'SRG-OS-000054-GPOS-00025', 'SRG-OS-000122-GPOS-00063', 'SRG-OS-000255-GPOS-00096', 'SRG-OS-000337-GPOS-00129', 'SRG-OS-000348-GPOS-00136', 'SRG-OS-000349-GPOS-00137', 'SRG-OS-000350-GPOS-00138', 'SRG-OS-000351-GPOS-00139', 'SRG-OS-000352-GPOS-00140', 'SRG-OS-000353-GPOS-00141', 'SRG-OS-000354-GPOS-00142', 'SRG-OS-000358-GPOS-00145', 'SRG-OS-000365-GPOS-00152', 'SRG-OS-000475-GPOS-00220', 'SRG-OS-000755-GPOS-00220']
  tag gid: 'V-274018'
  tag rid: 'SV-274018r1120042_rule'
  tag stig_id: 'AZLX-23-001030'
  tag fix_id: 'F-78014r1120041_fix'
  tag cci: ['CCI-000169', 'CCI-000130', 'CCI-000135', 'CCI-000172', 'CCI-001464', 'CCI-002884', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000154', 'CCI-000158', 'CCI-001876', 'CCI-001487', 'CCI-001914', 'CCI-001875', 'CCI-001877', 'CCI-001878', 'CCI-001879', 'CCI-001880', 'CCI-001881', 'CCI-001882', 'CCI-001889', 'CCI-003938', 'CCI-004188']
  tag nist: ['AU-12 a', 'AU-3 a', 'AU-3 (1)', 'AU-12 c', 'AU-14 (1)', 'MA-4 (1) (a)', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-6 (4)', 'AU-7 (1)', 'AU-7 a', 'AU-3 f', 'AU-12 (3)', 'AU-7 b', 'AU-8 b', 'CM-5 (1) (b)', 'MA-3 (5)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  grub_stdout = command('grubby --info=ALL').stdout
  setting = /audit\s*=\s*1/

  describe 'GRUB config' do
    it 'should enable page poisoning' do
      expect(parse_config(grub_stdout)['args']).to match(setting), 'Current GRUB configuration does not disable this setting'
      expect(parse_config_file('/etc/default/grub')['GRUB_CMDLINE_LINUX']).to match(setting), 'Setting not configured to persist between kernel updates'
    end
  end
end
