control 'SV-274167' do
  title 'Amazon Linux 2023 must enable auditing of processes that start prior to the audit daemon.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

If auditing is enabled late in the startup process, the actions of some startup processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.'
  desc 'check', %q(Verify Amazon Linux 2023 is configured so that GRUB 2 enables auditing of processes that start prior to the audit daemon with the following commands:

Check that the current GRUB 2 configuration enables auditing:

$ sudo grubby --info=ALL | grep args | grep -v 'audit=1'

If any output is returned, this is a finding.

Check that auditing is enabled by default to persist in kernel updates: 

$ grep audit /etc/default/grub
GRUB_CMDLINE_LINUX="audit=1"

If "audit" is not set to "1", is missing, or is commented out, this is a finding.)
  desc 'fix', 'Configure Amazon Linux 2023 so that GRUB 2 enables auditing of processes that start prior to the audit daemon with the following command:

$ sudo grubby --update-kernel=ALL --args="audit=1"

Add or modify the following line in "/etc/default/grub" to ensure the configuration survives kernel updates:

GRUB_CMDLINE_LINUX="audit=1"'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag satisfies: ['SRG-OS-000062-GPOS-00031', 'SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000466-GPOS-00210', 'SRG-OS-000473-GPOS-00218', 'SRG-OS-000254-GPOS-00095']
  tag gid: 'V-274167'
  tag rid: 'SV-274167r1120489_rule'
  tag stig_id: 'AZLX-23-002515'
  tag fix_id: 'F-78163r1120488_fix'
  tag cci: ['CCI-000169', 'CCI-000130', 'CCI-000135', 'CCI-000172', 'CCI-002884', 'CCI-001464']
  tag nist: ['AU-12 a', 'AU-3 a', 'AU-3 (1)', 'AU-12 c', 'MA-4 (1) (a)', 'AU-14 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  grub_stdout = command('grubby --info=ALL').stdout
  setting = /audit\s*=\s*1/

  describe 'GRUB configuration' do
    it 'should enable auditing of processes that start prior to the audit daemon' do
      expect(parse_config(grub_stdout)['args']).to match(setting), 'Current GRUB configuration does not enable audit=1'
      expect(parse_config_file('/etc/default/grub')['GRUB_CMDLINE_LINUX']).to match(setting), 'audit=1 not configured to persist between kernel updates'
    end
  end
end
