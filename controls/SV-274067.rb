control 'SV-274067' do
  title "Amazon Linux 2023 must allocate audit record storage capacity to store at least one week's worth of audit records, when audit records are not immediately sent to a central audit record storage facility."
  desc 'To ensure operating systems have a sufficient storage capacity in which to write the audit logs, operating systems must be able to allocate audit record storage capacity.'
  desc 'check', 'Verify Amazon Linux 2023 allocates audit record storage capacity to store at least one week of audit records when audit records are not immediately sent to a central audit record storage facility.

Note: The partition size needed to capture a week of audit records is based on the activity level of the system and the total storage capacity available. Typically 10.0 GB of storage space for audit records should be sufficient.

Determine which partition the audit records are being written to with the following command:

$ sudo grep log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log 

Check the size of the partition that audit records are written to with the following command and verify whether it is sufficiently large:

 # df -h /var/log/audit/
/dev/sda2 24G 10.4G 13.6G 43% /var/log/audit 

If the audit record partition is not allocated for sufficient storage capacity, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to provide adequate storage for at least one-week of audit logs when audit records are not immediately sent to a central audit record storage facility.

If the storage partition is not large enough for at least one week of audit logs, then either:

1. Resize the partition to ensure there is enough storage capacity.
2. Create a new partition for the audit logs.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag gid: 'V-274067'
  tag rid: 'SV-274067r1120653_rule'
  tag stig_id: 'AZLX-23-002015'
  tag fix_id: 'F-78063r1120652_fix'
  tag cci: ['CCI-001849', 'CCI-001851']
  tag nist: ['AU-4', 'AU-4 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  audit_log_dir = command("dirname #{auditd_conf.log_file}").stdout.strip

  describe file(audit_log_dir) do
    it { should exist }
    it { should be_directory }
  end

  # Fetch partition sizes in 1K blocks for consistency
  partition_info = command("df -B 1K #{audit_log_dir}").stdout.split("\n")
  partition_sz_arr = partition_info.last.gsub(/\s+/m, ' ').strip.split

  # Get unused space percentage
  percentage_space_unused = (100 - partition_sz_arr[4].to_i)

  describe "auditd_conf's space_left threshold" do
    it 'should be under the amount of space currently available (in 1K blocks) for the audit log directory' do
      expect(auditd_conf.space_left.to_i).to be <= percentage_space_unused
    end
  end
end
