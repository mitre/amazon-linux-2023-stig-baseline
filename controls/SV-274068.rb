control 'SV-274068' do
  title 'Amazon Linux 2023 must use a separate file system for the system audit data path.'
  desc 'Placing "/var/log/audit" in its own partition enables better separation between audit files and other system files and helps ensure that auditing cannot be halted due to the partition running out of space.'
  desc 'check', 'Verify Amazon Linux 2023 has a separate file system/partition created for the system audit data path with the following command:

Note: /var/log/audit is used as the example as it is a common location.

$ mount | grep /var/log/audit 
UUID=2efb2979-45ac-82d7-0ae632d11f51 on /var/log/home type xfs (rw,realtime,seclabel,attr2,inode64)'
  desc 'fix', 'Configure Amazon Linux 2023 to have a separate file system/partition for the system audit data path.

Migrate the system audit data path onto a separate partition.'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag gid: 'V-274068'
  tag rid: 'SV-274068r1120192_rule'
  tag stig_id: 'AZLX-23-002020'
  tag fix_id: 'F-78064r1120191_fix'
  tag cci: ['CCI-000366', 'CCI-001849']
  tag nist: ['CM-6 b', 'AU-4']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  audit_data_path = command("dirname #{auditd_conf.log_file}").stdout.strip

  describe mount(audit_data_path) do
    it { should be_mounted }
  end

  describe etc_fstab.where { mount_point == audit_data_path } do
    it { should exist }
  end
end
