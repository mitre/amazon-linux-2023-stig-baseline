control 'SV-274164' do
  title 'Amazon Linux 2023 must ensure a sticky bit be set on all public directories.'
  desc 'Preventing unauthorized information transfers mitigates the risk of information, including encrypted representations of information, produced by the actions of prior users/roles (or the actions of processes acting on behalf of prior users/roles) from being available to any current users/roles (or current processes) that obtain access to shared system resources (e.g., registers, main memory, hard disks) after those resources have been released back to information systems. The control of information in shared resources is also commonly referred to as object reuse and residual information protection.

This requirement generally applies to the design of an information technology product, but it can also apply to the configuration of particular information system components that are, or use, such products. This can be verified by acceptance/validation processes in DOD or other government agencies.

There may be shared resources with configurable protections (e.g., files in storage) that may be assessed on specific information system components.'
  desc 'check', 'Verify Amazon Linux 2023 world-writable directories have the sticky bit set.

Determine if all world-writable directories have the sticky bit set by running the following command:

$ sudo find / -type d -perm -0002 ! -perm -1000 -exec ls -ld {} +

If any output is returned, these directories are world-writable and do not have the sticky bit set, and this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 world-writable directories to have the sticky bit set to prevent unauthorized and unintended information transferred via shared system resources.

Set the sticky bit on all world-writable directories using the following command:

$ sudo find / -type d -perm -0002 ! -perm -1000 -exec chmod +t {} +'
  impact 0.5
  tag check_id: 'C-78255r1120478_chk'
  tag severity: 'medium'
  tag gid: 'V-274164'
  tag rid: 'SV-274164r1137695_rule'
  tag stig_id: 'AZLX-23-002500'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-78160r1120479_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
  tag 'host'
  tag 'container'

  partitions = etc_fstab.params.map { |partition| partition['mount_point'] }.uniq

  ww_dirs = command("find #{partitions.join(' ')} -xdev -type d -perm -0002 ! -perm -1000 -print 2>/dev/null").stdout.split("\n").reject(&:empty?)

  describe 'World-writable directories without the sticky bit' do
    it 'should not exist' do
      failure_message = "World-writable directories missing the sticky bit (run: chmod +t <dir>):\n\t- #{ww_dirs.join("\n\t- ")}"
      expect(ww_dirs).to be_empty, failure_message
    end
  end
end
