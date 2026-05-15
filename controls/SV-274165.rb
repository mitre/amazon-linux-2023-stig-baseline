control 'SV-274165' do
  title 'Amazon Linux 2023 must ensure all world-writable directories be owned by root, sys, bin, or an application user.'
  desc 'Preventing unauthorized information transfers mitigates the risk of information, including encrypted representations of information, produced by the actions of prior users/roles (or the actions of processes acting on behalf of prior users/roles) from being available to any current users/roles (or current processes) that obtain access to shared system resources (e.g., registers, main memory, hard disks) after those resources have been released back to information systems. The control of information in shared resources is also commonly referred to as object reuse and residual information protection.

This requirement generally applies to the design of an information technology product, but it can also apply to the configuration of particular information system components that are, or use, such products. This can be verified by acceptance/validation processes in DOD or other government agencies.

There may be shared resources with configurable protections (e.g., files in storage) that may be assessed on specific information system components.'
  desc 'check', 'Verify Amazon Linux 2023 world writable directories are owned by root, a system account, or an application account with the following command:

$ sudo find / -xdev -type d -perm -0002 ! -user root ! -uid +999 -exec ls -ld {} +

If there is output, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 public directories to be owned by root or a system account to prevent unauthorized and unintended information transferred via shared system resources.

Set the owner of all public directories as root or a system account using the following command:

$ sudo find / -xdev -type d -perm -0002 ! -user root ! -uid +999 -exec chown root:root {} +'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag gid: 'V-274165'
  tag rid: 'SV-274165r1137695_rule'
  tag stig_id: 'AZLX-23-002505'
  tag fix_id: 'F-78161r1120482_fix'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
  tag 'host'
  tag 'container'

  partitions = etc_fstab.params.map { |partition| partition['mount_point'] }.uniq

  ww_dirs = command("find #{partitions.join(' ')} -xdev -type d -perm -0002 ! -user root ! -uid +999 -print 2>/dev/null").stdout.split("\n")

  describe 'World-writable directories not owned by root or a uid > 999' do
    subject { ww_dirs }
    it { should be_empty }
  end
end
