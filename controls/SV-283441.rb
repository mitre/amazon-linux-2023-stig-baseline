control 'SV-283441' do
  title 'Amazon Linux 2023 must enable FIPS mode.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated. This includes NIST FIPS-validated cryptography for the following: Provisioning digital signatures, generating cryptographic hashes, and to protect data requiring data-at-rest protections in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.'
  desc 'check', 'Verify Amazon Linux 2023 is in FIPS mode with the following command:

$ sudo fips-mode-setup --check
FIPS mode is enabled.

If FIPS mode is not enabled, this is a finding.

If any other lines are returned by the above command, run the following command to see the currently applied crypto-policy:

$ update-crypto-policies --show
FIPS

If the policy is not "FIPS" or a FIPS policy authorized by and documented with the ISSO, this is a finding.'
  desc 'fix', 'Configure the Amazon Linux 2023 to implement FIPS mode with the following command:

$ sudo fips-mode-setup --enable

To ensure the kernel enables FIPS mode for early boot, "fips=1" must be added to the grub config:
$ sudo grubby --update-kernel=ALL --args="fips=1"

Verify the setting with the following command:
$ cat /proc/cmdline
BOOT_IMAGE=(hd0,gpt2)/vmlinuz-5.14.0-570.21.1.el9_6.x86_64 root=/dev/mapper/rhel-root ro resume=/dev/mapper/rhel-swap rd.luks.uuid=luks-cd37eb8d-a2c3-4671-96ee-1e6a3a681561 rd.lvm.lv=rhel/root rd.lvm.lv=rhel/swap rhgb quiet fips=1 boot=UUID=acbbb4ee-adc0-4cb2-9546-afab857b8849 audit_backlog_limit=8192 crashkernel=1G-4G:192M,4G-64G:256M,64G-:512M

Reboot the system for the changes to take effect.'
  impact 0.7
  tag check_id: 'C-88006r1192636_chk'
  tag severity: 'high'
  tag gid: 'V-283441'
  tag rid: 'SV-283441r1192638_rule'
  tag stig_id: 'AZLX-23-000050'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-87911r1192637_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe command('fips-mode-setup --check') do
    its('stdout') { should match(/FIPS mode is enabled/) }
  end

  describe command('update-crypto-policies --show') do
    its('stdout.strip') { should match(/^FIPS\b/) }
  end
end
