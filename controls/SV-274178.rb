control 'SV-274178' do
  title 'Amazon Linux 2023 must prevent files with the setuid and setgid bit set from being executed on the /boot/efi directory.'
  desc 'The "nosuid" mount option causes the system not to execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.'
  desc 'check', %q(Verify Amazon Linux 2023 is configured so that the /boot/efi directory is mounted with the "nosuid" option with the following command:

$ mount | grep '\s/boot/efi\s'

/dev/sda1 on /boot/efi type vfat (rw,nosuid,relatime,fmask=0077,dmask=0077,codepage=437,iocharset=ascii,shortname=winnt,errors=remount-ro)

If the /boot/efi file system does not have the "nosuid" option set, this is a finding.)
  desc 'fix', 'Configure Amazon Linux 2023 so that the /boot/efi directory is mounted with the "nosuid" option.

Modify "/etc/fstab" to use the "nosuid" option on the "/boot/efi" directory.'
  impact 0.5
  tag check_id: 'C-78269r1120520_chk'
  tag severity: 'medium'
  tag gid: 'V-274178'
  tag rid: 'SV-274178r1120522_rule'
  tag stig_id: 'AZLX-23-002580'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-78174r1120521_fix'
  tag 'documentable'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  interactive_users = passwd.where {
    uid.to_i >= 1000 && shell !~ /nologin/
  }

  interactive_user_homedirs = interactive_users.homes.map { |home_path|
    home_path.match(%r{^(.*)/.*$}).captures.first
  }.uniq

  option = 'nosuid'

  mounted_on_root = interactive_user_homedirs.select { |dir| dir == '/' }
  not_configured = interactive_user_homedirs.reject { |dir| etc_fstab.where { mount_point == dir }.configured? }
  option_not_set = interactive_user_homedirs.reject { |dir| etc_fstab.where { mount_point == dir }.mount_options.flatten.include?(option) }

  describe 'All interactive user home directories' do
    it "should not be mounted under root ('/')" do
      expect(mounted_on_root).to be_empty, "Home directories mounted on root ('/'):\n\t- #{mounted_on_root.join("\n\t- ")}"
    end
    it 'should be configured in /etc/fstab' do
      expect(not_configured).to be_empty, "Unconfigured home directories:\n\t- #{not_configured.join("\n\t- ")}"
    end
    if (option_not_set - not_configured).nil?
      it "should have the '#{option}' mount option set" do
        expect(option_not_set - not_configured).to be_empty, "Mounted home directories without '#{option}' set:\n\t- #{not_configured.join("\n\t- ")}"
      end
    end
  end
end
