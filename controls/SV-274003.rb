control 'SV-274003' do
  title 'Amazon Linux 2023 must restrict exposed kernel pointer addresses access.'
  desc 'Exposing kernel pointers (through procfs or "seq_printf()") exposes kernel writeable structures, which may contain functions pointers. If a write vulnerability occurs in the kernel, allowing write access to any of this structure, the kernel can be compromised. This option disallows any program without the CAP_SYSLOG capability to get the addresses of kernel pointers by replacing them with "0".'
  desc 'check', 'Verify Amazon Linux 2023 restricts exposed kernel pointer addresses access by validating the runtime status of the Amazon Linux 2023 kernel.kptr_restrict kernel parameter with the following command:

$ sudo sysctl kernel.kptr_restrict 
kernel.kptr_restrict = 1

If "kernel.kptr_restrict" is not set to "1" or is missing, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to restrict exposed kernel pointer addresses access. 

Add or edit the following line in a system configuration file in the "/etc/sysctl.d/" directory:

kernel.kptr_restrict = 1

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000132-GPOS-00067'
  tag gid: 'V-274003'
  tag rid: 'SV-274003r1198253_rule'
  tag stig_id: 'AZLX-23-000210'
  tag fix_id: 'F-77999r1119996_fix'
  tag cci: ['CCI-000366', 'CCI-001082', 'CCI-002824']
  tag nist: ['CM-6 b', 'SC-2', 'SI-16']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  parameter = 'kernel.kptr_restrict'
  value = 1
  regexp = /^\s*#{parameter}\s*=\s*#{value}\s*$/

  describe kernel_parameter(parameter) do
    its('value') { should eq value }
  end

  search_results = command("/usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' | grep -F #{parameter}").stdout.strip.split("\n")

  correct_result = search_results.any? { |line| line.match(regexp) }
  incorrect_results = search_results.map(&:strip).reject { |line| line.match(regexp) }

  describe 'Kernel config files' do
    it "should configure '#{parameter}'" do
      expect(correct_result).to eq(true), 'No config file was found that correctly sets this action'
    end
    unless incorrect_results.nil?
      it 'should not have incorrect or conflicting setting(s) in the config files' do
        expect(incorrect_results).to be_empty, "Incorrect or conflicting setting(s) found:\n\t- #{incorrect_results.join("\n\t- ")}"
      end
    end
  end
end
