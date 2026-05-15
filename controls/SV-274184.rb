control 'SV-274184' do
  title 'Amazon Linux 2023 must implement nonexecutable data to protect its memory from unauthorized code execution.'
  desc "The no-execute (NX) feature uses the segmentation feature on all x86 systems to prevent execution in memory higher than a certain address. It writes an address as a limit in the code segment descriptor, to control where code can be executed, on a per-process basis. When the kernel places a process's memory regions such as the stack and heap higher than this address, the hardware prevents execution in that address range. This is enabled by default on the latest Red Hat and Fedora systems if supported by the hardware."
  desc 'check', %q(Verify Amazon Linux 2023 NX support is enabled with the following command:

$ sudo dmesg | grep '[NX|DX]*protection'
[ 0.000000] NX (Execute Disable) protection: active

If "dmesg" does not show "NX (Execute Disable) protection" active, this is a finding.)
  desc 'fix', 'Configure Amazon Linux 2023 NX support to be enabled by opening a support case via the AWS Console to investigate why NX support is not detected.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000433-GPOS-00192'
  tag gid: 'V-274184'
  tag rid: 'SV-274184r1120540_rule'
  tag stig_id: 'AZLX-23-002610'
  tag fix_id: 'F-78180r1120539_fix'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  grep_output = command("grep ^flags /proc/cpuinfo | grep -Ev '([^[:alnum:]])(nx)([^[:alnum:]]|$)'").stdout.strip
  grubby_output = command("grubby --info=ALL | grep args | grep -E '([^[:alnum:]])(noexec)([^[:alnum:]])'").stdout.strip

  describe 'ExecShield' do
    it 'is enabled on 64-bit AL2023 systems' do
      expect(grep_output).to be_empty
      expect(grubby_output).to be_empty
    end
  end
end
