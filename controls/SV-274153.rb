control 'SV-274153' do
  title 'Amazon Linux 2023 must use a Linux Security Module configured to enforce limits on system services.'
  desc 'An isolation boundary provides access control and protects the integrity of the hardware, software, and firmware that perform security functions.

Security functions are the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Operating systems implement code separation (i.e., separation of security functions from nonsecurity functions) in a number of ways, including through the provision of security kernels via processor rings or processor modes. For nonkernel code, security function isolation is often achieved through file system protections that serve to protect the code on disk and address space protections that protect executing code.

Developers and implementers can increase the assurance in security functions by employing well-defined security policy models; structured, disciplined, and rigorous hardware and software development techniques; and sound system/security engineering principles. Implementation may include isolation of memory space and libraries. Operating systems restrict access to security functions through the use of access control mechanisms and by implementing least privilege capabilities.'
  desc 'check', 'Verify Amazon Linux 2023 verifies the correct operation of security functions through the use of SELinux with the following command:

$ getenforce
Enforcing

If SELINUX is not set to "Enforcing", this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to verify correct operation of security functions.

Edit the file "/etc/selinux/config" and add or modify the following line:

SELINUX=enforcing 

A reboot is required for the changes to take effect.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag gid: 'V-274153'
  tag rid: 'SV-274153r1120713_rule'
  tag stig_id: 'AZLX-23-002450'
  tag fix_id: 'F-78149r1120446_fix'
  tag cci: ['CCI-001084', 'CCI-002696']
  tag nist: ['SC-3', 'SI-6 a']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) do
    !virtualization.system.eql?('docker')
  end

  describe selinux do
    it { should be_enforcing }
  end
end
