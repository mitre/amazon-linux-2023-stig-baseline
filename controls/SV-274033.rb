control 'SV-274033' do
  title 'Amazon Linux 2023 must have the policycoreutils package installed.'
  desc 'An isolation boundary provides access control and protects the integrity of the hardware, software, and firmware that perform security functions.

Security functions are the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Operating systems implement code separation (i.e., separation of security functions from nonsecurity functions) in a number of ways, including through the provision of security kernels via processor rings or processor modes. For nonkernel code, security function isolation is often achieved through file system protections that serve to protect the code on disk and address space protections that protect executing code.

Developers and implementers can increase the assurance in security functions by employing well-defined security policy models; structured, disciplined, and rigorous hardware and software development techniques; and sound system/security engineering principles. Implementation may include isolation of memory space and libraries. Operating systems restrict access to security functions through the use of access control mechanisms and by implementing least privilege capabilities.'
  desc 'check', 'Verify Amazon Linux 2023 has the policycoreutils package installed with the following command:

$ dnf list --installed policycoreutils
Installed Packages
policycoreutils.x86_64          3.4-6.amzn2023.0.2          @System

If the "policycoreutils" package is not installed, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to have the policycoreutils package installed with the following command:

$ sudo dnf install -y policycoreutils'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag gid: 'V-274033'
  tag rid: 'SV-274033r1120087_rule'
  tag stig_id: 'AZLX-23-001110'
  tag fix_id: 'F-78029r1120086_fix'
  tag cci: ['CCI-001084', 'CCI-000366']
  tag nist: ['SC-3', 'CM-6 b']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) do
    !virtualization.system.eql?('docker')
  end

  describe package('policycoreutils') do
    it { should be_installed }
  end
end
