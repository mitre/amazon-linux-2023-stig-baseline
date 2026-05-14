control 'SV-274066' do
  title 'Amazon Linux 2023 must display the Standard Mandatory DOD Notice and Consent Banner before granting local or remote access to the system via a SSH logon.'
  desc %q(Display of a standardized and approved use notification before granting access to the publicly accessible operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.

The banner must be formatted in accordance with applicable DOD policy. Use the following verbiage for operating systems that can accommodate banners of 1300 characters:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

Use the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner:

"I've read & consent to terms in IS user agreem't.")
  desc 'check', %q(Verify Amazon Linux 2023 displays the Standard Mandatory DOD Notice and Consent Banner before granting access to the system from any SSH connection.

Check for the location of the banner file being used with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*banner'
/etc/ssh/sshd_config.d/80-bannerPointer.conf:Banner /etc/issue

This command will return the banner keyword and the name of the file that contains the SSH banner (in this case "/etc/issue").

If the line is commented out, this is a finding.)
  desc 'fix', 'Configure Amazon Linux 2023 to display the Standard Mandatory DOD Notice and Consent Banner before granting access to the system via ssh.

Edit the "etc/ssh/sshd_config" file or a file in "/etc/ssh/sshd_config.d" to uncomment the banner keyword and configure it to point to a file that will contain the logon banner (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor).

An example configuration line is:

Banner /etc/issue'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000228-GPOS-00088'
  tag satisfies: ['SRG-OS-000023-GPOS-00006', 'SRG-OS-000228-GPOS-00088']
  tag gid: 'V-274066'
  tag rid: 'SV-274066r1120186_rule'
  tag stig_id: 'AZLX-23-002005'
  tag fix_id: 'F-78062r1120185_fix'
  tag cci: ['CCI-000048', 'CCI-001384', 'CCI-001385', 'CCI-001386', 'CCI-001387', 'CCI-001388']
  tag nist: ['AC-8 a', 'AC-8 c 1', 'AC-8 c 2', 'AC-8 c 3']
  tag 'host'
  tag 'container-conditional'

  only_if('SSH is not installed on the system this requirement is Not Applicable', impact: 0.0) {
    service('sshd').enabled? || package('openssh-server').installed?
  }

  sshd_bannerfile = input('sshd_bannerfile')

  if virtualization.system.eql?('docker') && !file('/etc/ssh/sshd_config').exist?
    impact 0.0
    describe 'skip' do
      skip 'SSH configuration does not apply inside containers. This control is Not Applicable.'
    end
  else
    describe 'SSH bannerfile' do
      it "should be set to #{sshd_bannerfile}" do
        expect(sshd_config.Banner).to(cmp(sshd_bannerfile), "SSH bannerfile is commented out or not set to the expected value (#{sshd_bannerfile})")
      end
    end
  end
end
