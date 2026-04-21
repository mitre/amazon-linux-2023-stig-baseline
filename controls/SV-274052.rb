control 'SV-274052' do
  title 'Amazon Linux 2023 must enable the Pluggable Authentication Module (PAM) interface for SSHD.'
  desc 'If maintenance tools are used by unauthorized personnel, they may accidentally or intentionally damage or compromise the system. The act of managing systems and applications includes the ability to access sensitive application information, such as system configuration details, diagnostic information, user information, and potentially sensitive application data.

Some maintenance and test tools are either standalone devices with their own operating systems or are applications bundled with an operating system.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection. Typically, strong authentication requires authenticators that are resistant to replay attacks and employ multifactor authentication. Strong authenticators include, for example, PKI where certificates are stored on a token protected by a password, passphrase, or biometric.'
  desc 'check', %q(Verify Amazon Linux 2023 SSHD is configured to allow for the UsePAM interface with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*usepam'
/etc/ssh/sshd_config.d/50-redhat.conf:UsePAM yes

If the "UsePAM" keyword is set to "no", is missing, or is commented out, this is a finding.)
  desc 'fix', 'Configure Amazon Linux 2023 SSHD to use the UsePAM interface.

Add or modify the following line in "/etc/ssh/sshd_config":

UsePAM yes

Restart the SSH daemon for the settings to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.7
  tag check_id: 'C-78143r1120142_chk'
  tag severity: 'high'
  tag gid: 'V-274052'
  tag rid: 'SV-274052r1120144_rule'
  tag stig_id: 'AZLX-23-001255'
  tag gtitle: 'SRG-OS-000125-GPOS-00065'
  tag fix_id: 'F-78048r1120143_fix'
  tag 'documentable'
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers without SSH installed', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !directory('/etc/ssh').exist?)
  }

  describe sshd_config do
    its('UsePAM') { should cmp 'yes' }
  end
end
