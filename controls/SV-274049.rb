control 'SV-274049' do
  title 'Amazon Linux 2023 must not permit direct logons to the root account using remote access via SSH.'
  desc 'To ensure individual accountability and prevent unauthorized access, organizational users must be individually identified and authenticated. Additionally, an additional layer of security is gained by extending the policy of not logging directly on as root, even though the communications channel may be encrypted.

A group authenticator is a generic account used by multiple individuals. Use of a group authenticator alone does not uniquely identify individual users. Examples of the group authenticator are the Unix OS "root" user account, the Windows "Administrator" account, the "sa" account, or a "helpdesk" account.

For example, the Unix and Windows operating systems offer a "switch user" capability allowing users to authenticate with their individual credentials and, when needed, switch" to the administrator role. This method provides for unique individual authentication prior to using a group authenticator.

Users (and any processes acting on behalf of users) need to be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization, which outlines specific user actions that can be performed on Amazon Linux 2023 without identification or authentication.

Requiring individuals to be authenticated with an individual authenticator prior to using a group authenticator allows for traceability of actions, as well as adding an additional level of protection of the actions that can be taken with group account knowledge.'
  desc 'check', 'Verify Amazon Linux 2023 remote access using SSH prevents users from logging on directly as "root" with the following command:

$ sudo grep -ir PermitRootLogin /etc/ssh/sshd_config /etc/ssh/sshd_config.d/
/etc/ssh/sshd_config:PermitRootLogin no

If the "PermitRootLogin" keyword is set to "yes", is missing, or is commented out, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to prevent SSH users from logging on directly as root add or modify the following line in "/etc/ssh/sshd_config" or in a file in "/etc/ssh/sshd_config.d".

PermitRootLogin no

Restart the SSH daemon for the settings to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000109-GPOS-00056'
  tag gid: 'V-274049'
  tag rid: 'SV-274049r1120747_rule'
  tag stig_id: 'AZLX-23-001240'
  tag fix_id: 'F-78045r1120134_fix'
  tag cci: ['CCI-000770', 'CCI-000366', 'CCI-004045']
  tag nist: ['IA-2 (5)', 'CM-6 b']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers without SSH installed', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !directory('/etc/ssh').exist?)
  }

  describe sshd_config do
    its('PermitRootLogin') { should cmp input('permit_root_login') }
  end
end
