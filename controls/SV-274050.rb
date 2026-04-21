control 'SV-274050' do
  title 'Amazon Linux 2023 must be configured so that all network connections associated with SSH traffic are terminated after 10 minutes of becoming unresponsive.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at Amazon Linux 2023 level, and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that Amazon Linux 2023 terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', %q(Verify Amazon Linux 2023 has the "ClientAliveInterval" variable set to a value of "600" or less by performing the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*clientaliveinterval'
/etc/ssh/sshd_config.d/91-ClientAliveInterval.conf:ClientAliveInterval 600

If "ClientAliveInterval" does not exist, does not have a value of "600" or less in "/etc/ssh/sshd_config" or a dropfile in "/etc/ssh/sshd_config.d", or is commented out, this is a finding.)
  desc 'fix', 'Configure Amazon Linux 2023 SSH server to terminate a user session automatically after the SSH client has been unresponsive for 10 minutes.

Note: This setting must be applied in conjunction with "ClientAliveCountMax 1" to function correctly.

Modify or append the following lines in the "/etc/ssh/sshd_config" or a dropfile in "/etc/ssh/sshd_config.d" file:

ClientAliveInterval 600

For the changes to take effect, the SSH daemon must be restarted.

$ sudo systemctl restart sshd.service'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag satisfies: ['SRG-OS-000163-GPOS-00072', 'SRG-OS-000126-GPOS-00066', 'SRG-OS-000279-GPOS-00109', 'SRG-OS-000395-GPOS-00175']
  tag gid: 'V-274050'
  tag rid: 'SV-274050r1120138_rule'
  tag stig_id: 'AZLX-23-001245'
  tag fix_id: 'F-78046r1120137_fix'
  tag cci: ['CCI-001133', 'CCI-002361', 'CCI-002891']
  tag nist: ['SC-10', 'AC-12', 'MA-4 (7)']
  tag 'host'
  tag 'container-conditional'

  only_if('SSH is not installed on the system this requirement is Not Applicable', impact: 0.0) {
    service('sshd').enabled? || package('openssh-server').installed?
  }

  client_alive_count = input('sshd_client_alive_count_max')

  if virtualization.system.eql?('docker') && !file('/etc/ssh/sshd_config').exist?
    impact 0.0
    describe 'skip' do
      skip 'SSH configuration does not apply inside containers. This control is Not Applicable.'
    end
  else
    describe 'SSH ClientAliveCountMax configuration' do
      it "should be set to #{client_alive_count}" do
        expect(sshd_config.ClientAliveCountMax).to(cmp(client_alive_count), "SSH ClientAliveCountMax is commented out or not set to the expected value (#{client_alive_count})")
      end
    end
  end
end
