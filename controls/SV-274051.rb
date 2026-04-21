control 'SV-274051' do
  title 'Amazon Linux 2023 must be configured so that all network connections associated with SSH traffic terminate after becoming unresponsive.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at Amazon Linux 2023 level, and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that Amazon Linux 2023 terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.

'
  desc 'check', %q(Verify Amazon Linux 2023 SSHD has the "ClientAliveCountMax" set to "1" by performing the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*clientalivecountmax'
/etc/ssh/sshd_config.d/92-ClientAliveCountMax.conf:ClientAliveCountMax 1

If "ClientAliveCountMax" do not exist, is not set to a value of "1" in "/etc/ssh/sshd_config" or a dropfile in "/etc/ssh/sshd_config.d" , or is commented out, this is a finding.)
  desc 'fix', 'Configure Amazon Linux 2023 SSHD to terminate a user session automatically after the SSH client has become unresponsive.

Note: This setting must be applied in conjunction with AZLX-23-000820 to function correctly.

Modify or append the following lines in the "/etc/ssh/sshd_config" file or a dropfile in "/etc/ssh/sshd_config.d":

ClientAliveCountMax 1

For the changes to take effect, the SSH daemon must be restarted.

$ sudo systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-78142r1120139_chk'
  tag severity: 'medium'
  tag gid: 'V-274051'
  tag rid: 'SV-274051r1120141_rule'
  tag stig_id: 'AZLX-23-001250'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-78047r1120140_fix'
  tag satisfies: ['SRG-OS-000163-GPOS-00072', 'SRG-OS-000279-GPOS-00109']
  tag 'documentable'
  tag cci: ['CCI-001133', 'CCI-002361']
  tag nist: ['SC-10', 'AC-12']
end
