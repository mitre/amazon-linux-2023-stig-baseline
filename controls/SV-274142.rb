control 'SV-274142' do
  title 'Amazon Linux 2023 must automatically exit interactive command shell user sessions after 15 minutes of inactivity.'
  desc 'Terminating an idle interactive command shell user session within a short time period reduces the window of opportunity for unauthorized personnel to take control of it when left unattended in a virtual terminal or physical console.'
  desc 'check', %q(Verify Amazon Linux 2023 is configured to exit interactive command shell user sessions after 10 minutes of inactivity or less with the following command:

$ sudo grep -i tmout /etc/profile /etc/profile.d/*.sh
/etc/profile.d/tmout.sh:declare -xr TMOUT=600

If "TMOUT" is not set to "600" or less in a script located in the "/etc/'profile.d/ directory, is missing or is commented out, this is a finding.)
  desc 'fix', 'Configure Amazon Linux 2023 to exit interactive command shell user sessions after 10 minutes of inactivity.

Add or edit the following line in "/etc/profile.d/tmout.sh":

#!/bin/bash

declare -xr TMOUT=600'
  impact 0.5
  tag check_id: 'C-78233r1120412_chk'
  tag severity: 'medium'
  tag gid: 'V-274142'
  tag rid: 'SV-274142r1120414_rule'
  tag stig_id: 'AZLX-23-002396'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-78138r1120413_fix'
  tag satisfies: ['SRG-OS-000163-GPOS-00072', 'SRG-OS-000029-GPOS-00010']
  tag 'documentable'
  tag cci: ['CCI-000057', 'CCI-001133']
  tag nist: ['AC-11 a', 'SC-10']
  tag 'host'
  tag 'container'

  # STIG check text greps both /etc/profile and /etc/profile.d/*.sh.
  # Iterate both — a TMOUT setting in any uncommented line counts.
  profile_files = ['/etc/profile'] + Dir.glob('/etc/profile.d/*.sh')
  max_timeout = input('shell_session_timeout')

  tmout_values = profile_files.flat_map do |path|
    next [] unless file(path).exist?
    file(path).content.lines
      .map(&:strip)
      .reject { |l| l.empty? || l.start_with?('#') }
      .flat_map { |l| l.scan(/TMOUT\s*=\s*(\d+)/i) }
      .flatten
      .map { |v| [path, v.to_i] }
  end

  too_high = tmout_values.select { |_path, v| v > max_timeout }

  describe "Shell timeout (TMOUT) across /etc/profile and /etc/profile.d/*.sh (max allowed: #{max_timeout})" do
    it 'should be set in at least one profile file' do
      expect(tmout_values).not_to be_empty,
        "No uncommented TMOUT setting found. Searched:\n\t- #{profile_files.join("\n\t- ")}"
    end
    it "should be <= #{max_timeout} wherever it is set" do
      expect(too_high).to be_empty,
        "Files with TMOUT > #{max_timeout}:\n\t- #{too_high.map { |p, v| "#{p} (TMOUT=#{v})" }.join("\n\t- ")}"
    end
  end
end
