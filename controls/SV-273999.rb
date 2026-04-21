control 'SV-273999' do
  title 'Amazon Linux 2023 must be a vendor-supported release.'
  desc '<packagename> To get information on all currently installed packages, use:
$ sudo dnf supportinfo --show installed<#text> An operating system release is considered "supported" if the vendor continues to provide security patches for the product. With an unsupported release, it will not be possible to resolve security issues discovered in the system software. Amazon Linux 2023 (AL2023) was released in March 2023 and will be supported until June 30, 2029. 

Standard support ends June 30, 2027.
Maintenance (security and critical fixes only) ends June 30, 2029.

To check the support status and dates of individual packages, use the following command:
$ sudo dnf supportinfo --pkg'
  desc 'check', 'Verify Amazon Linux 2023 is a vendor-supported version with the following command:

$ cat /etc/amazon-linux-release 
Amazon Linux release 2023.6.20250203 (Amazon Linux)

If the installed version of Amazon Linux 2023 is not supported, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to be a vendor supported release.

Upgrade to a supported version of Amazon Linux 2023.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000439-GPOS-00195'
  tag gid: 'V-273999'
  tag rid: 'SV-273999r1155171_rule'
  tag stig_id: 'AZLX-23-000130'
  tag fix_id: 'F-77995r1119984_fix'
  tag cci: ['CCI-000366', 'CCI-002605']
  tag nist: ['CM-6 b', 'SI-2 c']
  tag 'host'
  tag 'container'

  release = os.release

  # Note that versions 9.0 and 9.2 of RHEL9 are within the EUS window at
  # time of writing.

  # 9.1 is not a EUS-supported release and is no longer officially supported
  # by Red Hat. The date given for the expiration for 9.1 is based on the
  # RHEL9 Planning Guide diagram found on Red Hat's Life Cycle page:
  # https://access.redhat.com/support/policy/updates/errata/#Life_Cycle_Dates

  EOMS_DATE = {
    /^9\.0/ => 'May 31, 2024',
    /^9\.1/ => 'April 1, 2023',
    /^9\.2/ => 'May 31, 2025',
    /^9\.3/ => 'April 30, 2024',
    /^9\.4/ => 'May 31, 2026',
    /^9\.5/ => 'April 30, 2025',
    /^9\.6/ => 'May 31, 2027',
    /^9\.7/ => 'April 30, 2026',
    /^9\.8/ => 'May 31, 2028',
    /^9\.9/ => 'April 30, 2027',
    /^9\.10/ => 'May 31, 2032'
  }.find { |k, _v| k.match(release) }&.last

  describe "The release \"#{release}\"" do
    if EOMS_DATE.nil?
      it 'is a supported release' do
        expect(EOMS_DATE).not_to be_nil, "Release '#{release}' has no specified support window"
      end
    else
      it 'is still within the support window' do
        expect(Date.today).to be <= Date.parse(EOMS_DATE)
      end
    end
  end
end
