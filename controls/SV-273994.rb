control 'SV-273994' do
  title 'Amazon Linux 2023 local disk partitions must implement cryptographic mechanisms to prevent unauthorized disclosure or modification of all information that requires at rest protection.'
  desc 'Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive and tape drive, when used for backups) within an operating system.

This requirement addresses protection of user-generated data, as well as operating system-specific configuration data. Organizations may choose to employ different mechanisms to achieve confidentiality and integrity protections, as appropriate, in accordance with the security category and/or classification of the information.'
  desc 'check', 'Verify Amazon Linux 2023 is configured so that all partitions are encrypted with the following command:

$ sudo blkid
/dev/xvda1: UUID="ed0acbe9-bd05-495e-a9ac-cb615b29327d" TYPE="crypto_LUKS"

Every persistent disk partition present must be of "Type" "crypto_LUKS". 

If any partitions other than the boot partition, bios partition or pseudo file systems (such as /proc or /sys) are not type "crypto_LUKS", this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to protect the confidentiality and integrity of all information at rest.

Encrypting a partition in an already installed system is more difficult, because existing partitions will need to be resized and changed.

To encrypt an entire partition, dedicate a partition for encryption in the partition layout.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000185-GPOS-00079'
  tag satisfies: ['SRG-OS-000185-GPOS-00079', 'SRG-OS-000404-GPOS-00183', 'SRG-OS-000405-GPOS-00184']
  tag gid: 'V-273994'
  tag rid: 'SV-273994r1119970_rule'
  tag stig_id: 'AZLX-23-000100'
  tag fix_id: 'F-77990r1119969_fix'
  tag cci: ['CCI-001199', 'CCI-002475', 'CCI-002476']
  tag nist: ['SC-28', 'SC-28 (1)']
  tag 'host'

  all_args = command('blkid').stdout.strip.split("\n").map { |s| s.sub(/^"(.*)"$/, '\1') }

  def describe_and_skip(message)
    describe message do
      skip message
    end
  end

  # TODO: This should really have a resource

  if virtualization.system.eql?('docker')
    impact 0.0
    describe_and_skip('Disk Encryption and Data At Rest Implementation is handled on the Container Host')
  elsif input('data_at_rest_exempt')
    impact 0.0
    describe_and_skip('Data At Rest Requirements have been set to Not Applicable by the `data_at_rest_exempt` input.')
  elsif all_args.empty?
    # TODO: Determine if this is an NA vs and NR or even a pass
    describe_and_skip('Command blkid did not return and non-psuedo block devices.')
  else
    unencrypted_drives = all_args.reject { |a|
      a.match(/\bcrypto_LUKS\b/) ||
        input('luks_exceptions').include?(a.split(':').first) ||
        a.split(':').first.match(%r{^/dev/mapper/})
    }
    describe 'All local disk partitions' do
      it 'should be encrypted with crypto_LUKS' do
        expect(unencrypted_drives).to be_empty, "The following partitions are not encrypted with crypto_LUKS:\t\n- #{unencrypted_drives.join("\t\n- ")}"
      end
    end
  end
end
