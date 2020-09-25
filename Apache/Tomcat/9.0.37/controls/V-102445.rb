# encoding: UTF-8

control 'V-102445' do
  title 'Default password for keystore must be changed.'
  desc  "Tomcat currently operates only on JKS, PKCS11, or PKCS12 format
keystores. The JKS format is Java's standard \"Java KeyStore\" format, and is
the format created by the keytool command-line utility which is included in the
JDK. The PKCS12 format is an internet standard, and is managed using OpenSSL or
Microsoft's Key-Manager. This requirement only applies to JKS keystores. When a
new JKS keystore is created, if a password is not specified during creation the
default password used by Tomcat is \"changeit\" (all lower case). If the
default password is not changed, the keystore is at risk of compromise.


  "
  desc  'rationale', ''
  desc  'check', "
    From the Tomcat server console, run the following command to check the
keystore:

    sudo keytool -list -v

    When prompted for the keystore password type \"changeit\" sans quotes.

    If the contents of the keystore are displayed, this is a finding.
  "
  desc  'fix', "
    From the Tomcat server as a privileged user, run the following command:

    sudo keytool -storepasswd

    When prompted for the keystore password, select a strong password, minimum
10 characters, mixed case alpha-numeric.

    Document the password and store in a secured location that is only
accessible to authorized personnel.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000033-AS-000024'
  tag satisfies: ['SRG-APP-000033-AS-000023', 'SRG-APP-000176-AS-000125']
  tag gid: 'V-102445'
  tag rid: 'SV-111393r1_rule'
  tag stig_id: 'TCAT-AS-000060'
  tag fix_id: 'F-107985r1_fix'
  tag cci: ['CCI-000186', 'CCI-000213']
  tag nist: ['IA-5 (2) (b)', 'AC-3']

  keystore_file = input("keystore_file", value: "/root/.keystore")

  only_if("A keystore file does not exist. Skipping this check") do 
    command("keytool -list -v -keystore #{keystore_file}").exist?
  end

  describe 'The default password for keystore is "changeit" sans quotes. If the following command: "keytool -list -v -keystore <keystore location>" grants access. This check has failed.' do
    subject { command("keytool -list -v -keystore #{keystore_file}").exit_status }
    it { should_not eq 0 }
  end

end

