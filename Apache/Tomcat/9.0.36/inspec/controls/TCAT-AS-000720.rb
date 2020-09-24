# encoding: UTF-8

control 'TCAT-AS-000720' do
    title 'Default password for keystore must be changed.'
    desc  'Tomcat currently operates only on JKS, PKCS11 or PKCS12 format
    keystores. The JKS format is Java\'s standard \'Java KeyStore\' format, and is
    the format created by the keytool command-line utility which is included in the
    JDK. The PKCS12 format is an internet standard, and is managed using OpenSSL or
    Microsoft\'s Key-Manager. When a new JKS keystore is created, if a password is
    not specified during creation, the default password used by Tomcat is
    \'changeit\' (all lowercase). If the default password is not changed, the
    keystore is at risk of compromise.'
    desc  'rationale', ''
    desc  'check', '
      From the Tomcat server console run the following command to check the
    keystore:
  
      sudo keytool -list -v
  
      When prompted for the keystore password, type \'changeit\'.
  
      If the contents of the keystore are displayed, this is a finding.
    '
    desc  'fix', '
      From the Tomcat server as a privileged user:
  
      sudo keytool -storepasswd
  
      When prompted for the keystore password, select a strong password, minimum
    10 characters, mixed case alpha-numeric.
  
      Document the password and store in a secured location that is only
    accessible to authorized personnel.
    '
    impact 0.7
    tag severity: 'high'
    tag gtitle: 'SRG-APP-000176-AS-000125'
    tag gid: 'TCAT-AS-000720'
    tag rid: 'TCAT-AS-000720_rule'
    tag stig_id: 'TCAT-AS-000720'
    tag fix_id: 'F-TCAT-AS-000720_fix'
    tag cci: ['CCI-000186']
    tag nist: ['IA-5 (2) (b)']
    
    keytool = command("keytool -list -v")
    
    describe keytool do
        its('exit_status') { should eq 0 }
    end

    if keytool.exist?
        describe command("keytool -list -v -storepass changeit") do
            its('exist_status') { should eq 0 }
        end
    end

end