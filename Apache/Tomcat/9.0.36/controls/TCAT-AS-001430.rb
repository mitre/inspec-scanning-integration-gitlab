# encoding: UTF-8

control 'TCAT-AS-001430' do
    title 'Certificates in the trust store must be issued/signed by an approved
    CA.'
    desc  'Use of self-signed certificates creates a lack of integrity and
    invalidates the certificate based authentication trust model. Certificates used
    by production systems must be issued/signed by a trusted Root CA and cannot be
    self-signed. For systems that communicate with industry partners, the DoD ECA
    program supports the issuance of DoD-approved certificates to industry
    partners. For information on the DoD ECA program, refer to the DoD PKI office.
    Links to their site are available on https://public.cyber.mil.'
    desc  'rationale', ''
    desc  'check', '
      For the systemd Ubuntu OS, check the tomcat.service file to read the
    content of the JAVA_OPTS environment variable setting.
  
      sudo cat /etc/systemd/system/tomcat.service |grep -i truststore
  
      EXAMPLE output:
      set JAVA_OPTS=\'-Djavax.net.ssl.trustStore=/path/to/truststore\'
    \'-Djavax.net.ssl.trustStorePassword=************\'
  
      If the variable is not set, use the default location command below. If the
    variable is set, use the alternate location command below and include the path
    and truststore file.
  
      -Default location:
      keytool -list -cacerts -v | grep -i issuer
  
      -Alternate location:
      keytool -list -keystore <location of trust store file> -v |grep -i issuer
  
      If there are no CA certificates issued by a Certificate Authority (CA) that
    is part of the DoD PKI/PKE, this is a finding.
    '
    desc  'fix', '
      Obtain and install the DoD PKI CA certificate bundles by accessing the DoD
    PKI office web site at https://cyber.mil/pki-pke.
  
      Download the certificate bundles and then use certificate management
    utilities such as keytool or openssl to import the DoD CA certificates into the
    trust store.
    '
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000427-AS-000264'
    tag gid: 'TCAT-AS-001430'
    tag rid: 'TCAT-AS-001430_rule'
    tag stig_id: 'TCAT-AS-001430'
    tag fix_id: 'F-TCAT-AS-001430_fix'
    tag cci: ['CCI-002470']
    tag nist: ['SC-23 (5)']
    

    describe "This is a manual check" do 
        skip "Check the trustStore variable is set in the tomcat.service file. If it is not set run the 
        command: \"keytool -list -cacerts -v | grep -i issuer\" to set the Default Location. If the default is already set then run the 
        command: \"keytool -list -keystore <location of trust store file> -v |grep -i issuer\" to set the alternate location"
    end
    
end