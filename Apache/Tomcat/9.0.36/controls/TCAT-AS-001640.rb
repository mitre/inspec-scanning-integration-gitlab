# encoding: UTF-8

control 'TCAT-AS-001640' do
    title 'Application servers must use NIST-approved or NSA-approved key
    management technology and processes.'
    desc  'Class 3 PKI certificates are used for servers and software signing
    rather than for identifying individuals. Class 4 certificates are used for
    business-to-business transactions. Utilizing unapproved certificates not issued
    or approved by DoD or CNS creates an integrity risk. The application server
    must utilize approved DoD or CNS Class 3 or Class 4 certificates for software
    signing and business-to-business transactions.'
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
    PKI office web site at cyber.mil/pki-pke.
  
      Import the DoD CA certificates.
    '
    impact 0.3
    tag severity: 'low'
    tag gtitle: 'SRG-APP-000514-AS-000137'
    tag gid: 'TCAT-AS-001640'
    tag rid: 'TCAT-AS-001640_rule'
    tag stig_id: 'TCAT-AS-001640'
    tag fix_id: 'F-TCAT-AS-001640_fix'
    tag cci: ['CCI-002450']
    tag nist: ['SC-13']
    
    describe "This is a manual check" do 
        skip "Check the trustStore variable is set in the tomcat.service file. If it is not set run the 
        command: \"keytool -list -cacerts -v | grep -i issuer\" to set the Default Location. If the default is already set then run the 
        command: \"keytool -list -keystore <location of trust store file> -v |grep -i issuer\" to set the alternate location"
    end
  
end