# encoding: UTF-8

control 'TCAT-AS-001440' do
    title 'Secured connectors must use FIPS 140-2-validated cipher algorithms.'
    desc  '
      If approved cryptographic algorithms are not used, encryption strength
    cannot be assured.
  
      When configuring a connector for secured communications, the user must also
    select an approved encryption cipher.
  
      Examples include but are not limited to:
      Symmetric Key
      AES, Triple-DES, Escrowed Encryption Standard
      Asymmetric Key
      DSA, RSA, ECDSA
      Hash Standards
      *SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256
  
      *SHA1 may be used for legacy applications only.
    '
    desc  'rationale', ''
    desc  'check', '
      From the Tomcat server console, run the following command:
  
      sudo grep -i fipsmode $CATALINA_HOME/conf/server.xml.
  
      If there are no results displayed or if FIPSMode is not set to
    FIPSMode=\'on\', this is a finding.
    '
    desc  'fix', '
      From the Tomcat server as a privileged user:
  
      sudo nano $CATALINA_HOME/conf/server.xml.
  
      In the <Listener/> element, locate the AprLifecycleListener, either add or
    modify the FIPSMode setting and set it to FIPSMode=\'on\'
  
      EXAMPLE:
      <Listener
          className=\'org.apache.catalina.core.AprLifecycleListener\'
          SSLEngine=\'on\'
          FIPSMode=\'on\'
      />
  
      Restart the Tomcat server:
      sudo systemctl restart tomcat
      sudo systemctl daemon-reload
    '
    impact 0.7
    tag severity: 'high'
    tag gtitle: 'SRG-APP-000428-AS-000265'
    tag gid: 'TCAT-AS-001440'
    tag rid: 'TCAT-AS-001440_rule'
    tag stig_id: 'TCAT-AS-001440'
    tag fix_id: 'F-TCAT-AS-001440_fix'
    tag cci: ['CCI-002475']
    tag nist: ['SC-28 (1)']

    tomcat_server_file = xml("/usr/local/tomcat/conf/server.xml")
    listeners = tomcat_server_file["//Listener/@className"]
    
    listeners.each do |listener|
        if listener == "org.apache.catalina.core.AprLifecycleListener"
            describe tomcat_server_file['//Listener/@FIPSMode'][0] do 
                it { should cmp "on" }
            end 
        end 
    end

end