# encoding: UTF-8

control 'TCAT-AS-001690' do
    title 'ENFORCE_ENCODING_IN_GET_WRITER must be set to true.'
    desc  'Some clients try to guess the character encoding of text media when
    the mandated default of ISO-8859-1 should be used. Some browsers will interpret
    as UTF-7 when the characters are safe for ISO-8859-1. This can create the
    potential for a XSS attack. To defend against this,
    enforce_encoding_in_get_writer must be set to true.'
    desc  'rationale', ''
    desc  'check', '
      From the Tomcat server as a privileged user, run the following command:
  
      sudo grep -i  enforce_encoding /etc/systemd/system/tomcat.service
  
      If there are no results, or if the
    org.apache.catalina.connector.response.ENFORCE_ENCODING_IN_GET_WRITER is not
    enabled, this is a finding.
    '
    desc  'fix', '
      From the Tomcat server as a privileged user:
  
      Edit the /etc/systemd/system/tomcat.service file, and either add or edit
    the org.apache.catalina.connector.response.ENFORCE_ENCODING_IN_GET_WRITER
    setting.
  
      Set the
    org.apache.catalina.connector.response.ENFORCE_ENCODING_IN_GET_WRITER=true
  
      EXAMPLE:
      Environment=\'CATALINA_OPTS
    -Dorg.apache.catalina.connector.response.ENFORCE_ENCODING_IN_GET_WRITER=true\'
  
      Restart the Tomcat server.
      sudo systemctl restart tomcat
      sudo systemctl daemon-reload
    '
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000516-AS-000237'
    tag gid: 'TCAT-AS-001690'
    tag rid: 'TCAT-AS-001690_rule'
    tag stig_id: 'TCAT-AS-001690'
    tag fix_id: 'F-TCAT-AS-001690_fix'
    tag cci: ['CCI-000366']
    tag nist: ['CM-6 b']

    tomcat_service_file = "/etc/systemd/system/tomcat.service"
    environment = command("grep ENFORCE_ENCODING_IN_GET_WRITER #{tomcat_service_file}")
    catalina_options = environment.stdout.split(" ")
    if !catalina_options.empty?
        catalina_options.each do |option|
            if option.include? "ENFORCE_ENCODING_IN_GET_WRITER"
                describe option.split("=")[1] do 
                    it { should include "true" }
                end
            end
        end
    else 
        describe catalina_options.empty? do 
            it { should be false }
        end
    end
end