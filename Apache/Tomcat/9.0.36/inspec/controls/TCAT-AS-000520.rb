# encoding: UTF-8

control 'TCAT-AS-000520' do
    title 'DefaultServlet directory listings parameter must be disabled.'
    desc  'The DefaultServlet serves static resources as well as directory
    listings. It is declared globally in $CATALINA_BASE/conf/web.xml and by default
    is configured with the directory \'listings\' parameter set to disabled. If no
    welcome file is present and the \'listings\' setting is enabled, a directory
    listing is shown. Directory listings must be disabled.'
    desc  'rationale', ''
    desc  'check', '
      From the Tomcat server run the following OS command:
  
      sudo cat $CATALINA_HOME/conf/web.xml |grep -i -A10 -B2 defaultservlet
  
      The above command will include ten lines after and two lines before the
    occurrence of \'defaultservlet\'. Some systems may require that the user
    increase the after number (A10) in order to determine the \'listings\'
    param-value.
  
      If the \'listings\' param-value for the \'DefaultServlet\' servlet class
    does not = \'false\', this is a finding.
    '
    desc  'fix', '
      From the Tomcat server as a privileged user:
  
      Edit the $CATALINA_HOME/conf/web.xml file.
  
      Examine the <init-param> elements within the <Servletclass> element, if the
    \'listings\' <param-value>element is \'true\' change the \'listings\'
    <param-value> to read \'false\'.
  
      sudo systemctl restart tomcat
      sudo systemctl daemon-reload
    '
    impact 0.3
    tag severity: 'low'
    tag gtitle: 'SRG-APP-000141-AS-000095'
    tag gid: 'TCAT-AS-000520'
    tag rid: 'TCAT-AS-000520_rule'
    tag stig_id: 'TCAT-AS-000520'
    tag fix_id: 'F-TCAT-AS-000520_fix'
    tag cci: ['CCI-000381']
    tag nist: ['CM-7 a']
    
    tomcat_web_file = xml("/usr/local/tomcat/conf/web.xml") 
    servlets = tomcat_web_file["//servlet/servlet-name"]
    check_params = tomcat_web_file["//servlet/init-param/param-name"]
    index = 0
    param_index = 0

    only_if("Run only if DefaultServlet has listings enabled") do
        check_params.include?("listings")
    end 

    if !servlets.empty?
        servlets.each do |servlet|
            for i in 1..servlets.count
                if servlet == "default"
                    index+=1
                    break
                end
            end
        end
        params = tomcat_web_file["//servlet[#{index}]/init-param/param-name"]

        params.each do |param|
            for i in 1..params.count
                if param == "listings"
                    index+=1
                    break
                end
            end
        end

        readonly = tomcat_web_file["//servlet[1]/init-param[#{param_index}]/param-value"]
        describe readonly do 
            it { should cmp "false" }
        end
    end 
end