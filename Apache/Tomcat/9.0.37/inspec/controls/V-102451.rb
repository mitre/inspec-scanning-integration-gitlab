# encoding: UTF-8

control 'V-102451' do
  title 'DefaultServlet must be set to readonly for PUT and DELETE.'
  desc  "The Default servlet (or DefaultServlet) is a special servlet provided
with Tomcat, which is called when no other suitable page is found in a
particular folder. The DefaultServlet serves static resources as well as
directory listings. The DefaultServlet is declared globally in
$CATALINA_BASE/conf/web.xml and by default is configured with the \"readonly\"
parameter set to true where HTTP commands like PUT and DELETE are rejected.
Changing this to false allows clients to delete or modify static resources on
the server and to upload new resources. DefaultServlet readonly must be set to
true."
  desc  'rationale', ''
  desc  'check', "
    From the Tomcat server run the following command:

    sudo cat $CATALINA_BASE/conf/web.xml |grep -i -A5 -B2 defaultservlet

    If the \"readonly\" param-value does not exist, this is not a finding.

    If the \"readonly\" param-value for the \"DefaultServlet\" servlet class =
\"false\", this is a finding.
  "
  desc  'fix', "
    From the Tomcat server console as a privileged user:

    Edit the $CATALINA_BASE/conf/web.xml file.

    If the \"readonly\" param-value does not exist, it must be created.

    Change the \"readonly\" param-value for the \"DefaultServlet\" servlet
class = \"true\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000033-AS-000024'
  tag gid: 'V-102451'
  tag rid: 'SV-111399r1_rule'
  tag stig_id: 'TCAT-AS-000090'
  tag fix_id: 'F-107991r1_fix'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  catalina_base = input('catalina_base', value: '/usr/local/tomcat')
  tomcat_web_file = xml("#{catalina_base}/conf/web.xml") 
  servlets = tomcat_web_file["//servlet/servlet-name"]
  check_params = tomcat_web_file["//servlet/init-param/param-name"]
  index = 0
  param_index = 0

  only_if("Run only if DefaultServlet has readonly enabled") do
      check_params.include?("readonly")
  end 

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
          if param == "readonly"
              index+=1
              break
          end
      end
  end

  readonly = tomcat_web_file["//servlet[#{index}]/init-param[#{param_index}]/param-value"]
  describe "The readonly param for the DefaultServlet element must be set to true" do 
    subject { readonly } 
    it { should cmp "true" }
  end
 
end