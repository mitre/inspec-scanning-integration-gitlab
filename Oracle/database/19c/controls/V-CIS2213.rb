# encoding: UTF-8

control 'V-CIS2213' do
  title 'Ensure SEC_RETURN_SERVER_RELEASE_BANNER Is Set To False'
  desc  'blank', '' 
  desc  'rationale', ''
  desc  'check', "
    From SQL*Plus:

      select value from v$parameter where name = 'sec_return_server_release_banner';
  "
  desc  'fix', "
    Document Sec Return Server Release Banner in the System Security Plan.

    From SQL*Plus:

      ALTER SYSTEM SET SEC_RETURN_SERVER_RELEASE_BANNER = FALSE SCOPE = SPFILE;

    The above SQL*Plus command will set the parameter to take effect at next
system startup.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-DB-999900'
  tag gid: 'CIS2213'
  tag rid: ''
  tag stig_id: 'N/A'
  tag fix_id: ''
  tag cci: ['']
  tag nist: ['CM-6 b']
  
  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  parameter = sql.query("select value from v$parameter where name = 'sec_return_server_release_banner';").column('value')
 
  describe 'BANNER' do
    subject { parameter }
    it { should cmp 'FALSE' }
  end

end

