# encoding: UTF-8

control 'V-CIS229' do
  title 'The SEC_CASE_SENSITIVE_LOGON parameter must be set to TRUE.'
  desc  "The SEC_CASE_SENSITIVE_LOGON information determines whether or not case-sensativity is required for passwords during login."
  desc  'rationale', ''
  desc  'check', "
    From SQL*Plus:

      select value from v$parameter where name = 'sec_case_sensitive_logon';

    If the returned value is not TRUE or not documented in the System Security
Plan as required, this is a finding.
  "
  desc  'fix', "
    Document Sec Case Sensitive Logon in the System Security Plan.

    From SQL*Plus:

      alter system set sec_case_sensitive_logon = TRUE scope = spfile;

    The above SQL*Plus command will set the parameter to take effect at next
system startup.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-DB-999900'
  tag gid: 'CIS229'
  tag rid: ''
  tag stig_id: 'N/A'
  tag fix_id: ''
  tag cci: ['']
  tag nist: ['CM-6 b']

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  parameter = sql.query("select value from v$parameter where name = 'sec_case_sensitive_logon';").column('value')
 
  describe 'LOGO' do         
	subject { parameter }               
        it {should cmp 'TRUE'}
        end
end

