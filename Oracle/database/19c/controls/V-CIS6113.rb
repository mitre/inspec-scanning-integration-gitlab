# encoding: UTF-8

control 'V-CIS6113' do
  title 'The DROP ANY PROCEDURE Audit Option Is Enabled'
  desc  "The DROP ANY PROCEDURE command is auditing the dropping of procedures.  Enabling the option causes auditing of all such activities."
  desc  'rationale', ''
  desc  'check', "
    From SQL*Plus:

    SELECT AUDIT_OPTION,SUCCESS,FAILURE FROM CDB_STMT_AUDIT_OPTS  WHERE USER_NAME IS NULL  AND PROXY_NAME IS NULL  AND SUCCESS = 'BY ACCESS'  AND FAILURE = 'BY ACCESS'  AND AUDIT_OPTION='DROP ANY PROCEDURE'; 
  "
  desc  'fix', "
      From SQL*Plus:

	AUDIT DROP ANY PROCEDURE;

    The above SQL*Plus command will set the parameter to take effect at next
system startup.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-DB-999900'
  tag gid: 'CIS6113'
  tag rid: ''
  tag stig_id: 'N/A'
  tag fix_id: ''
  tag cci: ['']
  tag nist: ['CM-6 b']

sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

parameter = sql.query("SELECT AUDIT_OPTION,SUCCESS,FAILURE FROM CDB_STMT_AUDIT_OPTS WHERE USER_NAME IS NULL AND PROXY_NAME IS NULL AND SUCCESS = 'BY ACCESS' AND FAILURE = 'BY ACCESS' AND AUDIT_OPTION='DROP ANY PROCEDURE';")
                          
describe 'DAP' do
subject { parameter }
it {should_not be_empty}
end
end
