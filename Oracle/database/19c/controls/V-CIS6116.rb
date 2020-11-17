# encoding: UTF-8

control 'V-CIS6116' do
  title 'The ALTER SYSTEM Audit Option Is Enabled'
  desc  "ALTER SYSTEM allows one to change instance settings, including security settings and auding options. Additional, ALTER SYSTEM can be used to run operating system commands using undocumented Oracle functionality.  Enabling the audit option will audit all attempts to perform ALTER SYSTEM, whether successful or not and regardless of whether or not the ALTER SYSTEM privilege is held by the user attempting the action."
  desc  'rationale', ''
  desc  'check', "
    From SQL*Plus:

	SELECT AUDIT_OPTION,SUCCESS,FAILURE FROM DBA_STMT_AUDIT_OPTS  WHERE USER_NAME IS NULL  AND PROXY_NAME IS NULL  AND SUCCESS = 'BY ACCESS'  AND FAILURE = 'BY ACCESS'  AND AUDIT_OPTION='ALTER SYSTEM';

    "
  desc  'fix', "
      From SQL*Plus:

	AUDIT ALTER SYSTEM;

    The above SQL*Plus command will set the parameter to take effect at next
system startup.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-DB-999900'
  tag gid: 'CIS6116'
  tag rid: ''
  tag stig_id: 'N/A'
  tag fix_id: ''
  tag cci: ['']
  tag nist: ['CM-6 b']

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  parameter = sql.query("SELECT AUDIT_OPTION,SUCCESS,FAILURE FROM CDB_STMT_AUDIT_OPTS WHERE USER_NAME IS NULL
			AND PROXY_NAME IS NULL
			AND SUCCESS = 'BY ACCESS'
			AND FAILURE = 'BY ACCESS'
                        AND AUDIT_OPTION='ALTER SYSTEM';").column('audit_option')
                          
describe 'SAO' do
subject { parameter }
it {should_not be_empty}
end
end
