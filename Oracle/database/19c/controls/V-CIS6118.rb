# encoding: UTF-8

control 'V-CIS6118' do
  title 'The CREATE SESSION Audit Option Is Enabled'
  desc  "Enabling this audit option will cause auditing of all attempts to connect to the database, whether successful or not, as well as audit session disconnects/logoffs.  The commands to audit SESSION, CONNECT or CREATE SESSION all accomplish the same thing - they initiate statement auditing of the connect statement used to create a database session."
  desc  'rationale', ''
  desc  'check', "
    From SQL*Plus:

	SELECT AUDIT_OPTION,SUCCESS,FAILURE FROM DBA_STMT_AUDIT_OPTS  WHERE USER_NAME IS NULL  AND PROXY_NAME IS NULL  AND SUCCESS = 'BY ACCESS'  AND FAILURE = 'BY ACCESS'  AND AUDIT_OPTION='CREATE SESSION';

    "
  desc  'fix', "
      From SQL*Plus:

	AUDIT SESSION;

    The above SQL*Plus command will set the parameter to take effect at next
system startup.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-DB-999900'
  tag gid: 'CIS6118'
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
                        AND AUDIT_OPTION='CREATE SESSION';").column('audit_option')

describe 'CSAOS' do
subject { parameter }
it {should_not be_empty}
end
end
