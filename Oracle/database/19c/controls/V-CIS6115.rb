# encoding: UTF-8

control 'V-CIS6115' do
  title 'The PROCEDURE Audit Option Is Enabled'
  desc  "Any unauthorized attempts to create or drop a prcedure in another schema should cause concern, whether successful or not.  Changes to critical stored code can dramatically change the behavior of the application and produce serious security consequences, including enabling privilege escalation and introducing SQL injection vulnerabilities.  Audit records of such changes can be helpful in forensics."
  desc  'rationale', ''
  desc  'check', "
    From SQL*Plus:

SELECT AUDIT_OPTION,SUCCESS,FAILURE FROM DBA_STMT_AUDIT_OPTS  WHERE USER_NAME IS NULL  AND PROXY_NAME IS NULL  AND SUCCESS = 'BY ACCESS'  AND FAILURE = 'BY ACCESS'  AND AUDIT_OPTION='PROCEDURE'; 

    "
  desc  'fix', "
      From SQL*Plus:

	AUDIT PROCEDURE;

    The above SQL*Plus command will set the parameter to take effect at next
system startup.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-DB-999900'
  tag gid: 'CIS6115'
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
                        AND AUDIT_OPTION='PROCEDURE';").column('audit_option')
                          

describe 'PA' do
subject { parameter }
it {should_not be_empty}
                        end
end
