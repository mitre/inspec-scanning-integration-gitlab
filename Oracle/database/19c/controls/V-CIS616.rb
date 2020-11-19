# encoding: UTF-8

control 'V-CIS616' do
  title 'The PUBLIC DATABASE LINK Audit Option Is Enabled'
  desc  "The PUBLIC DATABAS LINK object allows for the creation of a public link for an application-based user to access the database for connections/session creation.  Enabling the audit option causes all user activities involving the creation, alteration or dropping of public links to be audited."
  desc  'rationale', ''
  desc  'check', "
    From SQL*Plus:

   SELECT AUDIT_OPTION,SUCCESS,FAILURE FROM CDB_STMT_AUDIT_OPTS  WHERE USER_NAME IS NULL  AND PROXY_NAME IS NULL  AND SUCCESS = 'BY ACCESS'  AND FAILURE = 'BY ACCESS'  AND AUDIT_OPTION='PUBLIC DATABASE LINK';
  "
  desc  'fix', "
      From SQL*Plus:

	AUDIT PUBLIC DATABASE LINK;

    The above SQL*Plus command will set the parameter to take effect at next
system startup.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-DB-999900'
  tag gid: 'CIS616'
  tag rid: ''
  tag stig_id: 'N/A'
  tag fix_id: ''
  tag cci: ['']
  tag nist: ['CM-6 b']

sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

parameter = sql.query("SELECT AUDIT_OPTION,SUCCESS,FAILURE FROM CDB_STMT_AUDIT_OPTS WHERE USER_NAME IS NULL AND PROXY_NAME IS NULL AND SUCCESS = 'BY ACCESS' AND FAILURE = 'BY ACCESS' AND AUDIT_OPTION='PUBLIC DATABASE LINK';").column('audit_option')

describe 'PDL' do
subject { parameter }                          
it {should_not be_empty}
end
end
