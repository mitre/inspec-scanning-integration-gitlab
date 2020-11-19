# encoding: UTF-8

control 'V-CIS6216' do
  title 'The ALTER SYNONYM Audit Option Is Enabled'
  desc  "Oracle database synonym is used to create an alternative name for a database object such as table, view procedure java object or even another synonym. Enable the audit creas logs of all ALTER SYNONYM AND ALTER Public SYNONYM statements."
  desc  'rationale', ''
  desc  'check', "
    From SQL*Plus:

WITH  CIS_AUDIT(AUDIT_OPTION) AS ( SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY('ALTER SYNONYM' ) )  ), AUDIT_ENABLED AS  ( SELECT DISTINCT AUDIT_OPTION   FROM AUDIT_UNIFIED_POLICIES AUD   WHERE AUD.AUDIT_OPTION IN ('ALTER SYNONYM' )        AND AUD.AUDIT_OPTION_TYPE = 'STANDARD ACTION'        AND EXISTS (SELECT *                    FROM AUDIT_UNIFIED_ENABLED_POLICIES ENABLED                    WHERE ENABLED.SUCCESS = 'YES'                        AND ENABLED.FAILURE = 'YES'                        AND ENABLED.ENABLED_OPTION = 'BY USER'                        AND ENABLED.ENTITY_NAME = 'ALL USERS'                        AND  ENABLED.POLICY_NAME = AUD.POLICY_NAME) ) SELECT C.AUDIT_OPTION  FROM CIS_AUDIT C  LEFT JOIN AUDIT_ENABLED E ON C.AUDIT_OPTION = E.AUDIT_OPTION  WHERE E.AUDIT_OPTION IS NULL; 

    "
  desc  'fix', "
      From SQL*Plus:

	ALTER AUDIT POLICY CIS_UNIFIED_AUDIT_POLICY ADD ACTIONS ALTER SYNONYM LINK; 

    The above SQL*Plus command will set the parameter to take effect at next
system startup.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-DB-999900'
  tag gid: 'CIS6216'
  tag rid: ''
  tag stig_id: 'N/A'
  tag fix_id: ''
  tag cci: ['']
  tag nist: ['CM-6 b']                                                                                                                                                                                                          
sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

parameter = sql.query("WITH CIS_AUDIT(AUDIT_OPTION) AS (SELECT * FROM TABLE(DBMSOUTPUT_LINESARRAY('ALTER SYNONYM') ) ), AUDIT_ENABLED AS (SELECT DISTINCT AUDIT_OPTION FROM AUDIT_UNIFIED_POLICIES AUD WHERE AUD.AUDIT_OPTION IN ('ALTER SYNONYM') AND AUD.AUDIT_OPTION_TYPE = 'STANDARD ACTION' AND EXISTS (SELECT *  FROM AUDIT_UNIFIED_ENABLED_POLICIES ENABLED WHERE ENABLED.SUCCESS = 'YES' AND ENABLED.FAILURE = 'YES' AND ENABLED.ENABLED_OPTION = 'BY USER' AND ENABLED.ENTITY_NAME = 'ALL USERS' AND ENABLED.POLICY_NAME = AUD.POLICY_NAME) ) SELECT C.AUDIT_OPTION FROM CIS_AUDIT C LEFT JOIN AUDIT_ENABLED E ON C.AUDIT_OPTION = E.AUDIT_OPTION WHERE E.AUDIT_OPTION IS NULL;").column('audit_option')
                      
describe 'ASL' do
subject { parameter }
it {should be_empty }
end
end

