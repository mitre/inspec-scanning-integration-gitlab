# encoding: UTF-8

control 'V-CIS6226' do
    title 'The LOGON AND LOGOFF Actions Audit Is Enabled'
    desc  "Oracle database users log on to the database to perform their work. Enabling this unified
    audit causes logging of all LOGON actions, whether successful or unsuccessful, issued by the
    users regardless of the privileges held by the users to log into the database. In addition,
    LOGOFF action audit captures logoff activities. This audit action also captures logon/logoff to
    the open database by SYSDBA and SYSOPER."
    desc  'rationale', ''
    desc  'check', "
  
        From SQL*Plus:

        WITH
        CIS_AUDIT(AUDIT_OPTION) AS
        (
        SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY( 'LOGON','LOGOFF' ) )
        ),
        AUDIT_ENABLED AS
        ( SELECT DISTINCT AUDIT_OPTION
        FROM AUDIT_UNIFIED_POLICIES AUD
        WHERE AUD.AUDIT_OPTION IN ('LOGON','LOGOFF' )
        AND AUD.AUDIT_OPTION_TYPE = 'STANDARD ACTION'
        AND EXISTS (SELECT *
        FROM AUDIT_UNIFIED_ENABLED_POLICIES ENABLED
        WHERE ENABLED.SUCCESS = 'YES'
        AND ENABLED.FAILURE = 'YES'
        AND ENABLED.ENABLED_OPTION = 'BY USER'
        AND ENABLED.ENTITY_NAME = 'ALL USERS'
        AND ENABLED.POLICY_NAME = AUD.POLICY_NAME)
        )
        SELECT C.AUDIT_OPTION
        FROM CIS_AUDIT C
        LEFT JOIN AUDIT_ENABLED E
        ON C.AUDIT_OPTION = E.AUDIT_OPTION
        WHERE E.AUDIT_OPTION IS NULL;
  
      "
    desc  'fix', "
        From SQL*Plus:
  
        ALTER AUDIT POLICY CIS_UNIFIED_AUDIT_POLICY
        ADD
        ACTIONS
        LOGON,
        LOGOFF;

      The above SQL*Plus command will set the parameter to take effect at next
  system startup.
    "
    impact 0.7
    tag severity: 'high'
    tag gtitle: 'SRG-APP-000516-DB-999900'
    tag gid: 'CIS6227'
    tag rid: ''
    tag stig_id: 'N/A'
    tag fix_id: ''
    tag cci: ['']
    tag nist: ['CM-6 b']                                                                                                                                                                                                          
  
    sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))
  
    parameter = sql.query("WITH
    CIS_AUDIT(AUDIT_OPTION) AS
    (
    SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY( 'LOGON','LOGOFF' ) )
    ),
    AUDIT_ENABLED AS
    ( SELECT DISTINCT AUDIT_OPTION
    FROM AUDIT_UNIFIED_POLICIES AUD
    WHERE AUD.AUDIT_OPTION IN ('LOGON','LOGOFF' )
    AND AUD.AUDIT_OPTION_TYPE = 'STANDARD ACTION'
    AND EXISTS (SELECT *
    FROM AUDIT_UNIFIED_ENABLED_POLICIES ENABLED
    WHERE ENABLED.SUCCESS = 'YES'
    AND ENABLED.FAILURE = 'YES'
    AND ENABLED.ENABLED_OPTION = 'BY USER'
    AND ENABLED.ENTITY_NAME = 'ALL USERS'
    AND ENABLED.POLICY_NAME = AUD.POLICY_NAME)
    )
    SELECT C.AUDIT_OPTION
    FROM CIS_AUDIT C
    LEFT JOIN AUDIT_ENABLED E
    ON C.AUDIT_OPTION = E.AUDIT_OPTION
    WHERE E.AUDIT_OPTION IS NULL;").column('audit_option')

    describe 'LOGON AND LOGOFF Actions are Audited' do
        subject { parameter }
        it { should be_empty }
    end
  end 
  
  
