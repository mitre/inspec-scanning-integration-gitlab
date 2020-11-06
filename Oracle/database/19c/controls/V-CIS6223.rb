# encoding: UTF-8

control 'V-CIS6223' do
    title 'The ALTER SYSTEM Actions Audit Is Enabled'
    desc  "The ALTER SYSTEM privilege allows the user to change instance settings which could impact
    security posture, performance or normal operation of the database. Additionally, the ALTER
    SYSTEM privilege may be used to run operating system commands using undocumented
    Oracle functionality. Enabling this unified audit causes logging of activities that involve
    exercise of this privilege, whether successful or unsuccessful, issued by the users
    regardless of the privileges held by the users to issue such statements."
    desc  'rationale', ''
    desc  'check', "
  
        From SQL*Plus:

        WITH
        CIS_AUDIT(AUDIT_OPTION) AS
        (
        SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY( 'ALTER SYSTEM' ) )
        ),
        AUDIT_ENABLED AS
        ( SELECT DISTINCT AUDIT_OPTION
        FROM AUDIT_UNIFIED_POLICIES AUD
        WHERE AUD.AUDIT_OPTION IN ('ALTER SYSTEM' )
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
        ALTER SYSTEM;

      The above SQL*Plus command will set the parameter to take effect at next
  system startup.
    "
    impact 0.7
    tag severity: 'high'
    tag gtitle: 'SRG-APP-000516-DB-999900'
    tag gid: 'CIS6223'
    tag rid: ''
    tag stig_id: 'N/A'
    tag fix_id: ''
    tag cci: ['']
    tag nist: ['CM-6 b']                                                                                                                                                                                                          
  
    sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))
  
    parameter = sql.query("WITH
    CIS_AUDIT(AUDIT_OPTION) AS
    (
    SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY( 'ALTER SYSTEM' ) )
    ),
    AUDIT_ENABLED AS
    ( SELECT DISTINCT AUDIT_OPTION
    FROM AUDIT_UNIFIED_POLICIES AUD
    WHERE AUD.AUDIT_OPTION IN ('ALTER SYSTEM' )
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
    WHERE E.AUDIT_OPTION IS NULL;").rows()

    describe 'ALTER SYSTEM Actions are Audited' do
        subject { parameter }
        it { should be_empty }
    end
  end 
  
  