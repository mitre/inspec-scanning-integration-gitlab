# encoding: UTF-8

control 'V-CIS5132' do
  title 'ALL Is Revoked from Unauthorized GRANTEE on DBA_%'
  desc  "The table sys.user$mig is created during migration and contains the Oracle
	password hashes before the migration starts.  This table should be dropped."
  desc  'rationale', ''
  desc  'check', "
    From SQL*Plus:

    SELECT GRANTEE,TABLE_NAME FROM DBA_TAB_PRIVS WHERE TABLE_NAME LIKE 'DBA_%'  AND OWNER = 'SYS' AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='Y') AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y');

    If the returned value is FALSE or not documented in the System Security
Plan as required, this is a finding.
  "
  desc  'fix', "
      From SQL*Plus:

     REVOKE ALL ON <DBA_%> FROM <Non-DBA/SYS grantee>;

    The above SQL*Plus command will set the parameter to take effect at next
system startup.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-DB-999900'
  tag gid: 'CIS5132'
  tag rid: ''
  tag stig_id: 'N/A'
  tag fix_id: ''
  tag cci: ['']
  tag nist: ['CM-6 b']

 ORACLE_OPS  = command("source /home/oracle/.bashrc && echo -e \"SET PAGESIZE 0\n SET FEEDBACK OFF\n SELECT GRANTEE,TABLE_NAME FROM CDB_TAB_PRIVS WHERE TABLE_NAME LIKE \'DBA_%\' and owner= \'SYS\'
		        AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED=\'Y\') 
			AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED=\'Y\');\" | sqlplus -S -L / as sysdba").stdout

describe 'ORACLE_OPS' do
subject { ORACLE_OPS }
it {should be_empty}
end
end

