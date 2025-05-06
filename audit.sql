-- Audit SQL Server Authentication Configuration
SET NOCOUNT ON;

-- 1. List All Server Logins by Authentication Type
PRINT '=== Server Logins by Authentication Type ===';
SELECT 
    name AS Login_Name,
    type_desc AS Authentication_Type,
    is_disabled AS Is_Disabled,
    create_date AS Created_Date,
    modify_date AS Last_Modified,
    CASE 
        WHEN type_desc = 'SQL_LOGIN' THEN 
            CASE 
                WHEN is_policy_checked = 1 THEN 'Enabled'
                ELSE 'Disabled'
            END 
        ELSE 'N/A'
    END AS CHECK_POLICY,
    CASE 
        WHEN type_desc = 'SQL_LOGIN' THEN 
            CASE 
                WHEN is_expiration_checked = 1 THEN 'Enabled'
                ELSE 'Disabled'
            END 
        ELSE 'N/A'
    END AS CHECK_EXPIRATION
FROM sys.server_principals
WHERE type IN ('S', 'U', 'G') -- SQL Login, Windows User, Windows Group
  AND principal_id > 1 -- Exclude system principals
ORDER BY type_desc, name;

-- 2. Summarize Authentication Usage
PRINT CHAR(13) + '=== Authentication Usage Summary ===';
SELECT 
    type_desc AS Authentication_Type,
    COUNT(*) AS Login_Count,
    SUM(CASE WHEN is_disabled = 0 THEN 1 ELSE 0 END) AS Enabled_Logins,
    SUM(CASE WHEN is_disabled = 1 THEN 1 ELSE 0 END) AS Disabled_Logins
FROM sys.server_principals
WHERE type IN ('S', 'U', 'G')
  AND principal_id > 1
GROUP BY type_desc;

-- 3. Scrutinize 'sa' Login
PRINT CHAR(13) + '=== ''sa'' Login Status ===';
SELECT 
    name AS Login_Name,
    is_disabled AS Is_Disabled,
    CASE 
        WHEN name = 'sa' THEN 'Default Name (Not Renamed)'
        ELSE 'Renamed'
    END AS Name_Status,
    CASE 
        WHEN is_policy_checked = 1 THEN 'Enabled'
        ELSE 'Disabled (Weak Password Risk)'
    END AS CHECK_POLICY,
    CASE 
        WHEN is_expiration_checked = 1 THEN 'Enabled'
        ELSE 'Disabled (No Expiration Risk)'
    END AS CHECK_EXPIRATION,
    create_date AS Created_Date,
    modify_date AS Last_Modified
FROM sys.sql_logins
WHERE name = 'sa' OR principal_id = 1; -- Check both 'sa' and principal_id 1 in case renamed

-- 4. Check if 'sa' Usage is Audited
PRINT CHAR(13) + '=== ''sa'' Login Auditing Status ===';
IF EXISTS (
    SELECT 1 
    FROM sys.server_audits a
    JOIN sys.server_audit_specifications s ON a.audit_guid = s.audit_guid
    JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
    WHERE d.audited_result = 'SUCCESS AND FAILURE'
      AND d.audit_action_name LIKE '%LOGIN%'
      AND s.is_state_enabled = 1
)
    SELECT 
        'Auditing Enabled' AS Audit_Status,
        'Login auditing is configured for SUCCESS and FAILURE, potentially covering ''sa''.' AS Details
ELSE
    SELECT 
        'Auditing Disabled' AS Audit_Status,
        'No server-level login auditing detected for ''sa''. Recommendation: Enable auditing for SUCCESS and FAILURE logins.' AS Details;

-- 5. Check Mixed Mode Authentication Setting
PRINT CHAR(13) + '=== Server Authentication Mode ===';
SELECT 
    CASE SERVERPROPERTY('IsIntegratedSecurityOnly')
        WHEN 1 THEN 'Windows Authentication Only'
        ELSE 'Mixed Mode (Windows and SQL Server Authentication)'
    END AS Authentication_Mode,
    CASE SERVERPROPERTY('IsIntegratedSecurityOnly')
        WHEN 1 THEN 'Recommendation: Preferred mode for security.'
        ELSE 'Recommendation: Justify SQL Server Authentication usage and secure SQL Logins.'
    END AS Security_Note;

-- 6. Identify SQL Logins with Potential Security Risks
PRINT CHAR(13) + '=== SQL Logins with Potential Security Risks ===';
SELECT 
    name AS Login_Name,
    'CHECK_POLICY Disabled' AS Issue
FROM sys.sql_logins
WHERE is_policy_checked = 0
  AND is_disabled = 0
UNION ALL
SELECT 
    name,
    'CHECK_EXPIRATION Disabled'
FROM sys.sql_logins
WHERE is_expiration_checked = 0
  AND is_disabled = 0
UNION ALL
SELECT 
    l.name,
    'Privileged Account (sysadmin)'
FROM sys.sql_logins l
INNER JOIN sys.server_role_members rm ON l.principal_id = rm.member_principal_id
INNER JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
WHERE r.name = 'sysadmin'
  AND l.is_disabled = 0
ORDER BY Login_Name;

-- 7. Export Results to a Table for Reporting
IF OBJECT_ID('tempdb..#AuthAudit') IS NOT NULL
    DROP TABLE #AuthAudit;

CREATE TABLE #AuthAudit (
    Audit_Category VARCHAR(100),
    Login_Name VARCHAR(128),
    Issue_Detail VARCHAR(500),
    Recorded_Date DATETIME DEFAULT GETDATE()
);

INSERT INTO #AuthAudit (Audit_Category, Login_Name, Issue_Detail)
SELECT 
    'SQL Authentication' AS Audit_Category,
    name AS Login_Name,
    'SQL Login - Justify usage; CHECK_POLICY: ' + 
        CASE WHEN is_policy_checked = 1 THEN 'Enabled' ELSE 'Disabled' END + 
        '; CHECK_EXPIRATION: ' + 
        CASE WHEN is_expiration_checked = 1 THEN 'Enabled' ELSE 'Disabled' END AS Issue_Detail
FROM sys.sql_logins
WHERE is_disabled = 0
UNION ALL
SELECT 
    'sa Login',
    name,
    CASE 
        WHEN is_disabled = 1 THEN 'Disabled - Secure'
        ELSE 'Enabled - Ensure renamed and strong password; CHECK_POLICY: ' + 
             CASE WHEN is_policy_checked = 1 THEN 'Enabled' ELSE 'Disabled' END
    END
FROM sys.sql_logins
WHERE name = 'sa' OR principal_id = 1
UNION ALL
SELECT 
    'Privileged SQL Login',
    l.name,
    'sysadmin role detected'
FROM sys.sql_logins l
INNER JOIN sys.server_role_members rm ON l.principal_id = rm.member_principal_id
INNER JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
WHERE r.name = 'sysadmin'
  AND l.is_disabled = 0;

-- Display Audit Summary
PRINT CHAR(13) + '=== Audit Summary ===';
SELECT 
    Audit_Category,
    COUNT(*) AS Issue_Count,
    STRING_AGG(Login_Name, ', ') AS Affected_Logins
FROM #AuthAudit
GROUP BY Audit_Category;

-- Cleanup
-- DROP TABLE #AuthAudit; -- Uncomment to drop temp table
