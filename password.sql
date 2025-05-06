-- Audit SQL Server Login Password Policies
SET NOCOUNT ON;

-- 1. Check Server-Level Password Policy Settings
PRINT '=== Server-Level Password Policy Settings ===';
SELECT 
    name AS Server_Setting,
    CAST(value AS VARCHAR(100)) AS Setting_Value
FROM sys.configurations
WHERE name IN ('default password policy enforced', 'default password length');

-- 2. List SQL Logins with Password Policy and Expiration Settings
PRINT CHAR(13) + '=== SQL Logins Password Policy and Expiration Settings ===';
SELECT 
    name AS Login_Name,
    is_disabled AS Is_Disabled,
    CASE 
        WHEN is_policy_checked = 1 THEN 'Enabled'
        ELSE 'Disabled'
    END AS CHECK_POLICY,
    CASE 
        WHEN is_expiration_checked = 1 THEN 'Enabled'
        ELSE 'Disabled'
    END AS CHECK_EXPIRATION,
    create_date AS Created_Date,
    modify_date AS Last_Modified
FROM sys.sql_logins
WHERE principal_id > 1 -- Exclude system logins
ORDER BY name;

-- 3. Identify Logins with Weak or Default Passwords (Basic Check)
-- Note: SQL Server doesn't store passwords in plaintext, so we check for common weak patterns indirectly
PRINT CHAR(13) + '=== Potential Weak Password Indicators ===';
SELECT 
    name AS Login_Name,
    'Warning: CHECK_POLICY is OFF' AS Issue
FROM sys.sql_logins
WHERE is_policy_checked = 0
UNION ALL
SELECT 
    name AS Login_Name,
    'Warning: Password Expiration is OFF' AS Issue
FROM sys.sql_logins
WHERE is_expiration_checked = 0
ORDER BY Login_Name;

-- 4. Check Privileged Accounts (sysadmin role) for Policy Compliance
PRINT CHAR(13) + '=== Privileged Accounts (sysadmin) Policy Compliance ===';
SELECT 
    l.name AS Login_Name,
    CASE 
        WHEN l.is_policy_checked = 1 THEN 'Enabled'
        ELSE 'Disabled'
    END AS CHECK_POLICY,
    CASE 
        WHEN l.is_expiration_checked = 1 THEN 'Enabled'
        ELSE 'Disabled'
    END AS CHECK_EXPIRATION,
    'sysadmin' AS Server_Role
FROM sys.sql_logins l
INNER JOIN sys.server_role_members rm ON l.principal_id = rm.member_principal_id
INNER JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
WHERE r.name = 'sysadmin'
ORDER BY l.name;

-- 5. Check Password History and Complexity (Windows Policy Dependency)
PRINT CHAR(13) + '=== Password Policy Notes ===';
SELECT 
    'Note' AS Note,
    'SQL Server relies on Windows password policies for complexity, length, and history when CHECK_POLICY is enabled.' AS Description
UNION ALL
SELECT 
    'Recommendation',
    'Ensure Windows policies enforce: Minimum 8 characters, complexity (uppercase, lowercase, numbers, special chars), and password history (e.g., 24 previous passwords).'
UNION ALL
SELECT 
    'Weak Password Audit',
    'Manually test for weak passwords using tools like SQLPing or custom scripts, as T-SQL cannot directly read password content.';

-- 6. Optional: Export Results to a Table for Reporting
IF OBJECT_ID('tempdb..#PasswordPolicyAudit') IS NOT NULL
    DROP TABLE #PasswordPolicyAudit;

CREATE TABLE #PasswordPolicyAudit (
    Audit_Category VARCHAR(100),
    Login_Name VARCHAR(128),
    Issue_Detail VARCHAR(500),
    Recorded_Date DATETIME DEFAULT GETDATE()
);

INSERT INTO #PasswordPolicyAudit (Audit_Category, Login_Name, Issue_Detail)
SELECT 
    'No CHECK_POLICY' AS Audit_Category,
    name AS Login_Name,
    'CHECK_POLICY is Disabled' AS Issue_Detail
FROM sys.sql_logins
WHERE is_policy_checked = 0
UNION ALL
SELECT 
    'No CHECK_EXPIRATION',
    name,
    'CHECK_EXPIRATION is Disabled'
FROM sys.sql_logins
WHERE is_expiration_checked = 0
UNION ALL
SELECT 
    'Privileged Account',
    l.name,
    'sysadmin role with CHECK_POLICY ' + CASE WHEN l.is_policy_checked = 1 THEN 'Enabled' ELSE 'Disabled' END
FROM sys.sql_logins l
INNER JOIN sys.server_role_members rm ON l.principal_id = rm.member_principal_id
INNER JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
WHERE r.name = 'sysadmin';

-- Display Audit Summary
PRINT CHAR(13) + '=== Audit Summary ===';
SELECT 
    Audit_Category,
    COUNT(*) AS Issue_Count,
    STRING_AGG(Login_Name, ', ') AS Affected_Logins
FROM #PasswordPolicyAudit
GROUP BY Audit_Category;

-- Cleanup
-- DROP TABLE #PasswordPolicyAudit; -- Uncomment to drop temp table
