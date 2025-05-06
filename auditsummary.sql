-- Audit SQL Server for Principle of Least Privilege and Auditing Configuration
SET NOCOUNT ON;

-- 1. Check 'sa' Login Auditing Status
PRINT '=== ''sa'' Login Auditing Status ===';
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

-- 2. Audit Server-Level Role Memberships
PRINT CHAR(13) + '=== Server-Level Role Memberships ===';
SELECT 
    r.name AS Server_Role,
    m.name AS Member_Name,
    m.type_desc AS Member_Type,
    CASE 
        WHEN m.is_disabled = 1 THEN 'Disabled'
        ELSE 'Enabled'
    END AS Member_Status,
    'Recommendation: Justify membership in ' + r.name + ' role.' AS Note
FROM sys.server_principals r
INNER JOIN sys.server_role_members rm ON r.principal_id = rm.role_principal_id
INNER JOIN sys.server_principals m ON rm.member_principal_id = m.principal_id
WHERE r.type = 'R' 
  AND r.name IN ('sysadmin', 'serveradmin', 'securityadmin', 'processadmin', 'setupadmin', 'bulkadmin', 'diskadmin', 'dbcreator')
ORDER BY r.name, m.name;

-- 3. Audit Database-Level Role Memberships
PRINT CHAR(13) + '=== Database-Level Role Memberships ===';
DECLARE @DatabaseRoleAudit NVARCHAR(MAX) = '';
DECLARE @DBName SYSNAME;

DECLARE db_cursor CURSOR FOR
SELECT name FROM sys.databases WHERE state = 0; -- Online databases only

OPEN db_cursor;
FETCH NEXT FROM db_cursor INTO @DBName;

WHILE @@FETCH_STATUS = 0
BEGIN
    SET @DatabaseRoleAudit += '
    SELECT 
        ''' + QUOTENAME(@DBName) + ''' AS Database_Name,
        r.name AS Role_Name,
        m.name AS Member_Name,
        m.type_desc AS Member_Type,
        CASE 
            WHEN r.name = ''db_owner'' THEN ''Warning: Excessive permissions (db_owner)''
            ELSE ''Review: Justify membership''
        END AS Audit_Note
    FROM ' + QUOTENAME(@DBName) + '.sys.database_principals r
    INNER JOIN ' + QUOTENAME(@DBName) + '.sys.database_role_members rm ON r.principal_id = rm.role_principal_id
    INNER JOIN ' + QUOTENAME(@DBName) + '.sys.database_principals m ON rm.member_principal_id = m.principal_id
    WHERE r.type = ''R''
      AND m.name != ''dbo''
    UNION ALL';
    
    FETCH NEXT FROM db_cursor INTO @DBName;
END;

CLOSE db_cursor;
DEALLOCATE db_cursor;

-- Remove trailing UNION ALL and execute
SET @DatabaseRoleAudit = LEFT(@DatabaseRoleAudit, LEN(@DatabaseRoleAudit) - 10);
IF @DatabaseRoleAudit != ''
BEGIN
    EXEC sp_executesql @DatabaseRoleAudit;
END
ELSE
BEGIN
    SELECT 'No database roles found' AS Database_Name, '' AS Role_Name, '' AS Member_Name, '' AS Member_Type, '' AS Audit_Note;
END;

-- 4. Audit Excessive db_owner and dbo Permissions
PRINT CHAR(13) + '=== Excessive db_owner and dbo Permissions ===';
DECLARE @DBOwnerAudit NVARCHAR(MAX) = '';
DECLARE @DBName2 SYSNAME;

DECLARE db_cursor2 CURSOR FOR
SELECT name FROM sys.databases WHERE state = 0;

OPEN db_cursor2;
FETCH NEXT FROM db_cursor2 INTO @DBName2;

WHILE @@FETCH_STATUS = 0
BEGIN
    SET @DBOwnerAudit += '
    SELECT 
        ''' + QUOTENAME(@DBName2) + ''' AS Database_Name,
        p.name AS Principal_Name,
        p.type_desc AS Principal_Type,
        ''db_owner role membership'' AS Issue
    FROM ' + QUOTENAME(@DBName2) + '.sys.database_principals p
    INNER JOIN ' + QUOTENAME(@DBName2) + '.sys.database_role_members rm ON p.principal_id = rm.member_principal_id
    INNER JOIN ' + QUOTENAME(@DBName2) + '.sys.database_principals r ON rm.role_principal_id = r.principal_id
    WHERE r.name = ''db_owner''
      AND p.name != ''dbo''
    UNION ALL
    SELECT 
        ''' + QUOTENAME(@DBName2) + ''',
        p.name,
        p.type_desc,
        ''Mapped to dbo user''
    FROM ' + QUOTENAME(@DBName2) + '.sys.database_principals p
    WHERE p.name = ''dbo''
      AND p.sid NOT IN (SELECT sid FROM sys.server_principals WHERE name = ''sa'')
    UNION ALL';
    
    FETCH NEXT FROM db_cursor2 INTO @DBName2;
END;

CLOSE db_cursor2;
DEALLOCATE db_cursor2;

-- Remove trailing UNION ALL and execute
SET @DBOwnerAudit = LEFT(@DBOwnerAudit, LEN(@DBOwnerAudit) - 10);
IF @DBOwnerAudit != ''
BEGIN
    EXEC sp_executesql @DBOwnerAudit;
END
ELSE
BEGIN
    SELECT 'No excessive db_owner/dbo permissions found' AS Database_Name, '' AS Principal_Name, '' AS Principal_Type, '' AS Issue;
END;

-- 5. Audit Permissions Granted to PUBLIC Role
PRINT CHAR(13) + '=== Permissions Granted to PUBLIC Role ===';
DECLARE @PublicPermsAudit NVARCHAR(MAX) = '';
DECLARE @DBName3 SYSNAME;

DECLARE db_cursor3 CURSOR FOR
SELECT name FROM sys.databases WHERE state = 0;

OPEN db_cursor3;
FETCH NEXT FROM db_cursor3 INTO @DBName3;

WHILE @@FETCH_STATUS = 0
BEGIN
    SET @PublicPermsAudit += '
    SELECT 
        ''' + QUOTENAME(@DBName3) + ''' AS Database_Name,
        p.class_desc AS Object_Type,
        COALESCE(o.name, ''N/A'') AS Object_Name,
        p.permission_name AS Permission,
        p.state_desc AS State,
        ''Warning: PUBLIC role permissions should be minimized'' AS Audit_Note
    FROM ' + QUOTENAME(@DBName3) + '.sys.database_permissions p
    LEFT JOIN ' + QUOTENAME(@DBName3) + '.sys.objects o ON p.major_id = o.object_id
    WHERE p.grantee_principal_id = (
        SELECT principal_id 
        FROM ' + QUOTENAME(@DBName3) + '.sys.database_principals 
        WHERE name = ''public''
    )
    UNION ALL';
    
    FETCH NEXT FROM db_cursor3 INTO @DBName3;
END;

CLOSE db_cursor3;
DEALLOCATE db_cursor3;

-- Remove trailing UNION ALL and execute
SET @PublicPermsAudit = LEFT(@PublicPermsAudit, LEN(@PublicPermsAudit) - 10);
IF @PublicPermsAudit != ''
BEGIN
    EXEC sp_executesql @PublicPermsAudit;
END
ELSE
BEGIN
    SELECT 'No PUBLIC role permissions found' AS Database_Name, '' AS Object_Type, '' AS Object_Name, '' AS Permission, '' AS State, '' AS Audit_Note;
END;

-- 6. Check Azure Auditing (SQL Server Audit to Log Analytics)
PRINT CHAR(13) + '=== Azure Auditing Configuration (Log Analytics) ===';
IF EXISTS (
    SELECT 1 
    FROM sys.server_audits 
    WHERE destination = 'LOG_ANALYTICS'
      AND is_state_enabled = 1
)
    SELECT 
        'Azure Log Analytics Auditing Enabled' AS Audit_Status,
        'SQL Server audit data is being sent to Azure Log Analytics.' AS Details
ELSE
    SELECT 
        'Azure Log Analytics Auditing Disabled' AS Audit_Status,
        'No audit configuration found for Log Analytics. Recommendation: Enable Azure auditing for comprehensive monitoring.' AS Details;

-- 7. Export Results to a Table for Reporting
IF OBJECT_ID('tempdb..#LeastPrivilegeAudit') IS NOT NULL
    DROP TABLE #LeastPrivilegeAudit;

CREATE TABLE #LeastPrivilegeAudit (
    Audit_Category VARCHAR(100),
    Database_Name VARCHAR(128),
    Principal_Name VARCHAR(128),
    Issue_Detail VARCHAR(500),
    Recorded_Date DATETIME DEFAULT GETDATE()
);

INSERT INTO #LeastPrivilegeAudit (Audit_Category, Database_Name, Principal_Name, Issue_Detail)
SELECT 
    'Server Role' AS Audit_Category,
    'N/A' AS Database_Name,
    m.name AS Principal_Name,
    'Member of ' + r.name + ' server role' AS Issue_Detail
FROM sys.server_principals r
INNER JOIN sys.server_role_members rm ON r.principal_id = rm.role_principal_id
INNER JOIN sys.server_principals m ON rm.member_principal_id = m.principal_id
WHERE r.type = 'R' 
  AND r.name IN ('sysadmin', 'serveradmin', 'securityadmin')
UNION ALL
SELECT 
    'Database Role',
    d.Database_Name,
    m.name,
    'Member of ' + r.name + ' role in ' + d.Database_Name
FROM sys.databases db
CROSS APPLY (
    SELECT 
        QUOTENAME(db.name) AS Database_Name,
        r.name,
        m.name
    FROM sys.database_principals r
    INNER JOIN sys.database_role_members rm ON r.principal_id = rm.role_principal_id
    INNER JOIN sys.database_principals m ON rm.member_principal_id = m.principal_id
    WHERE r.type = 'R'
      AND m.name != 'dbo'
      AND r.name = 'db_owner'
) d
WHERE db.name = d.Database_Name
UNION ALL
SELECT 
    'PUBLIC Role Permission',
    p.Database_Name,
    'public',
    'Permission: ' + p.permission_name + ' on ' + COALESCE(p.Object_Name, 'N/A')
FROM sys.databases db
CROSS APPLY (
    SELECT 
        QUOTENAME(db.name) AS Database_Name,
        p.class_desc,
        COALESCE(o.name, 'N/A') AS Object_Name,
        p.permission_name
    FROM sys.database_permissions p
    LEFT JOIN sys.objects o ON p.major_id = o.object_id
    WHERE p.grantee_principal_id = (
        SELECT principal_id 
        FROM sys.database_principals 
        WHERE name = 'public'
    )
) p
WHERE db.name = p.Database_Name;

-- Display Audit Summary
PRINT CHAR(13) + '=== Audit Summary ===';
SELECT 
    Audit_Category,
    COUNT(*) AS Issue_Count,
    STRING_AGG(Principal_Name + ' (' + ISNULL(Database_Name, 'Server') + ')', ', ') AS Affected_Principals
FROM #LeastPrivilegeAudit
GROUP BY Audit_Category;

-- Cleanup
-- DROP TABLE #LeastPrivilegeAudit; -- Uncomment to drop temp table
