/*
This T-SQL needs to be executed to revoke execute permissions on Extended Procedures from the PUBLIC user/role.
This is a dynamic script to account for different SQL versions.

Date: June 21, 2016
Murli Koushik
*/

SET NOCOUNT ON ;

IF EXISTS ( SELECT 1 FROM TEMPDB.DBO.SYSOBJECTS WHERE NAME LIKE '#TEMPTABLE%' )
BEGIN
  DROP TABLE #TEMPTABLE;
END

CREATE TABLE #TEMPTABLE ( ROWID INT IDENTITY(1,1) NOT NULL, COMMANDSTRING NVARCHAR(255) NULL ) ;

INSERT INTO #TEMPTABLE
SELECT 'REVOKE EXECUTE ON ' + OBJECT_NAME(major_id) + ' FROM ' + UPPER ( USER_NAME(grantee_principal_id) ) + '; '
FROM   sys.database_permissions -- ORDER BY OBJECT_NAME(major_id)
WHERE  OBJECT_NAME(major_ID) LIKE 'xp%'
AND    USER_NAME(grantee_principal_id) LIKE 'PUBLIC'
ORDER  BY OBJECT_NAME(major_id)

-- SELECT * FROM #TEMPTABLE ;

DECLARE @CMD NVARCHAR(255)

DECLARE RevokeCur CURSOR FOR 
SELECT COMMANDSTRING FROM #TEMPTABLE WHERE COMMANDSTRING LIKE 'REVOKE%' ORDER BY ROWID ;

OPEN RevokeCur ;
FETCH NEXT FROM RevokeCur INTO @CMD ;

WHILE ( @@FETCH_STATUS = 0 )
BEGIN   
  EXEC (@CMD);  

  FETCH NEXT FROM RevokeCur INTO @CMD ;
END   

CLOSE RevokeCur ;
DEALLOCATE RevokeCur ;

