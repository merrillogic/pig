"""
analyzers.py

Basic file for defining the different attack profiles
Functions to use are:
- addPrelimNode() :: adds a Node at the PRELIM threat level
    @return - The integer index of the added node
- addThreatNode() :: adds a Node at the THREAT threat level
    @return - The integer index of the added node
- addTransition(src, dest, score, triggers) :: adds a scored transition between
  the src and dest nodes
    @param src - Integer index of the Node to transition from
    @param dest - Integer index of the Node to transition to
    @param score - Numerical attack score to be assigned to the transition
    @param triggers - List of boolean functions to be satisfied in order to
        make the transition

"""
from attackanalyzer import AttackAnalyzer
from re import search

class SQLInjectionAnalyzer(AttackAnalyzer):

    attackType = 'sql'

    def isQuery(self, packet):
        if search('^GET.*?.*HTTP/\d\.\d\n', packet.payload):
            return True
        else:
            return False

    def hasSQLComment(self, packet):
        if search('^GET.*?.*;--.*HTTP/\d\.\d\n', packet.payload):
            return True
        else:
            return False 
            
    def hasSQLCodes(self, packet):
        #OhGodSoMany
        '''
        ADD 	EXCEPT 	PERCENT
ALL 	EXEC 	PLAN
ALTER 	EXECUTE 	PRECISION
AND 	EXISTS 	PRIMARY
ANY 	EXIT 	PRINT
AS 	FETCH 	PROC
ASC 	FILE 	PROCEDURE
AUTHORIZATION 	FILLFACTOR 	PUBLIC
BACKUP 	FOR 	RAISERROR
BEGIN 	FOREIGN 	READ
BETWEEN 	FREETEXT 	READTEXT
BREAK 	FREETEXTTABLE 	RECONFIGURE
BROWSE 	FROM 	REFERENCES
BULK 	FULL 	REPLICATION
BY 	FUNCTION 	RESTORE
CASCADE 	GOTO 	RESTRICT
CASE 	GRANT 	RETURN
CHECK 	GROUP 	REVOKE
CHECKPOINT 	HAVING 	RIGHT
CLOSE 	HOLDLOCK 	ROLLBACK
CLUSTERED 	IDENTITY 	ROWCOUNT
COALESCE 	IDENTITY_INSERT 	ROWGUIDCOL
COLLATE 	IDENTITYCOL 	RULE
COLUMN 	IF 	SAVE
COMMIT 	IN 	SCHEMA
COMPUTE 	INDEX 	SELECT
CONSTRAINT 	INNER 	SESSION_USER
CONTAINS 	INSERT 	SET
CONTAINSTABLE 	INTERSECT 	SETUSER
CONTINUE 	INTO 	SHUTDOWN
CONVERT 	IS 	SOME
CREATE 	JOIN 	STATISTICS
CROSS 	KEY 	SYSTEM_USER
CURRENT 	KILL 	TABLE
CURRENT_DATE 	LEFT 	TEXTSIZE
CURRENT_TIME 	LIKE 	THEN
CURRENT_TIMESTAMP 	LINENO 	TO
CURRENT_USER 	LOAD 	TOP
CURSOR 	NATIONAL 	TRAN
DATABASE 	NOCHECK 	TRANSACTION
DBCC 	NONCLUSTERED 	TRIGGER
DEALLOCATE 	NOT 	TRUNCATE
DECLARE 	NULL 	TSEQUAL
DEFAULT 	NULLIF 	UNION
DELETE 	OF 	UNIQUE
DENY 	OFF 	UPDATE
DESC 	OFFSETS 	UPDATETEXT
DISK 	ON 	USE
DISTINCT 	OPEN 	USER
DISTRIBUTED 	OPENDATASOURCE 	VALUES
DOUBLE 	OPENQUERY 	VARYING
DROP 	OPENROWSET 	VIEW
DUMMY 	OPENXML 	WAITFOR
DUMP 	OPTION 	WHEN
ELSE 	OR 	WHERE
END 	ORDER 	WHILE
ERRLVL 	OUTER 	WITH
ESCAPE 	OVER 	WRITETEXT
        '''
        SQLCodePossibilities = '[]'
        if search('^GET.*?.*' + SQLCodePossibilities + '.*HTTP/\d\.\d\n', packet.payload):
            return True
        else:
            False

    def addAttackProfile(self):
        numPrelims = 5
        for i in range(numPrelims):
            self.addPrelimNode(500)
        threat = self.addThreatNode()
        
        self.addTransition(0, 1, 1, [self.isQuery])
        self.addTransition(0, threat, [self.hasSQLComment])
        for prelimIndex in range(1, numPrelims):
            #for the first numPrelims-1 nodes...
            self.addTransition(prelimIndex, prelimIndex + 1, prelimIndex+1, [self.isQuery])
            self.addTransition(prelimIndex, threat, numPrelims * 2, [self.hasSQLComment])
        
        #Add transitions for looping in threat.
        self.addTransition(threat, threat, numPrelims, [self.isQuery])
        self.addTransition(threat, threat, numPrelims * 2, [self.hasSQLComment])
        
