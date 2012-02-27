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
#I apologize for this global "I" variable. It's to make re matching
# be case insensitive, and used for the search function. Didn't want
# to import the entire library for one variable.
from re import search, I

class SQLInjectionAnalyzer(AttackAnalyzer):

    attackType = 'sql'
    httpIDRE = 'HTTP/\d\.\d\r\n'

    def isQuery(self, packet):
        """
        Returns True if the packet is an HTTP GET that looks like it has a
         query in it.
        
        @param packet - The packet to search in
        """
        if search('^GET.*\?.*' + self.httpIDRE, packet.payload, I) != None:
            return True
        else:
            return False

    def hasSQLComment(self, packet):
        """
        Returns True if the packet is an HTTP GET that looks like it has an
         sql comment in it.
        
        @param packet - The packet to search in
        """
        if search('^GET.*\?.*(;.*)*--.*' + self.httpIDRE, packet.payload, I) != None:
            return True
        else:
            return False 
            
    def hasSQLCode(self, packet):
        """
        Returns True if the packet has any sql code in the query, false if 
         not
        
        @param packet - The packet to search in
        """
        sqlKeyWords = ["ADD", "EXCEPT", "PERCENT",
                        "ALL", "EXEC", "PLAN",
                        "ALTER", "EXECUTE", "PRECISION",
                        "AND", "EXISTS", "PRIMARY",
                        "ANY", "EXIT", "PRINT",
                        "AS", "FETCH", "PROC",
                        "ASC", "FILE", "PROCEDURE",
                        "AUTHORIZATION", "FILLFACTOR", "PUBLIC",
                        "BACKUP", "FOR", "RAISERROR",
                        "BEGIN", "FOREIGN", "READ",
                        "BETWEEN", "FREETEXT", "READTEXT",
                        "BREAK", "FREETEXTTABLE", "RECONFIGURE",
                        "BROWSE", "FROM", "REFERENCES",
                        "BULK", "FULL", "REPLICATION",
                        "BY", "FUNCTION", "RESTORE",
                        "CASCADE", "GOTO", "RESTRICT",
                        "CASE", "GRANT", "RETURN",
                        "CHECK", "GROUP", "REVOKE",
                        "CHECKPOINT", "HAVING", "RIGHT",
                        "CLOSE", "HOLDLOCK", "ROLLBACK",
                        "CLUSTERED", "IDENTITY", "ROWCOUNT",
                        "COALESCE", "IDENTITY_INSERT", "ROWGUIDCOL",
                        "COLLATE", "IDENTITYCOL", "RULE",
                        "COLUMN", "IF", "SAVE",
                        "COMMIT", "IN", "SCHEMA",
                        "COMPUTE", "INDEX", "SELECT",
                        "CONSTRAINT", "INNER", "SESSION_USER",
                        "CONTAINS", "INSERT", "SET",
                        "CONTAINSTABLE", "INTERSECT", "SETUSER",
                        "CONTINUE", "INTO", "SHUTDOWN",
                        "CONVERT", "IS", "SOME",
                        "CREATE", "JOIN", "STATISTICS",
                        "CROSS", "KEY", "SYSTEM_USER",
                        "CURRENT", "KILL", "TABLE",
                        "CURRENT_DATE", "LEFT", "TEXTSIZE",
                        "CURRENT_TIME", "LIKE", "THEN",
                        "CURRENT_TIMESTAMP", "LINENO", "TO",
                        "CURRENT_USER", "LOAD", "TOP",
                        "CURSOR", "NATIONAL", "TRAN",
                        "DATABASE", "NOCHECK", "TRANSACTION",
                        "DBCC", "NONCLUSTERED", "TRIGGER",
                        "DEALLOCATE", "NOT", "TRUNCATE",
                        "DECLARE", "NULL", "TSEQUAL",
                        "DEFAULT", "NULLIF", "UNION",
                        "DELETE", "OF", "UNIQUE",
                        "DENY", "OFF", "UPDATE",
                        "DESC", "OFFSETS", "UPDATETEXT",
                        "DISK", "ON", "USE",
                        "DISTINCT", "OPEN", "USER",
                        "DISTRIBUTED", "OPENDATASOURCE", "VALUES",
                        "DOUBLE", "OPENQUERY", "VARYING",
                        "DROP", "OPENROWSET", "VIEW",
                        "DUMMY", "OPENXML", "WAITFOR",
                        "DUMP", "OPTION", "WHEN",
                        "ELSE", "OR", "WHERE",
                        "END", "ORDER", "WHILE",
                        "ERRLVL", "OUTER", "WITH",
                        "ESCAPE", "OVER", "WRITETEXT"]
        SQLCodePossibilities = '(.*('
        for word in sqlKeyWords:
            SQLCodePossibilities += '' + word + '|'
        SQLCodePossibilities = SQLCodePossibilities[:-1] + ').*)'
        #print SQLCodePossibilities
        if search('^GET.*\?.*' + SQLCodePossibilities + '.*' + \
                    self.httpIDRE, packet.payload, I) != None:
            return True
        else:
            return False

    def addAttackProfile(self):
        """
        Sets up an automata to detect SQL attacks. It has a chain of nodes with length
         numPrelims that are the path to detect likely automated attacks, they check
         for just queries. Each node on this path has a 'fast track' transition
         to the threat node if any query has sql code or an sql comment in it.
        """
        numPrelims = 15
        for i in range(numPrelims):
            self.addPrelimNode(1000)
        threat = self.addThreatNode(60000)
        self.addTransition(0, 1, 1, [self.isQuery])
        self.addTransition(0, threat, numPrelims*10, [self.hasSQLCode])
        self.addTransition(0, threat, numPrelims*5, [self.hasSQLComment])
        for prelimIndex in range(1, numPrelims+1):
            #for the first numPrelims-1 nodes...
            self.addTransition(prelimIndex, threat, numPrelims * 10, 
                                    [self.hasSQLCode])
            self.addTransition(prelimIndex, threat, numPrelims * 5, 
                                    [self.hasSQLComment])
            self.addTransition(prelimIndex, prelimIndex + 1, prelimIndex+1, [self.isQuery])
        #Add transitions for looping in threat.
        self.addTransition(threat, threat, numPrelims * 10, 
                                    [self.hasSQLCode])
        self.addTransition(threat, threat, numPrelims * 5, 
                                    [self.hasSQLComment])
        self.addTransition(threat, threat, numPrelims, [self.isQuery])
