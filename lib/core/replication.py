import sqlite3


class Replication:
    def __init__(self, dbpath):
        self.dbpath = dbpath
        self.connection = sqlite3.connect(dbpath)
        self.connection.isolation_level = None
        self.cursor = self.connection.cursor()
        
    class DataType:
        def __init__(self, name):
            self.name = name

        def __str__(self):
            return self.name

        def __repr__(self):
            return "<DataType: %s>" % self
       
    class Table:
        def __init__(self, parent, name, columns, typeless=False):
            self.parent = parent
            self.name = name
            self.columns = columns
            if not typeless:
                self.parent.cursor.execute('CREATE TABLE %s (%s)' % (name, ','.join('%s %s' % (colname, coltype) for colname, coltype in columns)))
            else:
                self.parent.cursor.execute('CREATE TABLE %s (%s)' % (name, ','.join(colname for colname in columns)))
            
        def insert(self, rows):
            self.parent.cursor.executemany('INSERT INTO %s VALUES (?,?,?,?,?)' % self.name, rows)


    NULL = DataType('NULL')
    INTEGER = DataType('INTEGER')
    REAL = DataType('REAL')
    TEXT = DataType('TEXT')
    BLOB = DataType('BLOB')
    
    def createTable(self, name, columns):
        return Table(self, name, columns)
    
    def __del__(self):
        self.cursor.close()
        self.connection.close()
        