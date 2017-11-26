#!/usr/bin/python

import sys
import codecs

import ipaddress as ip
import pandas as pd

from datetime import datetime as dt

class BroLogFile:
    def doSeparator(self, fields):
        sep = fields[1]

        if len(sep) == 1:          # a literal?
            self.separator = sep
        elif sep[:2] == '\\x':     # a hexadecimal (ASCII) value?
            self.separator = chr(int(sep[2:], 16))
        else:
            raise ValueError('invalid separator format in log file')

        return


    def __init__(self, fname, row_transform = None, row_filter = None):
        """
        Crete a new Pandas DataFrame from the given file.

        fname is the name of the file to be opened.

        row_transform is an (optional) function function which will be applied
              to each row as it is read.  It may modify the individual column
              values, such as by performing integer conversions on exptected
              numeric fields.  This function does not return a value.

        row_filter is an (optional) function which will be used to test each
              input row.  It is executed after row_transform (if one exists),
              and must return a boolean value.  If True, the row will be
              included in the result.  If False, the row will be suppressed.

        May generate an exception if the file could not be opened or if an
        invalid format is found in the separator value.
        """

        self.row_transform = row_transform
        self.row_filter = row_filter

        self.field_names = []
        self.field_types = []
        self.empty_field = '(empty)'
        self.unset_field = '-'
        self.set_separator = ','
        self.separator = ' '

        self.rows = []

        self.field_map = None

        #f = file(fname, 'r')
        f = codecs.open(fname, 'r', encoding = 'utf-8')
        line = f.readline()

        while line[0] == '#':
            fields = line[1:].strip().split(self.separator)

            if fields[0] == 'separator':
                self.doSeparator(fields)
            elif fields[0] == 'empty_field':
                self.empty_field = fields[1]
            elif fields[0] == 'unset_field':
                self.unset_field = fields[1]
            elif fields[0] == 'fields':
                self.field_names = fields[1:]
            elif fields[0] == 'types':
                self.field_types = fields[1:]

            line = f.readline()

        for line in f:
            if line[0] == '#': continue

            fields = line.rstrip("\r\n").split(self.separator)

            if self.row_transform is not None:
                self.row_transform(fields, self.field_types, self.field_names)

            if self.row_filter is not None:
                if self.row_filter(fields, self.field_types, self.field_names) is False: continue

            self.rows.append(fields)

        return

    def asDataFrame(self):
        df = pd.DataFrame(self.rows, columns = self.field_names)
        return df

    def __len__(self):
        return len(self.rows)


def conn_transform(fields, types, names):
    ntypes = len(types)
    for fno in range(ntypes):

        if fields[fno] == '-':
            fields[fno] = None
            continue

        elif fields[fno] == '(empty)':
            fields[fno] = ''
            continue

        elif types[fno] == 'count' or types[fno] == 'port':
            try:
                val = int(fields[fno])
                fields[fno] = val
            except:
                pass

        elif types[fno] == 'interval':
            try:
                val = float(fields[fno])
                fields[fno] = val
            except:
                pass

        elif types[fno] == 'addr':
            try:
                ip_addr = ip.ip_address(fields[fno])
                fields[fno] = int(ip_addr)
            except ValueError:
                # IPv6 address?  TBD...
                fields[fno] = 0

        elif types[fno] == 'time':
            ts = float(fields[fno])
            t = dt.fromtimestamp(ts).isoformat()
            fields[fno] = t

    return

def conn_filter(fields, types, names):
    return fields[6] == 'tcp'

def main(argv):
    con = BroLogFile('20161224/conn.log',
                     row_transform = conn_transform )

    #for n in range(10):
    #    print(con.rows[n])

    df = con.asDataFrame()
    print(df.head(10))
    print(df.describe())

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
