import logging
import sqlite3
from io import StringIO
import pandas as pd
from sqlalchemy import create_engine, select

def initialize_database(filename, table_name, column_names, column_types):
    incrementer = 0
    columns = ""
    while incrementer < len(column_names):
        columns += column_names[incrementer] + " " + column_types[incrementer]
        incrementer += 1        
        if incrementer != len(column_names):
            columns += ", "

    con = sqlite3.connect(filename)
    cur = con.cursor()
    sql = f"CREATE TABLE IF NOT EXISTS {table_name}({columns})"
    logging.debug(sql)
    logging.info(f"Creating table {table_name} in {filename} with columns {columns}")

    cur.execute(sql)
    con.commit()
    con.close()

def select(filename, columns, tables, conditionals=None):
    con = sqlite3.connect(filename)
    df = pd.read_sql_query(f'''SELECT {columns} from {tables}''', con)
    logging.debug(df.head())
    con.close()
    return df

def insert(filename, table_name, column_names, values):
    if isinstance(column_names, list):
        incrementer = 0
        field_names = ""
        value_placeholders
        while incrementer < len(column_names):
            field_names += column_names[incrementer]
            value_placeholders += "?"
            incrementer += 1   
            if incrementer != len(column_names):
                field_names += ", "
                value_placeholders += ", "
    else:
        columns = column_names
        values = [values]
        value_placeholders = "?"

    con = sqlite3.connect(filename)
    cur = con.cursor()

    #create table if it doesn't exist
    sql = f"CREATE TABLE IF NOT EXISTS {table_name} ({columns})"
    logging.debug(sql)
    logging.debug(f"Creating table {table_name} in {filename} with columns {columns}")
    try:
        cur.execute(sql)
    except Exception as e: 
        logging.error(f"Issue with SQL statement '{sql}': {e}")
    con.commit()

    sql = f"INSERT INTO {table_name} ({columns}) VALUES ({value_placeholders})"
    try:
        cur.execute(sql, tuple(values))
    except Exception as e: 
        logging.error(f"Issue with SQL statement '{sql}': {e}")
        if "no column named" in e:
            add_column(filename, table_name, columns)
    con.commit()

def insert_dict(filename, dict, table_name):
    df = pd.DataFrame(dict)
    engine = create_engine(f'sqlite:///{filename}')
    logging.info(f"Starting insert of dictionary into '{filename}'")

    try:
        df.to_sql(table_name, con=engine, if_exists='append')

    except Exception as e:
        logging.error(f"Issue while attempting to insert dictionary into database: {e}")
        if "no column named" in str(e):
            pass
            #add_column(filename, table_name, column_name)
            #df.to_sql(table_name, con=engine, if_exists='append')
    logging.info(f"Completed insert of dictionary into '{filename}'")

def insert_list(filename, dict, table_name):
    df = pd.DataFrame(dict)
    engine = create_engine(f'sqlite:///{filename}')
    logging.info(f"Starting insert of dictionary into '{filename}'")

    try:
        df.to_sql(table_name, con=engine, if_exists='append')

    except Exception as e:
        logging.error(f"Issue while attempting to insert dictionary into database: {e}")
        if "no column named" in str(e):
            pass
            #add_column(filename, table_name, column_name)
            #df.to_sql(table_name, con=engine, if_exists='append')
    logging.info(f"Completed insert of dictionary into '{filename}'")

def insert_df(filename, df, table_name):
    engine = create_engine(f'sqlite:///{filename}')
    logging.info(f"Starting insert of dictionary into '{filename}'")

    try:
        df.to_sql(table_name, con=engine, if_exists='append', index=False)

    except Exception as e:
        logging.error(f"Issue while attempting to insert dictionary into database: {e}")
        if "no column named" in str(e):
            pass
    logging.info(f"Completed insert of dictionary into '{filename}'")


def update(filename, table_name, column_name, value):

    #sql = '''UPDATE commands SET azurehp2=? WHERE command=? and quantity=?'''
    #sql = f'''UPDATE malware SET {honeypot[incrementer]}_quantity=?, {honeypot[incrementer]}=? WHERE hash=?'''
    #
    pass

#def select(filename, table_names, column_names, value_comparisons=None):
#    incrementer = 0
#    columns = ""
#    while incrementer < len(column_names):
#        columns += column_names[incrementer] + " " + column_names[incrementer]
#        incrementer += 1        
#        if incrementer != len(column_names):
#            columns += ", "
#
#    incrementer = 0
#    tables = ""
#    while incrementer < len(table_names):
#        tables += table_names[incrementer] + " " + table_names[incrementer]
#        incrementer += 1        
#        if incrementer != len(table_names):
#            table += ", "

#    con = sqlite3.connect(filename)
#    cur = con.cursor()
#    sql = f"SELECT {columns} from {tables}"
#    if value_comparisons is not None:
#        sql += "where {value_comparisons}"
#    cur.execute(sql)
#    con.commit()
#    return cur.fetchall() # return rows of data

def add_column(filename, table_name, column_name, column_type):
    con = sqlite3.connect(filename)
    cur = con.cursor()
    sql = f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"
    cur.execute(sql)
    con.commit()

def value_exists(filename, table_names, column_names, value_comparisons):
    incrementer = 0
    columns = ""
    while incrementer < len(column_names):
        columns += column_names[incrementer] + " " + column_names[incrementer]
        incrementer += 1        
        if incrementer != len(column_names):
            columns += ", "

    incrementer = 0
    tables = ""
    while incrementer < len(table_names):
        tables += table_names[incrementer] + " " + table_names[incrementer]
        incrementer += 1        
        if incrementer != len(table_names):
            table += ", "

    con = sqlite3.connect(filename)
    cur = con.cursor()
    sql = f"SELECT {columns} from {tables} where {value_comparisons}"
    try:
        cur.execute(sql)
        rows = cur.fetchall()
    except Exception as e:
        logging.error(f"Issue running query '{sql}': {e}")
        return False
    
    if len(rows) > 0:
        return True
    else:
        return False

def add_table(filename, table_name, columns):
    con = sqlite3.connect(filename)
    cur = con.cursor()
    sql = f"CREATE TABLE IF NOT EXISTS {table_name}({columns})"
    logging.debug(sql)
    logging.info(f"Creating table {table_name} in {filename} with columns {columns}")
    cur.execute(sql)
    con.commit()

def drop_table(filename, table_name):
    con = sqlite3.connect(filename)
    cur = con.cursor()
    sql = f"DROP TABLE {table_name}"
    cur.execute(sql)
    con.commit()