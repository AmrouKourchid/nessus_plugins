#TRUSTED 4db1b5ea913a1fef09f700ed16bec7d6740c54dd68ff3dd8a6b4b80c2ad815717ebb9639627251538cdd8b5e7a1ddf617cd0e38b2aa49f970082abd274c95c2cdadb71549f2cfbc0848c6bc0149bf2c7ded82d85fee0ad0e498a9ff0c3a80ee14302de5d2af17a0a268c4f4a8b1796d69ee08511c68f49b50d0f03ef729f24e5a5b87204c928e304a901763b09af0b14e76d7fabcbf58c0bb3b044a18f23b173f04498b27b63549c85a06aa166544ffb0f7c31f5116b900b4ba9bf6d80ebbc62615b0f50264405427f1de6ed2c8a7e1c3248f25c758c998abb1d50d08c56f2a80b5169f89f03a956c73d1bb235f7e3c1853c5839dc7ebb183ff628a7091d114386143bb446546f42fab729f359e621553a2989fa9202c52ce05839e2c0a182e8d55376c2eeba1784c3484d3df343202955d9e77c811b24bc658f30a865ece255faa9d13faddc1d7219853fa4fd838bf1754eb03cbe6d049a83af29dae00271dbfb240994a954fe7419fca44186aabe4e22e14e99a955277928b336771b7603b027995542f9038670c250a414c857f08ffa1a6b8361e296c0760eaf8d52ac37a18be0b43529bff65cecc110501b2b2decdc21efbdf62c94912179f570c16e42e7903d3137c66c55755ae4230c6a29752562c45634957d8cb1081e171aca4b252048c8bc9b578ee83c9e69b536214374797ff4ebc28fe5fba3a8ea57c358e70cd3
###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# Revision: 0.2
#
# <at:var at:name="NOGPL" />
#
###

include("compat_shared.inc");
include("debug.inc");
include("lists.inc");

namespace sql {
  ##
  # Checks to see if table has been created, defaults to checking the
  # scratchpad DB
  #
  # @anonparam [string] Name of table to check
  # @param [db:handle] The handle to a database to check (optional)
  #
  # @return bool TRUE if table exists, FALSE otherwise or for error
  ##
  function check_table(db)
  {
    var table = _FCT_ANON_ARGS[0];
    if (!table)
    {
      dbg::log(src:FUNCTION_NAME, msg:'No table name sent as anonymous argument.');
      return FALSE;
    }
    if (!validate_table_name(table))
    {
      dbg::log(src:FUNCTION_NAME, msg:'Invalid table name: ' + table);
      return FALSE;
    }
    var query =
      "SELECT name FROM sqlite_master WHERE type='table' AND name=?";
    var tables;
    if (db) tables = db_query(db:db, query:query, table);
    else tables = query_scratchpad(query, table);
    if (tables[0]['name'] != table)
    {
      dbg::log(src:FUNCTION_NAME, msg:'Table "'+table+'" does not exist.');
      return FALSE;
    }
    return TRUE;
  }

  ##
  # Queries the full contents of a table and returns the array,
  # defaults to scratchpad DB
  #
  # @anonparam [string] Name of table to retrieve
  # @param [db:handle] The handle to a database to check (optional)
  #
  # @return [list of arrays] Table contents if successful, or NULL
  #                          if an error is encountered
  ##
  function get_table(db)
  {
    var table = _FCT_ANON_ARGS[0];
    if (!validate_table_name(table))
    {
      dbg::log(src:FUNCTION_NAME, msg:'Invalid table name: ' + table);
      return NULL;
    }
    if (!check_table(db:db, table)) return NULL;
    var query = "SELECT * FROM " + table;
    var ret;
    if (db) ret = db_query(db:db, query:query);
    else ret = query_scratchpad(query);
    if (!ret) dbg::log(src:FUNCTION_NAME, msg:'Query did not return ' +
      'contents for table "'+table+'".');
    return ret;
  }

  ##
  # Queries the full contents of a table and converts contents to text
  # for output / debugging
  #
  # @anonparam [string] Name of table to dump
  # @param [key:string] Name of primary key (optional)
  # @param [db:handle]  The handle to a database to check (optional)
  # @param [column_max_width:int] The maximum width of any column
  #                     Data will be truncated at this width (optional)
  #
  # @return [string] Contents of table, formatted for output, or NULL
  #                  if an error was encountered
  ##
  function dump_table(key, db, column_max_width)
  {
    var table = _FCT_ANON_ARGS[0];
    var contents = get_table(table, db:db);
    if (!contents) return NULL;
    if (max_index(contents) < 1)
    {
      dbg::log(src:FUNCTION_NAME, msg:'Table "'+table+'" is empty.');
    }
    return format_table(table, key:key, contents:contents,
             column_max_width:column_max_width);
  }

  ##
  # Formats the results of a database query into a column formatted
  # string for display.
  #
  # @anonparam [string] Name of query or table to dump
  # @param [key:string] Name of primary key (optional)
  # @param [contents:list of arrays] Result of a database query.
  # @param [column_max_width:int] The maximum width of any column
  #                     Data will be truncated at this width (optional)
  #
  # @return [string] Contents of table, formatted for output, or NULL
  #                  if an error was encountered
  ##
  function format_table(key, contents, column_max_width)
  {
    if (!contents) return NULL;
    var table = _FCT_ANON_ARGS[0];
    if (!validate_table_name(table))
    {
      dbg::log(src:FUNCTION_NAME, msg:'Invalid table name: ' + table);
      return FALSE;
    }
    # Key will be printed first, change it to NULL if it's not a valid
    # column name
    if (key && !contents[0][key]) key = NULL;
    var cols = sort(keys(contents[0]));

    var ret, title = 'Table : ' + table + '\n\n';
    var max, i, record, col, len, val, maxs = {};

    # Get column widths
    for (i=0; i < max_index(cols); i++)
    {
      col = cols[i];
      max = strlen(string(col));
      foreach record (contents)
      {
        len = strlen(serialize(record[col]));
        if (len > max) max = len;
      }
      if (column_max_width && max > column_max_width)
        maxs[col] = column_max_width;
      else maxs[col] = max;
    }

    # If key was passed, rearrange columns list
    if (key)
    {
      var tmp = [];
      tmp[0] = key;
      for (i=0; i < max_index(cols); i++)
      {
        if (cols[i] == key) continue;
        append_element(var:tmp, value:cols[i]);
      }
      cols = tmp;
    }

    # Generate headers
    ret = "|";
    var divider = '\n|';
    for (i=0; i < max_index(cols); i++)
    {
      col = cols[i];
      val = string(col);
      if (strlen(val) > maxs[col]) val = substr(val, 0, maxs[col] - 4) + "...";
      ret += crap(data:" ",length:(maxs[col] - strlen(val))) + val + "|";
      divider += crap(data:"-", length:maxs[col]) + "|";
    }
    ret += divider;

    # Generate output
    var r;
    for (r=0; r < max_index(contents); r++)
    {
      ret += '\n|';
      record = contents[r];
      for (i=0; i < max_index(cols); i++)
      {
        col = cols[i];
        val = serialize(record[col]);
        if (strlen(val) > maxs[col]) val = substr(val, 0, maxs[col] - 4) + "...";
        ret += crap(data:" ",length:(maxs[col] - strlen(val))) + val + "|";
      }
    }
    ret = title + ret + '\n';
    return ret;
  }

  ##
  # Checks a table to see if a value has been inserted:
  # - If it has, the ID of the row is returned
  # - If it hasn't, the value is inserted and the new ID is returned
  #
  # This is assumed to be used for tables of unique values with
  # autoincrementing IDs. In the case of multiple rows with the value,
  # the ID of rows[0] will be returned.
  #
  # @anonparam [string]     Name of table to check
  # @param [db:handle]      The handle to a database to check (optional)
  # @param [id_col:string]  The name of the ID column to return (optional)
  # @param [val_col:string] The name of the value column to check
  # @param [value:any]      The value to expect or insert in val_col
  # @param [no_insert:bool] TRUE if the value should not be inserted
  #                         if it isn't already in the table (optional)
  #
  # @return [int] Positive integer for row ID containing value,
  #               -1 for not found, -2 for error
  ##
  function get_id_for_value(db, id_col, val_col, value, no_insert)
  {
    var table = _FCT_ANON_ARGS[0];
    if (!check_table(db:db, table)) return -2;
    if (!val_col)
    {
      dbg::log(src:FUNCTION_NAME, msg:"No val_col passed for name of values column.");
      return -2;
    }
    if (!value)
    {
      dbg::log(src:FUNCTION_NAME, msg:"No value passed to look for in column '"+val_col+"'.");
      return -2;
    }

    if (!id_col) id_col = 'id';
    var rows, query = "SELECT * FROM " + table + " WHERE " + val_col + "=?";

    if (db) rows = db_query(db:db, query:query, value);
    else rows = query_scratchpad(query, value);

    if (!rows || !rows[0])
    {
      if (no_insert) return -1;
      var ins_query = "INSERT INTO " + table + " (" + val_col + ") VALUES (?)";
      var i;
      if (db)
      {
        db_query(db:db, query:ins_query, value);
        rows = db_query(db:db, query:query, value);
      }
      else
      {
        query_scratchpad(ins_query, value);
        rows = query_scratchpad(query, value);
      }
      if (!rows || !rows[0]) return -1;
    }

    var id = rows[0][id_col];
    if (!id) return -2;
    return id;
  }

  ##
  # Extracts a single column out of a list of arrays
  # returned by db_query as a simple array.
  #
  # @param [res:list of arrays] Result of a database query.
  # @param [col:string] The name of the column to extract.
  #
  # @return On success returns an array (possibly empty) of
  #         the requested column values, or NULL if a
  #         required argument is missing.
  #
  ##
  function list_from_query_res(res, col)
  {
    if (!res || !col)
      return dbg::log(src:FUNCTION_NAME, msg:
        'Both "res" and "col" args are required.');

    local_var row, ret = [];

    foreach row (res)
      ret[max_index(ret)] = row[col];

    return ret;
  }

  ##
  # Checks a database name for conformance to NASL convention.
  #
  # @anonparam [string] Name of table to check
  #
  # @return bool TRUE if table name conforms, FALSE otherwise
  # @remark The SQLITE engine places few restrictions on table names
  #         if they are enclosed in quotes or brackets.  This function
  #         checks for expected NASL usage and allows dotted schema names.
  ##
  function validate_table_name()
  {
    if (_FCT_ANON_ARGS[0] !~ '^[a-zA-Z0-9_.]+$') return FALSE;
    return TRUE;
  }


  ##
  # Wrapper to allow the nessus engine function db_query()
  # to be used with collib::apply even though it uses a
  # named parameter for the query.
  #
  # @param     [db_h:integer] A handle to a database
  # @anonparam [first:array]  An array with a database query
  #                           at index 0 and bound parameters
  #                           for the rest of the elements.
  #
  # @return Returns the result of the database query or NULL
  #         if an error occurs.
  ##
  function db_query_wrapper()
  {
    var all_args = _FCT_ANON_ARGS;
    var db_h = all_args[0];
    var query = all_args[1];

    if (!db_h)
    {
      dbg::log(src:FUNCTION_NAME, msg:"No database handle was provided.");
      return NULL;
    }

    if (!query)
    {
      dbg::log(src:FUNCTION_NAME, msg:"No query was provided.");
      return NULL;
    }

    var args = collib::drop(all_args, n:2);
    if(!args || len(args) == 0)
      return db_query(db:db_h, query:query);

    return db_query(db:db_h, query:query, FCT_ARGS(args));
  }
}
