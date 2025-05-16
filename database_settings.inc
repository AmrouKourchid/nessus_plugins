#TRUSTED 4f1f5f9c21f2aaf650ffca384064681f0da2406358c62f92a020120d448653261cd59fb38a56820fd7485e2703df1a282edef6c14c4b7bfb175ef00ef6874e739caefd36dd544755b5dbe427559ea1942a4e1e82c2bbec53cf7da093cf655219f181f553a0876fb65a050e03b01dc99017bc8c6314b062743344fcba3b2e07fe970f92cd3560c52d6a7ed69dbe03ebd04dec8de17a9ab32747e7ce8aacaea43ef098ddc2b3e3d6666ea6a3316293ead44129aa62282e53be5b1044c00c701f97ab92364d7ccaecba12af3b71441f27e53aaf735541051bb30497d4f1f759ad61b2b0eed8bb97cf92b25da7cf0bd6a1d4e0fd0e7fee4cc0ac50f994a34922954edc0cdd7093fe897902f5eb5fcbf8f62e3af526f777a176e745e375efcff03e1717cd38453cce71dbf16272c7e11a938cf7a3320c5b36fefecb02ef298be0f14bc683248e4f97bfeda88800e68364c2a756ca2aef938f97cdb147e34ace6ee15164d4c3fe1e5bc0903e1d35900fc963c98719274e39c1cd306dd8e2907f95b954065bc0b33fcf32bd7b0d045f4e3c7eb41da129e2de8eaf6206081e9ec7e11bf93274f44882e9c41c9044a22484e8856fbfb90131215df1d619d2b1d76623e2a29e0f90a70c274a47a58fbde81f7657b7a258d3b5135b6014d842cd935d678a4d50f126783671d395ceacfde98b883377ebc504feba8103fb9ece7bf528ef1dd8
#TRUST-RSA-SHA256 2e4f173198fbf05e4160c7215908b0e5fe3936a3698479bdf21a8cf43ab5ce9b13ff5bdcce22403993b79e4739e0403da76c3dc0116b549db365bdb33b36662a50527506bd06e0c5848601b8761e70c1b875b7d1a5a1a65eaa3fa8bcbd3b7484421317a7821acced0cb482a2af1e9054ab8490d6731546d79ad06366413677daf887417084082f0b30bf090e9947d31de76127a04df39cbee38ed1bfcb7968dea13e3c23c78be7805908ad5be49bad1322d9290c7f4f9bf4071abae361ce8cb303f5284d954f53bdc0d10ac1e6a6e91e26dab7a4292c8fe320f005fca7e494da4153308548bc88e5260785242be7cf6365b50bd3cbf2041244efaf6b06b59e4a645bb16c5446de463b7f72d9c092b54b537c41847ba8ab8e006d8eb42589abac951cbc356f0d8ad0647f18a0f4086ac942675a3737c2e89c1449310e08f31c51564f5abd37cd5916eba15b2e3fa551bbb04ce72ab64f8d935a7453b0e20979209143310316beca9206707303b001d20a262d7355bee6ddb3268021a8e0a38c243556c27578cfdd7b71ed4d80f6816de9630b38c2d60e0b776fd22f65fe5de54112b5a6f05f81fc3b4dc89dc77142ac21e4f4a97e879422cd951a5761d0076a0868e0231f52cc858a0bf065de9d83489bf6e4f763b97b59aaf3b290c19af63f1acecb81ee8b0a3daae2a115e8514a26def9cd95f31a38f65bad95cf81c002033a
###
# (C) Tenable, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable, Inc.
#
# @NOGPL@
#
# database_settings.inc
#
# Revision: 1.14
###

include('compat_shared.inc');
include('csv_reader.inc');
include('cyberark.inc');
include('debug.inc');
include("integrations_common.inc");
include("spad_log_func.inc");

namespace database_settings
{
  var positions = {};
  var TAP_MODE = false;

  ##
  # Get the prefix and postfix strings for the preference based off the specified index.
  #
  # @param [index:int] index
  #
  # @return array with 'prefix' and 'postfix'; NULL if an error occurred
  ##
  function get_prefix_and_postfix(index)
  {
    index = int(index);

    var preference = {};

    if (index == 0)
    {
      preference.prefix  = '';
      preference.postfix = ' : ';
    }
    else
    {
      preference.prefix  = 'Additional ';
      preference.postfix = strcat(' (', index, ') : ');
    }

    return preference;
  }

  ##
  # Get KB index string based off the specified index.
  #
  # @param [index:int] The KB index
  #
  # @return string used for the 'Database' KB item
  ##
  function get_kb_index_text(index)
  {
    var kb_index_text;

    kb_index_text = 'Database';

    if (int(index) > 0)
      kb_index_text += '/' + index;

    return kb_index_text;
  }

  ##
  # Iterates over Database settings KB items to create global array with positions
  #
  # @remark positions array example: positions['import']['Oracle']['cyberark'] = [ 0, 2 ]
  #
  # @return NULL
  ##
  function store_positions()
  {
    var index_size, i, kb_index_text, kb_item, kb_value, entry, required_kbs, required_kb;
    var source, database, cred_type;

    index_size = get_kb_item('Database/index_size');

    required_kbs = [ 'source', 'database', 'cred_type' ];

    for (i = 0; i < index_size; i++)
    {
      kb_index_text = get_kb_index_text(index:i);

      entry = {};

      # Get required KB items that will be used as keys in positions array
      foreach required_kb (required_kbs)
      { 
        kb_item = strcat(kb_index_text, '/', required_kb);
        kb_value = get_kb_item(kb_item);

        if (empty_or_null(kb_value))
        { 
          dbg::log(src:FUNCTION_NAME, msg:'Missing required KB item: ' + kb_item);
          continue;
        }

        entry[required_kb] = kb_value;
      }

      # Missing at least one required KB    
      if (len(entry) < len(required_kbs)) continue; 

      # Add positions
      source = entry.source;
      database = entry.database;

      # Standardize credential type
      cred_type = tolower(entry.cred_type);
      if (cred_type =~ '^hashicorp')
        cred_type = 'hashicorp vault';
      else if (cred_type =~ '^cyberark')
        cred_type = 'cyberark';

      if (empty_or_null(positions[database][cred_type][source]))
        positions[database][cred_type][source] = [];

      append_element(var:positions[database][cred_type][source], value:i);
    }

    dbg::log(src:FUNCTION_NAME, msg:'positions array:\n' + obj_rep(positions)); 

    return NULL;
  }


  namespace cred_manager
  {
    ##
    # Retrieve the credentials from the specified credential manager.
    #
    # @param [cred_manager:str] credential manager (CyberArk or Hashicorp)
    # @param [entry_index:int] index of the credential manager entry with configuration
    # @param [import_index:int] (optional) index of the import entry 
    #
    # @remark The credential managers currently supported are CyberArk and Hashicorp.
    #
    # @return array with credentials or NULL if an error occurred
    ##
    function get_credentials(cred_manager, entry_index, import_index)
    {
      var kb_index_text, source, login, cred_manager_id, preference, config, hashicorp_result;

      var creds = {};

      if (!empty_or_null(import_index))
        kb_index_text = get_kb_index_text(index:import_index);
      else
        kb_index_text = get_kb_index_text(index:entry_index);

      source          = get_kb_item(kb_index_text + '/source');
      login           = get_kb_item(kb_index_text + '/login');
      cred_manager_id = get_kb_item(kb_index_text + '/cred_manager_id');

      if (cred_manager =~ 'cyberark' && empty_or_null(login) && empty_or_null(cred_manager_id))
      { 
        dbg::log(src:FUNCTION_NAME, msg:'Neither "login" or "cred_manager_id" Database KB item exists.');
        return NULL;
      }

      # For backwards-compatibility, clear 'login' if source is an 'entry' or 'cred_manager_id' specified
      if (source == 'entry' || !empty_or_null(cred_manager_id))
        login = NULL;

      preference = get_prefix_and_postfix(index:entry_index);   

      if (TAP_MODE)
      {
        creds.password = 'TAP_password';

        if (cred_manager =~ 'Hashicorp')
          creds.login = 'TAP_login';
      }
      else if (cred_manager =~ 'CyberArk')
      {
        creds.password = cark_get_password(
          login     : login,
          object_id : cred_manager_id,
          source    : source,
          prefix    : preference.prefix + 'Database ',
          postfix   : preference.postfix
        );
      }
      else if (cred_manager =~ 'Hashicorp')
      {
        hashicorp_result = hashicorp::get_credential(
          username : login,
          prefix : preference.prefix + 'Database ',
          postfix : preference.postfix,
          secret_override: cred_manager_id
        );
        if (hashicorp_result.success)
        {
          creds.password = hashicorp_result.password;
          creds.login    = hashicorp_result.username;
        }
      }
      else
      {
        dbg::log(src:FUNCTION_NAME, msg:strcat('Credential manager "', cred_manager, '" is not supported.'));
        return NULL;
      }

      if (empty_or_null(creds))
      {
        dbg::log(src:FUNCTION_NAME, msg:'No credentials were retrieved from: ' + cred_manager);
        return NULL;
      }

      return creds;
    }

    ##
    # Set or replace the credentials at the specified index in the Database KB items
    #
    # @param [index:int] index of the KB item for the password
    # @param [password:str] new password
    # @param [login:str] OPTIONAL new login
    #
    # @return true if successful; NULL if an error occurred
    ##
    function set_credentials(index, password, login)
    {
      var required_args, required_arg, kb_index_text;

      required_args = { 'index' : index, 'password' : password };

      foreach required_arg (sort(keys(required_args)))
      {
        if (empty_or_null(required_args[required_arg]))
        {
          dbg::log(src:FUNCTION_NAME, msg:strcat('Required argument "', required_arg, '" is empty or null.'));
          return NULL;
        }
      }

      kb_index_text = get_kb_index_text(index:index);

      replace_kb_item(name:strcat('/tmp/', kb_index_text, '/password'), value:password);
      dbg::log(src:FUNCTION_NAME, msg:'Successfully set password for index: ' + index);

      if (!empty_or_null(login))
      {
        replace_kb_item(name:kb_index_text + '/login', value:login);
        dbg::log(src:FUNCTION_NAME, msg:'Successfully set login for index: ' + index);
      }

      return true;
    }

    ##
    # Disable KB entry by simply adding '/disabled' KB item.
    #
    # @param [idnex:int] index of the credential manager to disable
    #
    # @remark Downstream plugins will need to be updated to check for this KB item.
    #
    # @return true if successful; NULL if an error occurred
    ##
    function disable_entry(index)
    {
      var required_args, required_arg, kb_index_text;

      required_args = { 'index' : index };

      foreach required_arg (sort(keys(required_args)))
      {
        if (empty_or_null(required_args[required_arg]))
        {
          dbg::log(src:FUNCTION_NAME, msg:strcat('Required argument "', required_arg, '" is empty or null.'));
          return NULL;
        }
      }

      kb_index_text = get_kb_index_text(index:index);

      replace_kb_item(name:kb_index_text + '/disabled', value:TRUE);
      dbg::log(src:FUNCTION_NAME, msg:'Disabled credential set at index: ' + index);

      return true;
    }

    ##
    # Retrieve and set credentials from the specified credential manager.
    #
    # @param [database:str] database name (e.g. Oracle)
    # @param [cred_manager:str] credential manager (CyberArk or Hashicorp)
    #
    # @remark sets the Database password KB item
    # @remark If a settings entry and at least one import exists, only the import entries will attempt auth
    #
    # @return true if no issues; NULL otherwise
    ##
    function get_and_set_credentials(database, cred_manager)
    {
      var required_args, required_arg;
      var indexes, source, prefix, postfix, index, kb_index_text, kb_item, cred_manager_id;
      var creds, entry_index, import_index; 

      required_args = { 'database' : database, 'cred_manager' : cred_manager };
      
      foreach required_arg (sort(keys(required_args)))
      { 
        if (empty_or_null(required_args[required_arg]))
        { 
          dbg::log(src:FUNCTION_NAME, msg:strcat('Required argument "', required_arg, '" is empty or null.'));
          return NULL;
        }
      }

      if (cred_manager !~ 'CyberArk|Hashicorp')
      {
        dbg::log(src:FUNCTION_NAME, msg:strcat('"', cred_manager, '" is not supported.'));
        return NULL;
      }

      indexes = {};
      indexes['entry']  = positions[database][cred_manager]['entry'];
      indexes['import'] = positions[database][cred_manager]['import'];

      # At least one entry is required
      if (empty_or_null(indexes['entry']))
      {
        dbg::log(src:FUNCTION_NAME, msg:strcat(
          'No entry was detected for "', database, '" and "', cred_manager, '".'));
        return NULL;
      }

      # Iterate over credential manager entries set in policy
      foreach entry_index (indexes['entry'])
      { 
        # No import entries, use settings entry instead
        if (empty_or_null(indexes['import']))
        {
          creds = get_credentials(
            cred_manager : cred_manager,
            entry_index  : entry_index
          ); 

          if (!empty_or_null(creds))
            set_credentials(index:entry_index, password:creds.password, login:creds.login);

          continue;
        }

        # Import file specified - disable cred manager KB items
        disable_entry(index:entry_index);

        # Iterate over credential manager entries set in imported file
        foreach import_index (indexes['import'])
        {
          creds = get_credentials(
            cred_manager : cred_manager,
            entry_index  : entry_index,
            import_index : import_index
          );

          if (!empty_or_null(creds))
            set_credentials(index:import_index, password:creds.password, login:creds.login);
        }
      }

      return true;
    }

    ##
    # Process credential manager entries and set passwords.
    #
    # @return NULL always
    ##
    function process_entries()
    {
      var source, database, cred_manager;
    
      # Store indexes into global 'positions' array
      #  Example: positions['import']['Oracle']['cyberark']
      store_positions();

      # Set credentials retrieved from credential managers
      foreach database (keys(positions))
        foreach cred_manager (keys(positions[database]))
          get_and_set_credentials(database:database, cred_manager:cred_manager);

      return NULL;
    }
  }

  namespace csv
  {
    var params = {

      'Oracle' : {
        'fields' : [
          'target', 'port', 'db_service_type', 'service',
          'username', 'oracle_cred_type',
          'cred_manager', 'cred_manager_id'
        ],

        'optional_fields' : [ 'cred_manager_id' ],

        'validation' : {
          'target'           : "^[a-zA-Z0-9.:-]+$",
          'port'             : "^[0-9]+$",
          'db_service_type'  : "^(SID|SERVICE_NAME)$",
          'service'          : "^[\w.]+$",
          'username'         : ".+",
          'oracle_cred_type' : "^(SYSDBA|SYSOPER|NORMAL)$",
          'cred_manager'     : "^(CyberArk|Hashicorp)$",
          'cred_manager_id'  : ".*"
        }
      },

      'MySQL' : {
        'fields' : [
          'target', 'port', 'database_name', 'username', 'cred_manager', 'cred_manager_id'
        ],

        'optional_fields' : ['database_name', 'cred_manager_id'],

        'validation' : {
          'target'           : "^[a-zA-Z0-9.:-]+$",
          'port'             : "^[0-9]+$",
          'username'         : ".+",
          'database_name'    : ".+",
          'cred_manager'     : "^(CyberArk|Hashicorp)$",
          'cred_manager_id'  : ".*"
        }
      },

      'DB2' : {
        'fields' : [
          'target', 'port', 'service', 'username', 'cred_manager', 'cred_manager_id'
        ],

        'optional_fields' : ['cred_manager_id'],

        'validation' : {
          'target'           : "^[a-zA-Z0-9.:-]+$",
          'port'             : "^[0-9]+$",
          'username'         : ".+",
          'database_name'    : ".+",
          'cred_manager'     : "^(CyberArk|Hashicorp)$",
          'cred_manager_id'  : ".*"
        }
      },

      'SQL Server' : {
        'fields' : [
          'target', 'port', 'instance_name', 'username', 'auth_type', 'cred_manager', 'cred_manager_id'
        ],

        'optional_fields' : ['instance_name', 'cred_manager_id'],

        'validation' : {
          'target'           : "^[a-zA-Z0-9.:-]+$",
          'port'             : "^[0-9]+$",
          'username'         : ".+",
          'instance_name'    : ".+",
          'auth_type'        : "^(SQL|Windows)$",
          'cred_manager'     : "^(CyberArk|Hashicorp)$",
          'cred_manager_id'  : ".*"
        }
      }

    };

    ##
    # Parses CSV with database parameters
    #
    # @param [csv:string]   CSV content to parse
    # @param [type:string]  database type to use for parameters
    #
    # @return parsed CSV list of arrays
    #         NULL if an error occurred
    ##
    function parse(csv, type)
    {
      var csv_params, csv_reader, parsed_csv;

      if (empty_or_null(csv))
      {
        dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:"Missing required 'csv' parameter.");
        return NULL;
      }

      if (empty_or_null(type))
      {
        dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:"The parameter 'type' is missing.");
        return NULL;
      }

      csv_params = params[type];

      if (empty_or_null(csv_params))
      {
        dbg::detailed_log(
          lvl: 1,
          src: FUNCTION_NAME,
          msg: "CSV import: An invalid database type was specified.",
          msg_details: {
            "": {"lvl": 1, "value": type}});
        return NULL;
      }

      csv_reader = new('csv_reader', csv);
      csv_reader.parse_csv(
        fields          : csv_params.fields,
        optional_fields : csv_params.optional_fields,
        validation      : csv_params.validation
      );

      parsed_csv = csv_reader.data_records;
      delete(csv_reader);

      return parsed_csv;
    }
  }

}
