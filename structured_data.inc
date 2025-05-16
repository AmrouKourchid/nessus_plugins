#TRUSTED 5052ccf8e8f1a381ebf3c7e36f368d77be4e206012de4093446c169372cf4b2535d42c2298f60c18ea87c1c261e3796094979facd60fd7417ce1cf2f262b47cc18a8914ee97778de92889fc4d2ae0b660f2590a5e85259b552dc30aeb3cde410b3744caa8d4ad3eb9c888114ce56d9fd744de6e18d286cc059546bfee3fe1458aaa7a8a6db491d98a2eae9656bd1825f0e9acbc9ab65721ab0a87fe57c6083cdbd4b2e6fe39ae6702e221affd7c1a79a88569e5fa9e87c9f193844de0a8ecc313bc3e2ca18fc37817473b27ce9381ff3399f4e4f77368eaa51258806f7292a7f18fa205b56b89dea5bf40a3d3682697cf8b05791ce045b041ae0db68565337d2db8747b778aab733bbec265ca0c2f2154aeb79c054474eb69a60361499d31507abdb67aefed0c7dc6c1c2b0e9e66d0b0a1880e0ba5ccb199dabd35783b8221c34327a4c14acd11b98fb6361a5d173b2d094f4f35976f7cfc177d3720e04ee03ce0a7c0bbad0067c06f0d2e17eee062c312416fc700a9784cacb6b546e7c5436fe8999074e30f9508dbe6007a7f85feaba068e0e93de0690beb02622c05c28612642ba403cbb3c2aeebb84700ceebd418d6dfabef62d34787ea732725b34ef4a15c08552d8104bcb668b8d3a9f870acdb640686389064879fd99915be7190d75c7aeaa86c02d6f329d15efbb0979adbfafac63d20c3a0e77cf8ce7831ad5b979b
#TRUST-RSA-SHA256 371e2b63e102e47362e610421a6634699f729b8e9d306f53805584110efa1ca0a1c0af56e05bf85ab923e9cf45fb3cb344228be5dc35fd3c309102c17756bd4dd69c018227f05b50eaa1bf9a37cabd256de8205a7d11db187c3e56a28819e2a21e9edce3d7fc040bb95a48f9ee28f19a4c2f67edd33254928acb24c4b3c466e5619aafd4ff9ce26b1cb539b98f7de7a39a64cd555b4389d739be4c1febb547dd4b3f744fe3bf6c7f09e17a5e83761f845417531a4fb6eec00f8a29694b640999a2b951e87818a202c5e1ed5654b521788ead8379539eebad3148dfd3916a1d0ed71b37082c41f9f14a6c941bd92df68a72c40cd38a6bb6236e7e9b2bd77ee899bafae3bdff79c49c01e2b4239e50ead0f2d0b7d146b46ce2fa1e5cfc7a3201d8871a8f0857be4feea0acf358541829befe85bacbd3d60618ab3ccd3aa3dfb5faa763af1405078f6d76911ca6219b8b887338b667b39f71434f52202b984e1fbf84c31be994142f9bda08fc58c60b0960edcb8413de0bdf98690f671763690e245649fcb3aa845e6c5b110cbbb1d4b5865220855de8fb7315fd1da1ea02fed4dea1bb0acfd313f856aebb2cfeb6850dad289968002153fdc83e405016c4448c5837f84781ad9d6e52e4c5e51fe5e88b40c3c56fa90b8df6209ba23594ea83b7777c85848b4f2d384944a2c212de45dd3436679738c5bed6fe8e3078bf999b6963
#
# (C) Tenable Network Security, Inc.
#
# Revision: 1.9

include("compat_shared.inc");
include("spad_log_func.inc");
include("debug.inc");
#pragma static(include)
include("structured_data_base.static");
include("structured_data_system_asset_info.static");
include("structured_data_system_network_config.static");
include('structured_data_installed_sw.static');
#pragma static(include:false)

object structured_data_asset_identifier : structured_data_base {
  ##
  # Constructs an asset identifier object for structured data reporting.
  ##
  function structured_data_asset_identifier() : super({
    identifier: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          type: {
            type: 'string',
          },
          identifier_source: {
            type: 'string',
          },
          identifier_value: {
            type: 'string',
          }
        }
      }
    }
  }, 'asset-identifier'){}
}


object structured_data_authentication_status_information : structured_data_base {

  var FAILED, SUCCESS;

  ##
  # Constructs an authentication status object for structured data reporting.
  ##
  function structured_data_authentication_status_information() : super({
    auth_info: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          name: {
            type: 'string',
          },
          attempts: {
            type: 'object',
            properties: {
              success: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    user_id: {
                      type: 'string',
                    },
                    method: {
                      type: 'string',
                    }
                  }
                }
              }
            }
          },
          failed_attempts: {
            type: 'integer',
          }
        }
      }
    }
  }, 'authentication-status-information'){

    # initiailize the structured object base objects
    this.set("auth_info", []);

    this.SUCCESS = 1;
    this.FAILED = 0;
  }

  ##
  # Add an entry to structured data authentication status information
  #
  # @param [auth_type:string] The type of auth, SSH, Windows, SNMP
  # @param [user_id:string] The user identifier used to log in
  # @param [method:string] The method used for logging in
  # @param [status:int] this.SUCCESS or this.FAILED values based on auth status
  #
  # @return [NULL|boolean] NULL if a parameter is NULL, true if fully ran
  ##
  public function insert_auth_status(auth_type, user_id, method, status)
  {
    dbg::detailed_log(lvl:1, msg:"Insert structured data authentication status information.");

    # required parameters
    if (isnull(auth_type) || isnull(user_id) || isnull(method) || isnull(status))
    {
      dbg::detailed_log(lvl:1, msg:"insert_auth_status had a missing parameter.");
      return NULL;
    }

    # all auth types are converted to lowercase to allow for consistent identification
    auth_type = tolower(auth_type);

    # if there are no entries, and no matching entries then insert a new auth type
    if (len(this.get('auth_info')) < 1 || !does_auth_type_exist(auth_type:auth_type))
    {
      this.set_auth_info_instance(auth_type:auth_type);
    }

    this.add_to_auth_attempts(auth_type:auth_type, user_id:user_id, method:method, status:status);

    return true;
  }

  ##
  # Insert the auth restults into the attempts array
  #
  # @param [auth_type:string] The type of auth, SSH, Windows, SNMP
  # @param [user_id:string] The user identifier used to log in
  # @param [method:string] The method used for logging in
  # @param [status:int] this.SUCCESS or this.FAILED values based on auth status
  ##
  function add_to_auth_attempts(auth_type, user_id, method, status)
  {
    dbg::detailed_log(lvl:1, msg:"Adding Auth Attempt Entry");
    var auth_info = get_auth_info();
    var auth_type_index = get_auth_type_index(auth_type:auth_type);

    if (status == this.SUCCESS)
    {
      append_element(var:auth_info[auth_type_index].attempts.success, value:{"user_id":user_id, "method":method});
      dbg::detailed_log(lvl:2, msg:"Success Auth Added");
    }
    else if (status == this.FAILED)
    {
      # Failed auths are not currently logged, this is a potential future addition
      # Do not uncomment this until the schema has been updated to support failed auth logging
      #append_element(var:auth_info[auth_type_index].attempts.failed, value:{"user_id":user_id, "method":method});
      auth_info[auth_type_index].failed_attempts++;
      dbg::detailed_log(lvl:2, msg:"Failed Auth Added");
    }

    set_auth_info(auth_info:auth_info);
  }

  ##
  # Initialize a new auth type that did not exist in the array.
  #
  # @param [auth_type:string] The auth type name, example: ssh, smb
  ##
  function set_auth_info_instance(auth_type)
  {
    dbg::detailed_log(lvl:1, msg:"New auth_type : " + auth_type);
    this.append('auth_info', {"name": auth_type, "attempts":{"success": []},"failed_attempts": 0});
  }

  ##
  # Gets the root auth_info data structure and returns it for changes
  ##
  function get_auth_info()
  {
    return this.get('auth_info');
  }

  ##
  # Sets the root auth_info data structure to the data structure passed in
  #
  # @param [auth_info:associative array] the auth_info structured data to set
  ##
  function set_auth_info(auth_info)
  {
    this.set('auth_info', auth_info);
  }

  ##
  # Searches for an auth type to see if it exists in the structure.
  #
  # @param [auth_type:string] The auth type to search for, example : ssh, smb
  #
  # @return [boolean] bool results, true if found, false if not found
  ##
  function does_auth_type_exist(auth_type)
  {
    var auth_type_index = get_auth_type_index(auth_type:auth_type);
    if (!isnull(auth_type_index)) return true;
    else return false;
  }

  ##
  # Locates the index in the array where an auth type is stored
  #
  # @param [auth_type:string] The auth type to search for, example : ssh, smb
  #
  # @return [int|NULL] int index into the array if found, NULL if not found
  ##
  function get_auth_type_index(auth_type)
  {
    var auth_info = get_auth_info();

    dbg::detailed_log(lvl:1, msg:'Get auth type index');
    for (var i = 0; i<len(auth_info); i++)
    {
      dbg::detailed_log(lvl:2, msg:'Compare auth type ' + auth_type + ':' + auth_info[i].name);
      if (auth_type == auth_info[i].name)
      {
        dbg::detailed_log(lvl:3, msg:auth_type + " found!");
        return i;
      }
    }
    dbg::detailed_log(lvl:3, msg:auth_type + " not found!");

    return NULL;
  }
}

object structured_data_package_manager_packages : structured_data_base {
  ##
  # Constructs a packages object for structured data reporting.
  ##
  function structured_data_package_manager_packages() : super({
    packages: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          pkg_name: {
            type: 'string',
          },
          vendor: {
            type: 'string',
          },
          version: {
            type: 'string',
          },
          target_sw: {
            type: 'string',
          },
          target_hw: {
            type: 'string',
          },
          install_date: {
            type: 'string',
          },
          path: {
            type: 'string',
          },
          managed_by: {
            type: 'string',
          }
        }
      }
    }
  }, 'package-manager-packages'){}
}

object structured_data_vuln_reporting : structured_data_base
{
  ##
  # Constructs a vulnerability object for structured data reporting.
  #
  # @anonparam [first:string] Port
  # @anonparam [second:string] Protocol
  ##
  function structured_data_vuln_reporting() : super(
  {
    vulnerability: {
      type: "array",
      items: {
        type: "object",
        properties: {
          fix_available: {
            type: "boolean"
          },
          fixes: {
            type: "array",
            items: {
              type: "object",
              properties: {
                fix_type: {
                  type: "string"
                },
                value: {
                  type: "string"
                },
                fix_display: {
                  type: "string"
                }
              },
              required: [
                "fix_type",
                "value"
              ]
            }
          },
          path: {
            type: "string"
          },
          all_vulnerabilities: {
            type: "boolean",
            default: true
          },
          vulnerabilities: {
            type: "array",
            items: []
          },
          version: {
            type: "string"
          },
          package: {
            type: "string"
          },
          identifier: {
            type: "string"
          }
        },
        required: [
          "identifier"
        ]
      }
    }
  },
  'vulnerability-finding',
   string(_FCT_ANON_ARGS[0]),
   _FCT_ANON_ARGS[1]){}

  ##
  # Overrides the base class implementation for unit testing.
  #
  # @return [boolean] TRUE on success, FALSE otherwise.
  ##
  public function report_internal()
  {
    if(empty_or_null(get_kb_item("TAP/structured_data_testing")))
      return super.report_internal();

    var tag = strcat(this.tag, '::', this.port, ':', this.protocol);

    replace_kb_item(name:"TAP/structured_data/tag", value:tag);
    replace_kb_item(name:"TAP/structured_data/port", value:this.port);
    replace_kb_item(name:"TAP/structured_data/protocol", value:this.protocol);
    replace_kb_item(name:"TAP/structured_data/tag_value", value:this.json_serialize());

    return TRUE;
  }
}
