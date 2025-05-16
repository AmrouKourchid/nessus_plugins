#TRUSTED 987025ba1634c46393432ceec4bddeba62a3f5c1e26f5bcb0f0b10a40efa3499f9893af43512f00e6e5ef21a497ba9759ccfe300c969f633ab1e6b00708c59cf603d3ab10f102d89b8948eaf751b43537687e5bd4980ccd78f9c9c56027f000e03ddd3e92905098038049407726b58869012b2f34b6162f319eda01a546ee78410c7917485d11f5ef402f74fd3c3abbc1c172a7e4faf17e6d80ace75e844a3717a88553f6113d188fb89d9d2230c0b42543f7ffa1d6b80b26bfde9fac22a3f96b18cefa6a7400a248d844c51e9bc4443620de5514f66a35f2d11d884e3b790f7fd84e5cb4057e5b5c01158f916c9c5400d24788ac6df8e2b0202c657c54b9d324164e3912c292cad04e12c04e747383860335ca228b01f14d21ad821105d6868b3e09293773b49ee0c1f6e914f8b162fa3495250143150ca476f76bd7c7f486bc7876b0eb22ce36318d8ccf74899d808d8027c143981adeed085d71db5073468762a9c938484b75af5c2ebf909cbef7187516f257632622cdecbd8e41282281cf7e3a7332d2abfe5c6f16c99c994314921c8e09da670000f68877fc1d6155236fae2e2475656ec63dc784a2f8fed8606b0543228947bdeb62bc4f63ee8501f54f19efa65256aad61e90e3af05a4749f1650fbf6fe6b8879ccd3b9e8e9d433c0d5614440d34a01cd996525e13460b5c02665601021cc57f62bb21f21d206bd2c0
#TRUST-RSA-SHA256 7c720552f6ef0d014aaa047702a968d6410fb0458c92a92a5ed335c3d022f168aa19f753c418831dc24ca320012db273dcefcf96e10192cd16ae56fbfc808a8fa72c2b9e784375245002f4ef62edc56fa2a19a990c97beb23acf019f2c3085e56493ce1e69488d8b4431a34b2072cd1fe1e9508ca07201c64c2ab9a44c09d92229d0a821230be3d2996bdec9ec32756c33d80d20f7acc0d091b89c9f249dd52100440f57e1195bd97696f20d7851984dcf1f67ffae66909559af94b00a360a4f87e50659275f100b83118c9c4662ebe2b8691a4acad8b2feaf3043e762e1c483dbfa01a6ba6d08b5194da634b8735125c43ced148ebe242269386e7221ab00ca0ebc49b043daa54db259d20a6e8160590d7bfbf01235c1a5d89b4b1c5c1a47b92e6c8df5ae1dbc0a31907522405358499049637b44cb4068e657620c4008581788c9278fc9517ef2d6c7e977d6ce22827ed708a569e9c88998acea545f724f577fc2d226aae267b7ea62574e1b395d7673ca8b02dd49a0c9d1f09c083b1487b694e11ce56e3f7ff45452e8826dee5aee285a5b55aab70128f7c1eefc83e79bec3f269c35040ffa3a75649ea90317d4ce52a5c5925ba2b8f23335bf67fa109ab9f96eae0ba77d718f46213b146b61c9c0967e2c73831f2988036a4c657de6bd665abda4c3ad0a08413278246b4c62aa2d65c73fc76a3d5641026cfc0c84bae373
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# @PREFERENCES@

include('deprecated_nasl_level.inc');
include("compat.inc");

if(description)
{

  script_id(33815);
  script_version("1.78");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/13");

  script_name(english:"Database settings");
  script_summary(english:"Set database preferences to perform security checks.");

  script_set_attribute(attribute:"synopsis", value:"Database settings." );
  script_set_attribute(attribute:"description", value:
"This plugin just sets global variables (SID, SERVICE_NAME, etc.), and
does not perform any security checks.");
  script_set_attribute(attribute:"solution", value:"n/a" );
  script_set_attribute(attribute:"risk_factor", value:"None" );
  script_set_attribute(attribute:"plugin_publication_date", value: "2009/02/03");
  script_set_attribute(attribute:"plugin_type", value:"settings");
  script_end_attributes();

  script_family(english:"Settings");

  script_dependencies("datapower_settings.nasl", "pam_database_auto_collect.nbin");

  script_copyright(english:"This script is Copyright (C) 2008-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_category(ACT_SETTINGS);

  var preference_count;
  preference_count = 5;
  if (NASL_LEVEL < 6000)
    preference_count = 1;

  var i;
  var prefix, index_text;
  var legacy_compat;
  for (i = 0; i < preference_count; i++)
  {
    prefix = "";
    index_text = "";
    legacy_compat = "";
    if (i > 0)
    {
      prefix = "Additional ";
      index_text = "(" + i + ") ";
      legacy_compat = " ";
    }
    script_add_preference(name:prefix+"DB Type "+index_text+": ", type:"radio", value:"Oracle;SQL Server;MySQL;DB2;Informix/DRDA;PostgreSQL;Sybase ASE");
    script_add_preference(name:prefix+"Database service type "+index_text+": ", type:"radio", value:"SID;SERVICE_NAME");
    script_add_preference(name:prefix+"Database SID "+index_text+": ", type:"entry", value:"");
    script_add_preference(name:prefix+"Database port to use "+index_text+": ", type:"entry", value:"");
    script_add_preference(name:prefix+"Login "+index_text+": ", type:"entry", value:"");
    script_add_preference(name:prefix+"Password "+index_text+": ", type:"password", value:"");
    script_add_preference(name:prefix+"Oracle auth type"+legacy_compat+index_text+": ", type:"radio", value:"NORMAL;SYSOPER;SYSDBA");
    script_add_preference(name:prefix+"SQL Server auth type"+legacy_compat+index_text+": ", type:"radio", value:"Windows;SQL");
    script_add_preference(name:prefix+"Sybase ASE auth type"+legacy_compat+index_text+": ", type:"radio", value:"RSA;Plain Text");
  }

  exit(0);
}

include("audit.inc");
include("csv_reader.inc");
include("database_settings.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("ssl_funcs.inc");
include("cyberark.inc");
include("cyberarkrest.inc");
include("lieberman.inc");
include("hashicorp.inc");
include("resolv_func.inc");
include("spad_log_func.inc");
include("pkcs12_func.inc");
include("wallix.inc");
include("senhasegura.inc");
include("qianxin.inc");
include("arcon.inc");
include("beyondtrust.inc");
include("delinea.inc");
include("debug.inc");

##
# This function reads the contents from an Oracle wallet,
# parses the wallet using the supplied password.  Then it
# extracts the relevant certificates and private key from the
# wallet. These are then saved to files that Nessus can use
# for TLS negotiation.  The new file names are returned to
# the caller.
#
# @param <wallet:string>   A file containing an Oracle wallet.
# @param <password:string> A password for decrypting the wallet.
#
# @return On success returns a list of file names in which
#         certificates and a private key are stored for use
#         in Nessus engine calls for TLS negotiation.  The
#         returned list is in the following order:
#         [private key, client cert, ca cert]
##
function get_creds_from_wallet(wallet, password)
{
  var pemPrivateKey, pemClientCertificate, pemCACertificate, creds;

  if(isnull(file_stat(wallet)))
  {
    spad_log(message:FUNCTION_NAME + "(): Oracle wallet file not found.");
    return NULL;
  }

  var walletContents = fread(wallet);
  if(isnull(walletContents))
  {
    spad_log(message:FUNCTION_NAME + "(): Could not read wallet file.");
    return NULL;
  }

  var decryptedWallet = parse_pkcs12(container:walletContents, password:password);
  if(isnull(decryptedWallet) ||
     isnull(decryptedWallet["auth_safe"]) ||
     isnull(decryptedWallet["auth_safe"][0]["content_data"]) ||
     isnull(decryptedWallet["auth_safe"][0]["content_data"]["data"]))
  {
    spad_log(message:FUNCTION_NAME + "(): Error decoding wallet.  Result:" + '\n' + serialize(decryptedWallet) + '\n');
    return NULL;
  }

  var walletData = decryptedWallet["auth_safe"][0]["content_data"]["data"];
  var privateKeys = get_private_keys_from_pkcs12_data(pkcs12Data:walletData);
  if(isnull(privateKeys) || len(privateKeys) < 1)
  {
    spad_log(message:FUNCTION_NAME + "(): Wallet contains no private keys.");
    return NULL;
  }

  var clientCertData, caCertData;
  foreach var pk(privateKeys)
  {
    clientCertData = get_related_client_cert(pkcs12Data:walletData, privateKey:pk);
    if(isnull(clientCertData))
      continue;

    caCertData = get_related_chain_of_trust(pkcs12Data:walletData, clientCert:clientCertData);
    if(!isnull(clientCertData) && !isnull(caCertData) && !isnull(pk['bag']) &&
       !isnull(pk['bag']['private_key']) && !isnull(clientCertData['certificate']))
    {
      pemPrivateKey = pk['bag']['private_key'];
      pemClientCertificate = clientCertData['certificate'];
      pemCACertificate = caCertData;
      break;
    }
  }

  if(isnull(pemPrivateKey) || isnull(pemClientCertificate) || isnull(pemCACertificate))
    return NULL;

  var pkFileName = wallet + "-1";
  var fd = file_open(name:pkFileName, mode:"w+");
  if(isnull(fd))
    return NULL;
  file_write(fp:fd, data:pemPrivateKey);
  file_close(fd);

  var cCertFileName = wallet + "-2";
  fd = file_open(name:cCertFileName, mode:"w+");
  if(isnull(fd))
    return NULL;
  file_write(fp:fd, data:pemClientCertificate);
  file_close(fd);

  var caCertFileName = wallet + "-3";
  fd = file_open(name:caCertFileName, mode:"w+");
  if(isnull(fd))
    return NULL;
  file_write(fp:fd, data:pemCACertificate);
  file_close(fd);

  return[pkFileName, cCertFileName, caCertFileName];
}


function store_instance_in_kb(index, service_type, service, port)
{
  local_var index_text;
  index_text = "";
  if (index > 0)
  {
    index_text = "/" + index;
  }

  # default to SID
  if (!strlen(service_type) || service_type == "SID;SERVICE_NAME")
    service_type = "SID";
  if (strlen(service))
    set_kb_item(name:"Database" + index_text + "/"+service_type, value:service);

  if (!isnull(port) && int(port) > 0)
  {
    set_kb_item(name:"Database" + index_text + "/Port", value:port);
  }
}

function store_credential_set_in_kb(index, source, db_type_name, db_type, cred_type, username, password, sspi,
          atype, sybase_ase_cred_type, client_cert, client_cert_ca, client_cert_pk, client_cert_pk_passphrase,
          cred_manager_id, mtls_wallet, mtls_wallet_pass, db_port)
{
  # In case the credentials happen to be all numbers and came in with the wrong type
  username = string(username);
  password = string(password);

  local_var index_text;
  index_text = "";
  if (index > 0)
  {
    index_text = "/" + index;
  }

  if (!empty_or_null(source))
    set_kb_item(name:strcat('Database', index_text, '/source'), value: source);

  if (!empty_or_null(db_type_name))
    set_kb_item(name:strcat('Database', index_text, '/database'), value: db_type_name);

  if (!isnull(db_type))
    set_kb_item(name: "Database" + index_text + "/type", value: db_type);

  if (!empty_or_null(cred_type))
    set_kb_item(name:strcat('Database', index_text, '/cred_type'), value: cred_type);

  if (strlen(username))
    set_kb_item(name: "Database" + index_text + "/login", value: username);

  if (strlen(password))
    set_kb_item(name: "/tmp/Database" + index_text + "/password", value: password);

  if (db_type == 1)
    set_kb_item(name: "Database" + index_text + "/sspi", value: sspi);

  if (atype)
    set_kb_item(name: "Database" + index_text + "/oracle_atype", value: atype);

  if (sybase_ase_cred_type)
    set_kb_item(name: "Database" + index_text + "/sybase_cred_type", value: sybase_ase_cred_type);

  if(!isnull(mtls_wallet))
  {
    var wallet_contents = get_creds_from_wallet(wallet:mtls_wallet, password:mtls_wallet_pass);
    if(!isnull(wallet_contents) && len(wallet_contents) == 3)
    {
      client_cert_pk = wallet_contents[0];
      client_cert = wallet_contents[1];
      client_cert_ca = wallet_contents[2];
      client_cert_pk_passphrase = NULL;

      spad_log(message:"mTLS credentials successfully supplied by wallet.");
    }
    else
    {
      spad_log(message:FUNCTION_NAME + "(): Failed to extract certs from Oracle wallet.");
    }
  }

  if (strlen(client_cert))
    set_kb_item(name: "Database" + index_text + "/client_cert", value: client_cert);

  if (strlen(client_cert_ca))
    set_kb_item(name: "Database" + index_text + "/CA", value: client_cert_ca);

  if (strlen(client_cert_pk))
    set_kb_item(name: "/tmp/Database" + index_text + "/client_key", value: client_cert_pk);

  if (strlen(client_cert_pk_passphrase))
    set_kb_item(name: "/tmp/Database" + index_text + "/client_key_pass", value: client_cert_pk_passphrase);

  if (!empty_or_null(cred_manager_id))
    set_kb_item(name:strcat('Database', index_text, '/cred_manager_id'), value: cred_manager_id);

  #Set KB to record non-standard port assignments recorded in credential
  if((!isnull(db_port) &&
      ((db_type_name == "Oracle" && db_port != 1521) ||
       (db_type_name == "SQL Server" && db_port != 1433) ||
       (db_type_name == "MySQL" && db_port != 3306) ||
       (db_type_name == "DB2" && db_port != 50000) ||
       (db_type_name == "Informix" && db_port != 9088 && db_port != 1526) ||
       (db_type_name == "PostgreSQL" && db_port != 5432) ||
       (db_type_name == "Sybase ASE" && db_port != 5000) ||
       (db_type_name == "Cassandra" && db_port != 9042) ||
       (db_type_name == "MongoDB" && db_port != 27017))))
  {
    replace_kb_item(name:"Database/nonstandard_db_port", value:1);
  }
}

##
#
##
function decode_db_type()
{
  local_var type;
  local_var value;
  local_var opts;
  type  = _FCT_ANON_ARGS[0];
  value = NULL;

  # Set type to default
  if ( ";" >< type )
  {
    opts = split(type,sep:";",keep:FALSE);
    type = opts[0];
  }

  if ("Oracle" >< type)
    value = 0;
  else if ("SQL Server" >< type)
    value = 1;
  else if ("MySQL" >< type)
    value = 2;
  else if ("DB2" >< type)
    value = 3;
  else if ("Informix" >< type)
    value = 4;
  else if ("PostgreSQL" >< type)
    value = 5;
  else if ("Sybase ASE" >< type)
    value = 6;
  else if ("Cassandra" >< type)
    value = 7;
  else if ("MongoDB" >< type)
    value = 8;

  return value;
}

##
# The Raw cert uploads need to be processed. ref: global_settings.nasl
#
# @param [filename:string] Name of the upload file to process.
##
function read_and_write_file_cred(filename)
{
  var b = NULL;

  if (file_stat(filename))
  {
   b = fread(filename);
   unlink(filename);
   fwrite(data:b, file:filename);
  }

  return b;
}

##
#
##
function get_cyberark_password(username, prefix, postfix)
{
  local_var parameters, cyberark_creds, db_password, cyberark_host, cyberark_port, cyberark_password,
  cyberark_ssl, cyberark_ssl_verify, cyberark_appid, cyberark_safe, cyberark_folder, cyberark_url,
  cyberark_objectname, cyberark_username, cyberark_client_cert, cyberark_private_key,
  cyberark_private_key_password, b;

  cyberark_host = script_get_preference(prefix+"Database CyberArk Host"+postfix);
  cyberark_port = script_get_preference(prefix+"Database CyberArk Port"+postfix);
  cyberark_username = script_get_preference(prefix+"Database CyberArk Username"+postfix);
  cyberark_password = script_get_preference(prefix+"Database CyberArk Password"+postfix);
  cyberark_ssl = script_get_preference(prefix+"Database CyberArk SSL"+postfix);
  cyberark_ssl_verify = script_get_preference(prefix+"Database CyberArk Verify SSL Certificate"+postfix);
  cyberark_appid = script_get_preference(prefix+"Database CyberArk AppId"+postfix);
  cyberark_safe = script_get_preference(prefix+"Database CyberArk Safe"+postfix);
  cyberark_folder = script_get_preference(prefix+"Database CyberArk Folder"+postfix);
  cyberark_url = script_get_preference(prefix+"Database CyberArk URL"+postfix);
  cyberark_objectname = script_get_preference(prefix+"Database CyberArk Account Details Name"+postfix);
  cyberark_client_cert = script_get_preference_file_location(prefix+"Database CyberArk client certificate to use"+postfix);
  cyberark_private_key = script_get_preference_file_location(prefix+"Database CyberArk private key to use"+postfix);
  cyberark_private_key_password = script_get_preference(prefix+"Database CyberArk Passphrase for private key"+postfix);

  if(isnull(cyberark_private_key_password))
  {
    cyberark_private_key_password = "";
  }

  # The Raw cert uploads need to be processed. ref: global_settings.nasl
  read_and_write_file_cred(filename:cyberark_client_cert);
  read_and_write_file_cred(filename:cyberark_private_key);

  spad_log(message:'Cyberark DB settings :\n' +
           " cyberark_host: " + cyberark_host + '\n' +
           " cyberark_port: " + cyberark_port + '\n' +
           " cyberark_username: " + cyberark_username + '\n' +
           " cyberark_ssl: " + cyberark_ssl + '\n' +
           " cyberark_ssl_verify: " +cyberark_ssl_verify + '\n' +
           " cyberark_appid: " + cyberark_appid + '\n' +
           " cyberark_safe: " + cyberark_safe + '\n' +
           " cyberark_folder: " + cyberark_folder + '\n' +
           " cyberark_url: " + cyberark_url + '\n' +
           ' cyberark_client_cert : ' + cyberark_client_cert + '\n' +
           ' cyberark_private_key : ' + cyberark_private_key + '\n' +
           " cyberark_objectname: " + cyberark_objectname + '\n'
           );

  if (strlen(ereg_replace(pattern:"([^ ]*) *$", string:cyberark_username, replace:"\1")) == 0)
    cyberark_username  = NULL;

  if (strlen(ereg_replace(pattern:"([^ ]*) *$", string:cyberark_password, replace:"\1")) == 0)
    cyberark_password = NULL;

  if (cyberark_ssl == "yes") cyberark_ssl = TRUE;
  else cyberark_ssl = FALSE;

  if (cyberark_ssl_verify == "yes") cyberark_ssl_verify = TRUE;
  else cyberark_ssl_verify = FALSE;

  cark_init(target:cyberark_host, port:cyberark_port, cark_url:cyberark_url,
    ssl:cyberark_ssl, ssl_verify:cyberark_ssl_verify,
    username:cyberark_username, password:cyberark_password,
    object_id:cyberark_objectname,
    client_cert:cyberark_client_cert,
    client_private_key:cyberark_private_key,
    client_private_key_password:cyberark_private_key_password);

  parameters = make_array(
        "AppID", cyberark_appid,
        "Safe", cyberark_safe,
        "Folder",cyberark_folder,
        "Object", cyberark_objectname,
        "Reason","NESSUS"
        );

  cyberark_creds = cark_get_password_http_req(parameters:parameters);

  if (isnull(cyberark_creds))
  {
    spad_log(message:'Cyberark Error : CyberArk Account Details Name (' + cyberark_objectname + ') could not be found.');
  }
  else
  {
    if (!isnull(cyberark_creds["Password"]))
    {
      spad_log(message:"Password found for " + cyberark_objectname + '.');
      db_password = cyberark_creds["Password"];
    }
    else
    {
      spad_log(message:'Cyberark Error : ' + cyberark_objectname + ' returned a null password.');
    }
  }

  return db_password;
}

function store_db_settings_in_kb()
{

  spad_log(message:'Database Settings : \n'+
           '  source:'+source+'\n'+
           "  type:"+type+'\n'+
           "  credential type:"+cred_type+'\n'+
           "  db_service_type:"+db_service_type+'\n'+
           "  service:"+service+'\n'+
           "  port:"+port+'\n'+
           "  username:"+username+'\n'+
           "  oracle_cred_type:"+oracle_cred_type+'\n'+
           "  mssql_cred_type:"+mssql_cred_type+'\n'+
           "  sybase_auth_type:"+sybase_type+'\n'+
           '  cred_manager_id:'+cred_manager_id+'\n'
  );

  if (cred_type =~ "CyberArk|Hashicorp")
    spad_log(message:'Additional processing required for: ' + cred_type);
  else if ('client certificate' >!< tolower(cred_type) && !strlen(password))
    spad_log(message:"Failed to obtain password for " + username);

  if ("Windows" >< mssql_cred_type)
    sspi = TRUE;
  else if ("SQL" >< mssql_cred_type)
    sspi = FALSE;

  if ("NORMAL" >< oracle_cred_type)
    atype = TNS_LOGON_NORMAL;
  else if ("SYSOPER" >< oracle_cred_type)
    atype = TNS_LOGON_SYSOPER;
  else if ("SYSDBA" >< oracle_cred_type)
    atype = TNS_LOGON_SYSDBA;

  if (sybase_type == 'RSA' || sybase_type == 'Plain Text')
    sybase_ase_cred_type = sybase_type;

  # The Raw cert uploads need to be processed. ref: global_settings.nasl
  if(client_cert) read_and_write_file_cred(filename:client_cert);
  if(client_cert_ca) read_and_write_file_cred(filename:client_cert_ca);
  if(client_cert_pk) read_and_write_file_cred(filename:client_cert_pk);

  store_instance_in_kb(
      index: kb_index,
      service_type: db_service_type,
      service: service,
      port: port
  );

  store_credential_set_in_kb(
      index: kb_index,
      source: source,
      db_type_name: type,
      db_type: decode_db_type(type),
      cred_type: cred_type,
      username: username,
      password: password,
      sspi: sspi,
      atype: atype,
      sybase_ase_cred_type: sybase_ase_cred_type,
      client_cert: client_cert,
      client_cert_ca: client_cert_ca,
      client_cert_pk: client_cert_pk,
      client_cert_pk_passphrase: client_cert_pk_passphrase,
      cred_manager_id: cred_manager_id,
      mtls_wallet: mtls_wallet,
      mtls_wallet_pass:mtls_wallet_pass,
      db_port:port
  );

  kb_index++;
}

var TNS_LOGON_NORMAL, TNS_LOGON_SYSOPER, TNS_LOGON_SYSDBA, kb_index, kb_path, i;
var username, password, oracle_cred_type, sybase_ase_cred_type, atype, sspi, port, type;
var mssql_instance_name, mssql_cred_type;
var service, service_type, client_cert, client_cert_ca, client_cert_pk, client_cert_pk_passphrase;
var cred_type, cred_manager_id;
var mtls_wallet, mtls_wallet_pass;

TNS_LOGON_NORMAL    = 0;
TNS_LOGON_SYSOPER   = 64;
TNS_LOGON_SYSDBA    = 32;

kb_index = 0;
process_cred_manager = false;

for (i = 0; TRUE; i++)
{
  # Clear variables
  username = password = atype = sspi = port = NULL;
  cred_type = oracle_cred_type = mssql_cred_type = sybase_ase_cred_type = NULL;
  type = source = service = service_type = csv = NULL;
  client_cert = client_cert_ca = client_cert_pk = client_cert_pk_passphrase = NULL;
  mtls_wallet = mtls_wallet_pass = NULL;
  cred_manager_id = NULL;

  if (i == 0)
  {
    type = script_get_preference("DB Type : ");
    source = script_get_preference("Source : ");
    cred_type = script_get_preference("Credential Type : ");

    # New section for PAM Database Auto Collection of Hosts from REST API's
    # SC implementation, AUTHENTICATION_AUTH_CYBERARKAUTODISCOVERY	=> "CyberArk Auto-Discovery"
    # which differs from credentials.json "CyberArk Database Auto-Discovery"
    if ("CyberArk" >< cred_type && "Auto-Discovery" >< cred_type)
    {
      var pam = cyberark_auto_collect::pam;
      kb_path = "/auto_db/";
      source = "entry";

      # set parameter vars for AIM Webservice query to fetch password
      var object = get_kb_item(pam + kb_path + "object");
      var safe = get_kb_item(pam + kb_path + "safe");
      var address = get_kb_item(pam + kb_path + "address");
      username = get_kb_item(pam + kb_path + "username");

      # set other database kb's
      port             = get_kb_item(pam + kb_path + "port");
      db_service_type  = get_kb_item(pam + kb_path + "db_service_type");
      service          = get_kb_item(pam + kb_path + "service");
      var db_auth      = get_kb_item(pam + kb_path + "db_auth");

      if (type == "Oracle")
      {
        oracle_cred_type = db_auth;
      }
      if (type == "SQL Server")
      {
        mssql_cred_type  = db_auth;
      }
      if (type == "Sybase ASE")
      {
        sybase_type = db_auth;
      }

      if (empty_or_null(object) || empty_or_null(safe) || empty_or_null(address))
      {
        spad_log(message:"Host did not contain 1 or more CyberArk query parameter values. Will not attempt to retrieve password.");
      }
      else
      {
        # get password from AIM Webservice
        var ca_result = cyberark_auto_collect::get_AIM_secret(settings:"Database settings", prefix:"Database ", postfix:" :", safe:safe, username:username, address:address, object:object);
        if (!ca_result.success)
        {
          spad_log(message:"Failed to retrieve password for CyberArk Database Host.");
        }
        else
        {
          password = ca_result.password;
        }
      }
    }
    else
    {
      if(cred_type == 'Import')
        source = 'import';

      if (empty_or_null(source))
        source = "entry";

      if (source != 'import')
      {
        source = "entry";

        if (!empty_or_null(cred_type))
        {
          spad_log(message:"Auth Type : " + cred_type);
        }

        db_service_type = script_get_preference("Database service type : ");
        service = script_get_preference("Database SID : ");
        port = script_get_preference("Database port to use : ");
        username = script_get_preference("Login : ");

        if (empty_or_null(username) && empty_or_null(cred_type))
        {
          spad_log(message:"Completed with " + kb_index + " KB entries set.");
          break;
        }

        oracle_cred_type = script_get_preference("Oracle auth type: ");
        mssql_cred_type = script_get_preference("SQL Server auth type: ");
        sybase_type = script_get_preference("Sybase ASE auth type : ");
        if ('client certificate' >< tolower(cred_type))
        {
          client_cert = script_get_preference_file_location("Database client certificate to use :");
          client_cert_ca = script_get_preference_file_location("Database client certificate CA to use :");
          client_cert_pk = script_get_preference_file_location("Database client certificate private key :");
          client_cert_pk_passphrase = script_get_preference("Database Passphrase for client certificate private key :");
        }
        else if ('oracle' == tolower(type) && script_get_preference("Oracle Wallet for mTLS Only :"))
        {
          mtls_wallet = script_get_preference_file_location("Oracle Wallet for mTLS Only :");
          mtls_wallet_pass = script_get_preference("Oracle Wallet Password :");
        }

        if ("CyberArk" >< cred_type || "cyberark" >< cred_type)
        {

          spad_log(message:"CyberArk Methods");
          if (!empty_or_null(script_get_preference("Database CyberArk Host :")))
          {
            spad_log(message:"CyberArk SOAP API");
            process_cred_manager = true;
          }
          else
          {
            var cyberark_result;
            spad_log(message:"CyberArk REST API");
            cyberark_result = cyberark::cyberark_rest_get_credential(username:username, prefix:"Database PAM ", postfix:" : ");
            if (!cyberark_result.success)
            {
              spad_log(message: "Failed to obtain a password.");
            }
            else
            {
              password = cyberark_result.password;
              username = cyberark_result.username;
            }
          }
        }
        else if ("Lieberman" >< cred_type)
        {
          password = lieberman_get_password(login:username, type: type, prefix:"Database ", postfix:" : ");
          password = password.body.Password;
        }
        else if ("Hashicorp" >< cred_type)
        {
          process_cred_manager = true;
        }
        else if ("Wallix" >< cred_type)
        {
          var wallix_result;

          wallix_result = wallix::rest_get_credential(prefix: "Database ", postfix: " : ");

          if (wallix_result.success)
          {
            spad_log(message: "Database credentials returned successfully.");
            password = wallix_result.password;
            username = wallix_result.username;
          }
          else
          {
            spad_log(message: "Failed to return Database credentials.");
          }
        }
        else if ("Senhasegura" >< cred_type)
        {
          var senha_result;

          senha_result = senhasegura::get_credential(prefix:"Database PAM ", postfix:" : ");

          if(senha_result.success)
          {
            spad_log(message:"Successfully retrieved Senhasegura PAM Database credentials.");

            username = senha_result.creds.username;
            password = senha_result.creds.password;
          }
          else
          {
            spad_log(message:"Failed to retrieve Senhasegura PAM Database credentials.");
          }
        }
        else if ("Arcon" >< cred_type)
        {
          var arcon_result = arcon::get_credential(username:username, prefix:"Database ", postfix:" : ", type:arcon::database_type_map[type]);

          if (arcon_result.success)
          {
            spad_log(message:"Successfully got Arcon PAM DB credentials.");

            password = arcon_result.password;
          }
          else
          {
            spad_log(message:"Failed to retrieve Arcon PAM DB credentials.");
          }
        }
        else if ("QiAnXin" >< cred_type)
        {
          var qianxin_result = qianxin::get_credential(prefix:"Database PAM ", postfix:" : ", default_platform:qianxin::database_type_map[type]);

          if (qianxin_result.success)
          {
            spad_log(message:"Successfully got QiAnXin PAM DB credentials.");
            username = qianxin_result.creds.username;
            password = qianxin_result.creds.password;
          }
          else
          {
            spad_log(message:"Failed to retrieve QiAnXin PAM DB credentials.");
          }
        }
        else if ("BeyondTrust" >< cred_type)
        {
          var domain = script_get_preference("Database domain (optional) : ");
          var beyondtrust_result = beyondtrust::get_password(prefix:"Database ", postfix:" : ", login:username, domain:domain, platform:'database');

          if (beyondtrust_result.success)
          {
            spad_log(message:"Successfully got BeyondTrust PAM DB credentials.");
            password = beyondtrust_result.body;
          }
          else
          {
            spad_log(message:"Failed to retrieve BeyondTrust PAM DB credentials.");
          }
        }
        else if ("Delinea" >< cred_type)
        {
          var delinea_result = delinea::rest_get_creds(prefix:"Database ", postfix:" : ");
          if (delinea_result.success)
          {
            spad_log(message:"Successfully got Delinea PAM DB credentials.");
            username = delinea_result.secrets.username;
            password = delinea_result.secrets.password;
          }
          else
          {
            spad_log(message:"Failed to retrieve Delinea PAM DB credentials.");
          }
        }
        else if ("Fudo" >< cred_type)
        {
          var fudo_result = fudo::get_credential(prefix:"Database PAM ", postfix:" : ");
          if (dbg::is_error(fudo_result))
          {
            dbg::log_error(msg:"Failed to retrieve Fudo PAM Database credentials.");
          }
          else
          {
            dbg::detailed_log(lvl:2, msg:"Successfully retrieved Fudo PAM Database credentials.");

            # Note that username (account) does not get retrieved from the integration.
            password = fudo_result.password;
          }
        }
        else
        {
          password = script_get_preference("Password : ");
        }
      }

      else if (source == "import")
      {
        csv = script_get_preference_file_location("CSV file : ");
        csv = read_and_write_file_cred(filename:csv);
      }
    }
  }
  else
  {
    spad_log(message:"Iteration " + i); # After 1st iteration to avoid log entry when no creds are specified

    type = script_get_preference("Additional DB Type (" + i + ") : ");
    source = script_get_preference("Additional Source (" + i + ") :");
    cred_type = script_get_preference("Additional Credential Type (" + i + ") : ");

    # New section for PAM Database Auto Collection of Hosts from REST API's
    # SC implementation, AUTHENTICATION_AUTH_CYBERARKAUTODISCOVERY	=> "CyberArk Auto-Discovery"
    # which differs from credentials.json "CyberArk Database Auto-Discovery"
    if ("CyberArk" >< cred_type && "Auto-Discovery" >< cred_type)
    {
      pam = cyberark_auto_collect::pam;
      settings = "Database settings";
      kb_path = "/auto_db/";
      prefix = "Additional Database ";
      source = "entry";

      # set parameter vars for AIM Webservice query to fetch password
      object = get_kb_item(pam + kb_path + "object");
      safe = get_kb_item(pam + kb_path + "safe");
      address = get_kb_item(pam + kb_path + "address");
      username = get_kb_item(pam + kb_path + "username");

      # set other database kb's
      port             = get_kb_item(pam + kb_path + "port");
      db_service_type  = get_kb_item(pam + kb_path + "db_service_type");
      service          = get_kb_item(pam + kb_path + "service");
      db_auth      = get_kb_item(pam + kb_path + "db_auth");

      if (type == "Oracle")
      {
        oracle_cred_type = db_auth;
      }
      if (type == "SQL Server")
      {
        mssql_cred_type  = db_auth;
      }
      if (type == "Sybase ASE")
      {
        sybase_type = db_auth;
      }

      if (empty_or_null(object) || empty_or_null(safe) || empty_or_null(address))
      {
        spad_log(message:"Host did not contain 1 or more CyberArk query parameter values. Will not attempt to retrieve password.");
      }
      else
      {
        ca_result = cyberark_auto_collect::get_AIM_secret(settings:settings, prefix:prefix, postfix: " ("+i+") :",safe:safe, username:username, address:address, object:object);
        if (!ca_result.success)
        {
          spad_log(message:"Failed to retrieve password for CyberArk Database Host.");
        }
        else
        {
          password = ca_result.password;
        }
      }
    }
    else
    {
      if(cred_type == 'Import')
        source = 'import';

      if (empty_or_null(source))
        source = "entry";

      if (source != 'import')
      {
        if (!isnull(cred_type))
        {
          spad_log(message:"Credential Type (" + i + ") : "+ cred_type);
        }

        db_service_type = script_get_preference("Additional Database service type (" + i + ") : ");
        service = script_get_preference("Additional Database SID (" + i + ") : ");
        port = script_get_preference("Additional Database port to use (" + i + ") : ");
        username = script_get_preference("Additional Login (" + i + ") : ");

        if (empty_or_null(username) && empty_or_null(cred_type))
        {
          spad_log(message:"Completed with " + kb_index + " KB entries set.");
          break;
        }

        password = script_get_preference("Additional Password (" + i + ") : ");
        oracle_cred_type = script_get_preference("Additional Oracle auth type (" + i + ") : ");
        mssql_cred_type = script_get_preference("Additional SQL Server auth type (" + i + ") : ");
        sybase_type = script_get_preference("Additional Sybase ASE auth type (" + i + ") : ");

        if ('client certificate' >< tolower(cred_type))
        {
          client_cert = script_get_preference_file_location("Database client certificate to use (" + i + ") :");
          client_cert_ca = script_get_preference_file_location("Database client certificate CA to use (" + i + ") :");
          client_cert_pk = script_get_preference_file_location("Database client certificate private key (" + i + ") :");
          client_cert_pk_passphrase = script_get_preference("Database Passphrase for client certificate private key (" + i + ") :");
        }
        else if ('oracle' == tolower(type) && script_get_preference("Oracle Wallet for mTLS Only (" + i + ") :"))
        {
          mtls_wallet = script_get_preference_file_location("Oracle Wallet for mTLS Only (" + i + ") :");
          mtls_wallet_pass = script_get_preference("Oracle Wallet Password (" + i + ") :");
        }


        if ("CyberArk" >< cred_type || "cyberark" >< cred_type)
        {
          if ("CyberArk (Legacy)" >< cred_type || "cyberarkLegacy" >< cred_type)
          {
            spad_log(message:"CyberArk SOAP API");
            process_cred_manager = true;
          }
          else
          {
            spad_log(message:"CyberArk REST API");
            cyberark_result = cyberark::cyberark_rest_get_credential(username:username, prefix:"Database PAM ", postfix:" : ");
            if (!cyberark_result.success)
            {
              spad_log(message: "Failed to obtain a password.");
            }
            else
            {
              password = cyberark_result.password;
              username = cyberark_result.username;
            }
          }
        }
        else if ("Lieberman" >< cred_type)
        {
          password = lieberman_get_password(login:username, type: type, prefix:"Additional Database ", postfix:" ("+i+") : ");
          password = password.body.Password;
        }
        else if ("Hashicorp" >< cred_type)
        {
          process_cred_manager = true;
        }
        else if ("Wallix" >< cred_type)
        {
          wallix_result = wallix::rest_get_credential(prefix: "Additional Database ", postfix:" ("+i+") : ");

          if (wallix_result.success)
          {
            spad_log(message: "Database credentials returned successfully.");
            password = wallix_result.password;
            username = wallix_result.username;
          }
          else
          {
            spad_log(message: "Failed to return Database credentials.");
          }
        }
        else if ("Senhasegura" >< cred_type)
        {
          var senha_result;

          senha_result = senhasegura::get_credential(prefix:"Additional Database PAM ", postfix:" : ");

          if(senha_result.success)
          {
            spad_log(message:"Successfully retrieved Senhasegura PAM Database credentials.");

            username = senha_result.creds.username;
            password = senha_result.creds.password;
          }
          else
          {
            spad_log(message:"Failed to retrieve Senhasegura PAM Database credentials.");
          }
        }
        else if ("Arcon" >< cred_type)
        {
          var arcon_result = arcon::get_credential(username:username, prefix:"Additional Database ", postfix:" (" + i + ") : ", type:arcon::database_type_map[type]);

          if (arcon_result.success)
          {
            spad_log(message:"Successfully got Arcon PAM DB credentials.");

            password = arcon_result.password;
          }

        }
        else if ("QiAnXin" >< cred_type)
        {
          var qianxin_result = qianxin::get_credential(prefix:"Additional Database PAM ", postfix:" (" + i + ") : ", default_platform:qianxin::database_type_map[type]);

          if (qianxin_result.success)
          {
            spad_log(message:"Successfully got QiAnXin PAM DB credentials.");
            username = qianxin_result.creds.username;
            password = qianxin_result.creds.password;
          }
          else
          {
            spad_log(message:"Failed to retrieve QiAnXin PAM DB credentials.");
          }
        }
        else if ("BeyondTrust" >< cred_type)
        {
          var domain = script_get_preference("Additional Database domain (optional) ("+i+") : ");
          var beyondtrust_result = beyondtrust::get_password(prefix:"Additional Database ", postfix:" (" + i + ") : ", login:username, domain:domain, platform:'database');

          if (beyondtrust_result.success)
          {
            spad_log(message:"Successfully got BeyondTrust PAM DB credentials.");
            password = beyondtrust_result.body;
          }
          else
          {
            spad_log(message:"Failed to retrieve BeyondTrust PAM DB credentials.");
          }
        }
        else if ("Delinea" >< cred_type)
        {
          var delinea_result = delinea::rest_get_creds(prefix:"Additional Database ", postfix:" (" + i + ") : ");
          if (delinea_result.success)
          {
            spad_log(message:"Successfully got Delinea PAM DB credentials.");
            username = delinea_result.secrets.username;
            password = delinea_result.secrets.password;
          }
          else
          {
            spad_log(message:"Failed to retrieve Delinea PAM DB credentials.");
          }
        }
        else if ("Fudo" >< cred_type)
        {
          var fudo_result = fudo::get_credential(prefix:"Additional Database PAM ", postfix:" (" + i + ") : ");
          if (dbg::is_error(fudo_result))
          {
            dbg::log_error(msg:"Failed to retrieve Fudo PAM Database credentials.");
          }
          else
          {
            dbg::detailed_log(lvl:2, msg:"Successfully retrieved Fudo PAM Database credentials.");

            # Note that username (account) does not get retrieved from the integration.
            password = fudo_result.password;
          }
        }
        else
        {
          if(empty_or_null(password))
            password = script_get_preference("Password ("+i+") : ");
        }
      }
      else if (source == "import")
      {
        csv = script_get_preference_file_location("Additional CSV file (" + i + ") : ");
        csv = read_and_write_file_cred(filename:csv);
      }
    }
  }

  if (source == "import")
  {
    var database_setting;

    if (!empty_or_null(csv))
      database_settings = database_settings::csv::parse(csv:csv, type:type);

    import_source_detected = true;

    foreach database_setting (database_settings)
    {
      if (!is_same_host(a:database_setting.target))
        continue;

      spad_log(message:"Target IP address (" + get_host_ip() + ") matched against CSV target " +
                        database_setting.target + ".");

      # Set variables to be set in KB
      port             = database_setting.port;
      db_service_type  = database_setting.db_service_type;
      service          = database_setting.service;
      username         = database_setting.username;
      password         = database_setting.password;

      oracle_cred_type = database_setting.oracle_cred_type;
      mssql_cred_type  = database_setting.auth_type;

      cred_type        = database_setting.cred_manager;
      cred_manager_id  = database_setting.cred_manager_id;

      if (!empty_or_null(cred_type)) process_cred_manager = true;

      store_db_settings_in_kb();
    }
  }
  else
  {
    store_db_settings_in_kb();
  }
}

if (!empty_or_null(kb_index))
  replace_kb_item(name:'Database/index_size', value:kb_index);

# Process CSV import and entries that use CyberArk or Hashicorp
if (process_cred_manager)
  database_settings::cred_manager::process_entries();

