#TRUSTED ad3fef3db1bf88de28ad201761431b2b319cddd8dc7d10527b88a00ee2fa1c4bcd5d430471b24a4e8a5882b2210c98241170cb13b4e22eb8e19a462863cfceb614bf7080d5c43786364e9875cc02cd7f207b7960dc4ddd0a28b4b8ac2569b038e363aaf522a96afcb117d3f2fed200cbaa7de9b927557c2cf3482e2cf0703bbe5b616b26f56b998a2a05d1d666bf62af2ca35da09383a9b7322ed4b5ef48daa93595859617a8bea66d51b3cf6c6788a229b97ab9c9358d100d3936a95813901f1d5e802246441d970dcfa4c8a588f7fd4e0d26e62e80fd32dd45c77f147cac6842230982c0938cf112e6e5f85aa539380a1ddcb4ce4b01d952ade97c550d96b1287ee79b8adaae27c2bcdb5a8f457e4d44a7ed062a23a204a3f8a730d0f085e66390a66975f53a8abbd71a69fe9808e7d59e40d7b88054b6ceb107203a28d23e5f68031ac27ba9978c5e79431be1b746757866ca2bdc4e236f054cd69b1196a54ce681fd609c5a48980293ae71852d221e3cfdcc0574f2eb7b38784365dc07eeb5cbea2fd4de3e509511baf76bfaa95befeb155c5913a09a29d87327de58d9cafb1fae010945de73cab50383c98b9e475e54b52fb2679d05ba7e4defaf62de9c3ad73ef09fe19f37808473d8866bc749f6af9cbbe94a772aadf54dff1e17aee58cc265e05453d1cd090c845d56cd7179a96d2e2cf3053a11556854ec84903d64
#TRUST-RSA-SHA256 87c139381ec354cbd35e51dd320648d03a2ebdfec23da6506683810f61abb50f9c7b3ccef75ec318a3020eca21f73a19cdd43ae9358268f51d759d832862c4ed23f352e9e8921e7f534903aad1f6d950ed1f12deb525ca4f5e150828d101ea0c211e992779cfc4a81d7c92d98c85826617b31cc13e65c1d85253bba13e908ceacc72380a484dbe80ea92a0d554d06d1ae99b89828659f9a1313456c5bb3fff7c98643ba694ba658cffac7f7389ca9bf440b1faa5383781c86d1147b660edd211bfe7150821e6c05987bdc1ba5a4c31dedb91d68f86a8742334913ebdb18f425e1ac49c121b603c043984aaa808fbbbc15424c7896cdc5685d9c07004f7ae0d7cbc718b88f622b2d91c5966aeaab987f18489851565f25c19fea165349f56dc725d04ecc08aae216c2641209eb8239cf03bd0c2aef53c3f3cb9ee2425526962af8a12bcae243f182172163b2f3f4b332f0a0b9660142489276848fe474a3df910d3306cc32be9a1aca6dab41292fb3aa7df051d55ded9626228c27e60690e109057d7af5f9719cd8bba7a7818923a54f80d61b8f03f5fc3e6c8c5901ee4e438eb278d9b24d358442887d4cc83c0e00e9c97dabcf03e29caefaf68bf72510531883a55f4f6885dec5ec99be9f928de22049a36606d221d8672448e5493694475463fa35a64cc98064f6e21d2503426e6bc579c4989b8e08cc7c8afebb2bde88571

###
# Functions to support SMB file operations for vuln detection.
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# smb_hotfixes_fcheck.inc
# Revision: 1.124
###

include("compat_shared.inc");
include("kerberos_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_globals.inc");
include("debug.inc");
include("agent.inc");
include('install_func.inc');
include("structured_data.inc");

global_var HCF_CONNECT = -1; # Could not connect to port 139 or 445
global_var HCF_NOAUTH =  -2; # No credentials or share does not exist
global_var HCF_NOENT  =  -3; # File does not exist
global_var HCF_ERR    =  -4; # Unknown error
global_var HCF_NOVER  =  -5; # File version does not exist
global_var HCF_NOTIME =  -6; # File timestamp does not exist.
global_var HCF_PARSE  =  -7; # Unable to parse pathname.
global_var HCF_OK     =   0; # No error
global_var HCF_OLDER  =   1; # The remote file is older than what we wanted

include("smb_reg_query.inc");
global_var HCF_UNACCESSIBLE_SHARE = 2;
global_var HCF_ACCESSIBLE_SHARE   = 3;

global_var hcf_init;
global_var hcf_report = NULL;

# note, these value are altered only if smb_check_rollup() or
# smb_check_dotnet_rollup() are called, respectively
global_var smb_check_rollup_done = TRUE;
global_var smb_check_dotnet_rollup_done = TRUE;

include("smb_fixes_summary.inc");

##
# Returns the collected plugin report.
#
# @return [string] The current plugin's report text.
##
function hotfix_get_report()
{
  if (!smb_check_rollup_done || !smb_check_dotnet_rollup_done)
  {
    hcf_report += '\n\nNote that this result may be incomplete ' +
      'because the following were not enumerated successfully :';

    if (!smb_check_rollup_done)
      hcf_report += '\n  - Windows Monthly Rollups';
    if (!smb_check_dotnet_rollup_done)
      hcf_report += '\n  - .NET Framework Monthly Rollups';
  }
  return hcf_report;
}

##
# Get text for "not affected" plugin audit log.
#
# @return [string] Text for "Host not" plugin audit.
##
function hotfix_get_audit_report()
{
  var out = 'affected.';
  if (!smb_check_rollup_done)
  {
    out += '\n\nNote that this result may be incomplete because ' +
      'rollups were not enumerated successfully.';
  }
  return out;
}

##
# Get text for "not affected" plugin audit log that includes app and version.
#
# @param [app:string] Application name
# @param [version:string] Application version
#
# @return [string] Text for "Host not" plugin audit.
##
function hotfix_get_dotnet_audit_report(app, version)
{
  # audit(AUDIT_INST_VER_NOT_VULN, app, version);
  var out = app + ' version ' + version + ' is installed and ' +
    'not affected.';
  if (!smb_check_dotnet_rollup_done)
  {
    out += '\n\nNote that this result may be incomplete because ' +
      '.NET rollups were not enumerated successfully.';
  }
  return out;
}

##
# Collects plugin vulnerability report for Windows hotfixes and adds an
# appropriate XML tag.
#
# @anonparam [First:string] (optional) Plugin report text
# @param [bulletin:string] (optional) Microsoft security advisory KB number.
# @param [kb:string] (optional) Microsoft rollup KB number
#
# @remark Any combination of the arguments may be supplied, but a report
#         usually requires at least two to make sense.
##
function hotfix_add_report(bulletin, kb)
{
  if (
    !isnull(bulletin) &&
    !isnull(kb)
  )
  {
    smb_hf_add(bulletin:bulletin, kb:kb);
    if(defined_func("report_xml_tag"))
      report_xml_tag(tag:bulletin, value:kb);
  }

  hcf_report += _FCT_ANON_ARGS[0];
}


##
# Collects a structured vulnerability report for a single plugin/advisory.
#
# @param [kb:string] Microsoft rollup KB number.
# @param [path:string] (optional) Path to detected application (i.e. Microsoft Exchange)
# @param [version:string] (optional) Current vulnerable version - usually of the file referred to by path
# @param [cpe:string] A platform identifier.
# @param [cves:list] (optional) CVEs addressed in the indicated KB advisory for the detected product.
##
function hotfix_add_structured_report(kb, path, version, cpe, cves)
{
  var cve;

  if(isnull(cpe))
    return NULL;

  var structured_data = new structured_data_vuln_reporting(445, "tcp");
  var fixes = [{"fix_type": "MSKB", "value": string(kb)}];

  var vuln = {
    "fix_available": TRUE,
    "identifier": cpe,
    "all_vulnerabilities": TRUE,
    "version": version,
    "path": path,
    "fixes": fixes
  };

  if(!empty_or_null(cves))
  {
    vuln.all_vulnerabilities = FALSE;

    #validate CVEs
    foreach cve(cves)
    {
      if(preg(pattern:"^CVE-\d{4}-\d{4,}$", string:cve))
      {
        if(empty_or_null(vuln.vulnerabilities))
          vuln.vulnerabilities = [cve];
        else
          append_element(var:vuln.vulnerabilities, value:cve);
      }
    }
  }

  structured_data.append("vulnerability", vuln);
  structured_data.report_internal();
}


##
# Reports a plugin finding and optionally sets scan KBs if
# the finding is XSS, XSRF or SQLi
#
# @param [severity:int] Reported severity
# @param [xss:boolean] (optional) TRUE if reporting a XSS vuln.
# @param [xsrf:boolean] (optional) TRUE if reporting a XSRF vuln.
# @param [sqli:boolean] (optional) TRUE if reporting a SQL injection vuln.
##
function hotfix_security_report(severity, xss, xsrf, sqli)
{
  var port = get_kb_item("SMB/transport");
  var env = nasl_environment(flags:ENV_PLUGIN);

  # These are set unconditionally
  if (xss)
    replace_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  if (xsrf)
    replace_kb_item(name:"www/"+port+"/XSRF", value:TRUE);
  if (sqli)
    replace_kb_item(name:"www/"+port+"/SQLInjection", value:TRUE);

  if (severity == SECURITY_HOLE) hotfix_security_hole();
  else if (severity == SECURITY_WARNING) hotfix_security_warning();
  else hotfix_security_note();
}


##
# Reports a high/critical security vulnerability with collected details for the
# current plugin.
##
function hotfix_security_hole()
{
  if ( ! isnull(hcf_report) )
    security_hole(port:get_kb_item("SMB/transport"), extra:'\n'+hotfix_get_report()+'\n');
  else
    security_hole(port:get_kb_item("SMB/transport"));
}


##
# Reports a medium security vulnerability with collected details for the
# current plugin.
##
function hotfix_security_warning()
{
  if ( ! isnull(hcf_report) )
    security_warning(port:get_kb_item("SMB/transport"), extra:'\n'+hotfix_get_report()+'\n');
  else
    security_warning(port:get_kb_item("SMB/transport"));
}


##
# Sends an low security vulnerability or informational report with collected details for the
# current plugin.
##
function hotfix_security_note()
{
  if ( ! isnull(hcf_report) )
    security_note(port:get_kb_item("SMB/transport"), extra:'\n'+hotfix_get_report()+'\n');
  else
    security_note(port:get_kb_item("SMB/transport"));
}


##
# Initializes hotfix file based checks for the current plugin.
#
# @return [int] HCF_OK
##
function hotfix_check_fversion_init()
{
  var soc, port, name;

  if(! smb_session_init()) return HCF_CONNECT;

  hcf_init = 1;
  return HCF_OK;
}


##
# Finalizes hotfix file based checks for the current plugin.
#
# @return [int] HCF_OK
##
function hotfix_check_fversion_end()
{
  if ( hcf_init != 0 ) {
    NetUseDel();
    hcf_init = 0;
  }
  return HCF_OK;
}

##
# Adds SQL Server information to the report if this
# plugin is checking a SQL Server version
#
# @param [file:string] Full path of a file
# @param [drive:strig] The SMB share as a drive letter - i.e. "C:"
# @return [string|NULL] Formatted information about SQL server to add to the report.
# @remark
# The following information is returned:
# ```
#      - Version number
#      - Human readable version
#      - Instance name
# ```
##
function hotfix_make_sql_report(file, drive)
{
  var report;
  report = NULL;

  var justthepath = ereg_replace(pattern:"^(.*)\\.*$", string: file, replace:"mssql/installs/" + drive + "\1/");

  var version_kb = justthepath + "SQLVersion";
  var version = get_kb_item(version_kb);
  if(!isnull(version))
    report += '  SQL Server Version   : ' + version;
  else
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, level:2, label:'get_kb_item call for mssql KB');
    return NULL;
  }

  var versionverbose = get_kb_item(justthepath + "SQLVerboseVersion");
  if(!isnull(versionverbose))
    report += ' (' + versionverbose + ')';

  var edition_typ = get_kb_item(justthepath + "edition_typ");
  if(!isnull(edition_typ))
    report += ' ' + edition_typ;
  else
  {
    var edition = get_kb_item(justthepath + "edition");
    if(!isnull(edition ))
      report += ' ' + edition;
  }

  var instance = get_kb_item(justthepath + "NamedInstance");
  if(!isnull(instance))
    report += '\n  SQL Server Instance  : ' + instance;

  if (!isnull(report))
    report = '\n' + report + '\n';

  return report;
}

##
# Checks if a file exists
#
# @param [path:string] absolute pathname of file to check
# @remark this function assumes hotfix_check_fversion_init() has already been called and succeeded
#
# @return [boolean|NULL] TRUE  if the given file exists,
#         FALSE if the given file does not exist,
#         NULL  otherwise
##
function hotfix_file_exists(path)
{
  var version, exists, fh;
  exists = NULL;
  version = hotfix_get_fversion(path:path);

  dbg::detailed_log(
    lvl:1, 
    src:FUNCTION_NAME, 
    msg:'file_exists checking path: ' + path,
    msg_details:{'Result':{'lvl':1, 'value':obj_rep(version['error'])}});

  if (version['error'] == HCF_OK || version['error'] == HCF_NOVER)
    exists = TRUE;
  else if (version['error'] == HCF_NOENT)
  {
    if (agent())
    {
      # If $path is a directory Windows Agents will return HCF_NOENT regardless, so retry with FILE_ATTRIBUTE_DIRECTORY
      dbg::detailed_log(lvl:1, msg:'Retrying file_exists check in directory mode...' + '\n');
      fh = CreateFile (
        file:path, 
        desired_access:GENERIC_READ, 
        file_attributes:FILE_ATTRIBUTE_DIRECTORY, 
        share_mode:FILE_SHARE_READ, 
        create_disposition:OPEN_EXISTING);

      if (fh[0] > 0)
      {
        dbg::detailed_log(lvl:1, msg:'dir mode file_exists check confirms path exists' + '\n');
        exists = TRUE;        
      }        
      else
      {
        dbg::detailed_log(lvl:1, msg:'dir mode file_exists check confirms path does not exist' + '\n');
        exists = FALSE;
      }
      CloseFile(handle:fh); 
    }
    else
      exists = FALSE;
  }
  else
    exists = NULL;

  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Return value ' + obj_rep(exists));
  return exists;
}

##
# gets file contents
#
# @param [path:string] absolute pathname of file to read
# @param [min_offset:int] The offset to start reading the file
# @param [max_bytes:int] The maxnumber of bytes to read from the file
# @remark this function assumes hotfix_check_fversion_init() has already been called and succeeded
#
# @return [array]  file content retrieval results.
# @remark
# The following information is returned:
# ```
#         ret['error'] = error code (see HCF_ constants)
#         ret['data'] = file contents, if it could be obtained
# ```
##
function hotfix_get_file_contents(path, min_offset, max_bytes)
{
  var match, share, file, login, pass, domain, r;
  var fh, size, offset, bytes_to_read, bytes_read, chunk, contents;
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Running get file contents for path ' + path);

  # Accept argument anonymously.
  if (isnull(path)) path = _FCT_ANON_ARGS[0];

  if (isnull(path) || (strlen(path) == 0))
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'path');
    return make_array('error', HCF_ERR);
  }

  if (!isnull(min_offset) && min_offset < 0)
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'min_offset');
    return make_array('error', HCF_ERR);
  }

  if (!isnull(max_bytes) && max_bytes <= 0)
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'max_bytes');
    return make_array('error', HCF_ERR);
  }

  match = pregmatch(string:path, pattern:"^([A-Za-z]):(.+)$");
  if (isnull(match))
  {
    dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
      'unable to parse pathname: ' + path);
    return make_array('error', HCF_PARSE);
  }

  share = match[1] + '$';
  file = match[2];

  login  = kb_smb_login();
  pass   = kb_smb_password();
  domain = kb_smb_domain();

  if ( hcf_init == 0 ) hotfix_check_fversion_init();
  r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if ( r != 1 ) return make_array('error', HCF_NOAUTH);

  fh = CreateFile(
    file:file,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (isnull(fh))
  {
    NetUseDel(close:FALSE);
    return make_array('error', HCF_NOENT);
  }

  size = GetFileSize(handle:fh);
  offset = 0;
  contents = '';

  # Restrict file reading based on function arguments
  if (!isnull(min_offset) && min_offset < size)
    offset = min_offset;
  
  if (!isnull(max_bytes) && offset + max_bytes < size)
    size = offset + max_bytes;

  while (offset < size)
  {
    if (size - offset < 16384)
      bytes_to_read = size - offset;
    else
      bytes_to_read = 16384;

    chunk = ReadFile(handle:fh, offset:offset, length:bytes_to_read);
    bytes_read = strlen(chunk);
    contents += chunk;
    offset += bytes_read;

    # bail out if the server did not send the number of bytes that were requested
    if (bytes_read != bytes_to_read)
    {
      CloseFile(handle:fh);
      NetUseDel(close:FALSE);
      return make_array('error', HCF_ERR);
      # never reached
    }
  }
  CloseFile(handle:fh);
  NetUseDel(close:FALSE);

  dbg::detailed_log(
    lvl:3,
    family:'SMB',
    src:FUNCTION_NAME,
    msg:'File contents',
    msg_details:{
      "Data":{"lvl":3, "value":obj_rep(contents)}
    });
  return make_array('error', HCF_OK, 'data', contents);
}


##
# gets a product version and saves it in the KB
#
# @param [path:string] absolute pathname of file to get product version for
#
# @return [array] product version retrieval results
# @remark
# The following information is returned:
# ```
#         ret['error'] = error code (see HCF_ constants)
#         ret['value'] = product version, if one could be obtained
# ```
##
function hotfix_get_pversion(path)
{
  var match, share, file, login, pass, domain, r, fh, str_v, v, v2, kb_name, ret;
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Running get pversion for path ' + path);

  if (isnull(path) || (strlen(path) == 0))
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'path');
    return make_array('error', HCF_ERR);
  }

  match = pregmatch(string:path, pattern:"^([A-Za-z]):(.+)$");
  if (isnull(match))
  {
    dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
      'unable to parse pathname: ' + path);
    return make_array('error', HCF_PARSE);
  }

  share = match[1] + '$';
  file = match[2];

  # Check if the product version is already in the KB
  kb_name = "SMB/ProductVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
  str_v = get_kb_item(kb_name);
  if (!isnull(str_v))
  {
    return make_array('error', HCF_OK, 'value', str_v);
    # never reached
  }

  # if not, connect to the target and get the product version
  login  = kb_smb_login();
  pass   = kb_smb_password();
  domain = kb_smb_domain();

  if ( hcf_init == 0 ) hotfix_check_fversion_init();
  r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if ( r != 1 ) return make_array('error', HCF_NOAUTH);

  fh = CreateFile(
    file:file,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (isnull(fh))
  {
    NetUseDel(close:FALSE);
    return make_array('error', HCF_NOENT);
  }

  v = GetProductVersion(handle:fh);
  CloseFile(handle:fh);
  NetUseDel(close:FALSE);

  if (!isnull(v))
    set_kb_item(name:kb_name, value:v);
  else
    return make_array('error', HCF_NOVER);

  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Returning pversion ' + obj_rep(v));
  return make_array('error', HCF_OK, 'value', v);
}


##
# gets a product name and saves it in the KB
#
# @param [path:string] absolute pathname of file to get product name for
#
# @return [array] product name retrieval results
# @remark
# The following information is returned:
# ```
#         ret['error'] = error code (see HCF_ constants)
#         ret['value'] = product name, if one could be obtained
# ```
##
function hotfix_get_pname(path)
{
  var match, share, file, login, pass, domain, r, fh, str_v, v, v2, kb_name, ret;
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Running get pname for path ' + path);

  if (isnull(path) || (strlen(path) == 0))
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'path');
    return make_array('error', HCF_ERR);
  }

  match = pregmatch(string:path, pattern:"^([A-Za-z]):(.+)$");
  if (isnull(match))
  {
    dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
      'unable to parse pathname: ' + path);
    return make_array('error', HCF_PARSE);
  }

  share = match[1] + '$';
  file = match[2];

  # Check if the product name is already in the KB
  kb_name = "SMB/ProductNames/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
  str_v = get_kb_item(kb_name);
  if (!isnull(str_v))
  {
    return make_array('error', HCF_OK, 'value', str_v);
    # never reached
  }

  # if not, connect to the target and get the product version
  login  = kb_smb_login();
  pass   = kb_smb_password();
  domain = kb_smb_domain();

  if ( hcf_init == 0 ) hotfix_check_fversion_init();
  r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if ( r != 1 ) return make_array('error', HCF_NOAUTH);

  fh = CreateFile(
    file:file,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (isnull(fh))
  {
    NetUseDel(close:FALSE);
    return make_array('error', HCF_NOENT);
  }

  v = GetProductName(handle:fh);
  CloseFile(handle:fh);
  NetUseDel(close:FALSE);

  if (!isnull(v))
    set_kb_item(name:kb_name, value:v);
  else
    return make_array('error', HCF_NOVER);

  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Returning pname ' + obj_rep(v));
  return make_array('error', HCF_OK, 'value', v);
}


##
# gets a file version and saves it in the KB
#
# @param [path:string] absolute pathname o3f file to get version for
# @param [locale:int] optional Windows Language Code Identifier for a locale (LCID)
# @remark this function assumes hotfix_check_fversion_init() has already been called and succeeded
#
# @return [array] file version retrieval result
# @remark
# The following information is returned:
# ```
#         ret['error'] = error code (see HCF_ constants)
#         ret['value'] = file version, as a list, if one could be obtained
#         ret['version'] = file version, as a string, if one could be obtained
# ```
##
function hotfix_get_fversion(path, locale)
{
  var match, share, file, login, pass, domain, r, fh, str_v, v, v2, kb_name, ret, v_string;
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Getting fversion for path ' + path);

  if (isnull(path) || (strlen(path) == 0))
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'path');
    return make_array('error', HCF_ERR);
  }

  match = pregmatch(string:path, pattern:"^([A-Za-z]):(.+)$");
  if (isnull(match))
  {
    dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
      'unable to parse pathname: ' + path);
    return make_array('error', HCF_PARSE);
  }

  share = match[1] + '$';
  file = match[2];

  # Check if the file version is already in the KB
  kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
  str_v = get_kb_item(kb_name);
  if (!isnull(str_v))
  {
    v2 = split( str_v, sep:'.', keep:0);
    v = make_list(v2[0], v2[1], v2[2], v2[3]);
    return make_array('error', HCF_OK, 'value', v, 'version', str_v);
    # never reached
  }

  # if not, connect to the target and get the file version
  login  = kb_smb_login();
  pass   = kb_smb_password();
  domain = kb_smb_domain();

  if ( hcf_init == 0 ) hotfix_check_fversion_init();
  r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if ( r != 1 ) return make_array('error', HCF_NOAUTH);

  fh = CreateFile(
    file:file,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (isnull(fh))
  {
    NetUseDel(close:FALSE);
    return make_array('error', HCF_NOENT);
  }

  v = GetFileVersion(handle:fh, locale:locale);
  CloseFile(handle:fh);
  NetUseDel(close:FALSE);

  if (!isnull(v))
  {
    v_string = v[0] + '.' + v[1] + '.' + v[2] + '.' + v[3];
    set_kb_item(name:kb_name, value:v_string);
    dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
      'Returning version string  ' + v_string);
    return make_array('error', HCF_OK, 'value', v, 'version', v_string);
  }
  else
    return make_array('error', HCF_NOVER);
}


##
# gets a file timestamp and saves it in the KB
#
# @param [path:string] absolute pathname of file to get product version for
#
# @return File timestamp retrieval result
# @remark
# The following information is returned:
# ```
#         ret['error'] = error code (see HCF_ constants)
#         ret['value'] = timestamp, if one could be obtained
# ```
##
function hotfix_get_timestamp(path)
{
  var match, share, file, login, pass, domain, r, fh, str_v, v, v2, kb_name, ret;
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Getting timestamp for path ' + path);

  if (isnull(path) || (strlen(path) == 0))
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'path');
    return make_array('error', HCF_ERR);
  }

  match = pregmatch(string:path, pattern:"^([A-Za-z]):(.+)$");
  if (isnull(match))
  {
    dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
      'unable to parse pathname: ' + path);
    return make_array('error', HCF_PARSE);
  }

  share = match[1] + '$';
  file = match[2];

  # Check if the product version is already in the KB
  kb_name = "SMB/Timestamps/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
  str_v = get_kb_item(kb_name);
  if (!isnull(str_v))
  {
    v2 = split( str_v, sep:'.', keep:0);
    v = make_list(v2[0], v2[1], v2[2], v2[3]);
    return make_array('error', HCF_OK, 'value', v);
    # never reached
  }

  # if not, connect to the target and get the product version
  login  = kb_smb_login();
  pass   = kb_smb_password();
  domain = kb_smb_domain();

  if ( hcf_init == 0 ) hotfix_check_fversion_init();
  r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if ( r != 1 ) return make_array('error', HCF_NOAUTH);

  fh = CreateFile(
    file:file,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (isnull(fh))
  {
    NetUseDel(close:FALSE);
    return make_array('error', HCF_NOENT);
  }

  ret = GetFileVersionEx(handle:fh);
  CloseFile(handle:fh);
  NetUseDel(close:FALSE);

  if (!isnull(ret) && !isnull(ret["dwTimeDateStamp"]))
    set_kb_item(name:kb_name, value:ret["dwTimeDateStamp"]);
  else
    return make_array('error', HCF_NOTIME);

  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Returning timestamp ' + ret["dwTimeDateStamp"]);
  return make_array('error', HCF_OK, 'value', ret["dwTimeDateStamp"]);
}


##
# Checks if the given file version is older than 'version'
#
# @param [file:string] filename of the binary to check
# @param [fversion:string] specifies a value to compare "version" to, instead of reading the version from the file (optional)
# @param [version:string] version to compare to
# @param [path:string] absolute path (including drive letter) of the directory containing "file"
# @param [min_version:string] a minimum cutoff 'version'. If 'version' is lower than this value, no check is performed (optional)
# @param [bulletin:string] Microsoft bulletin ID in the MSyy-xyz format
# @param [kb:string] Microsoft KB number (number only)
# @param [product:string] name of the product that "file" is a part of (optional)
# @param [channel:string] name of the Office 2016 Click-to-Run update channel e.g. 'Deferred' (optional)
# @param [channel_version:string] version number of the Office 2016 Click-to-Run channel e.g. '1509' (optional)
# @param [channel_product:string] name of the Office 2016 Click-to-Run product e.g. 'Word' (required if channel or channel_version is present)
# @param [rollup_check:string] used to format report output for smb_check_rollup.nasl
# @param [fversion_only:boolean] only check against the version in the fversion param (optional)
# @param [cpe:string] Platform enumeration of the affected software.
#
# @return [int] HCF_OK if not affected, HCF_OLDER if affected or an HCF error code.
# @remark HCF error codes are negative.
# @remark
#   The "cpe" parameter is required, but was recently added.  It would be nice if all legacy clients supplied it.
##
function hotfix_check_fversion(file, fversion, version, path, min_version, bulletin, kb, product, channel,
                               channel_version, channel_product, rollup_check, fversion_only, cpe)
{
  var login, pass, domain, share, r, handle, v, str_v,v2, i, kb_name, backslash, report, kb_channel;
  var kb_channels, kb_channel_version, matched_channel, kb_channel_versions, matched_channel_version;
  var sql_report, driveletter;

  dbg::detailed_log(lvl:2, family:'SMB', src:FUNCTION_NAME, msg:
    'Running hotfix_check_fversion for file ' + file + ' and version ' + version);

  if(empty_or_null(fversion_only))
    fversion_only = FALSE;

  if(hcf_init == 0 && !fversion_only)
  {
    if(hotfix_check_fversion_init() != HCF_OK)
      return HCF_OK;
  }

  if(fversion_only && empty_or_null(fversion))
    return HCF_ERR; # fversion_only set but no fversion specified

  if(isnull(path) || (strlen(path) == 0))
    path = hotfix_get_systemroot();

  if(isnull(path))
    return HCF_ERR;

  # Return HCF_OK if the check is for a different channel or channel_version
  if(channel)
  {
    if(!channel_product)
      return HCF_ERR; # channel was sent without channel_product
    if(tolower(channel_product) == "office")
      kb_channels = get_kb_list("SMB/Office/16.0/Channel");
    else kb_channels = get_kb_list("SMB/Office/"+channel_product+"/16.0/Channel");

    matched_channel = FALSE;
    foreach kb_channel (kb_channels)
    {
      if(empty_or_null(kb_channel))
        continue; # Product not found or doesn't have a Channel set
      if(tolower(kb_channel) == tolower(channel))
      {
        matched_channel = TRUE;
        break;
      }
    }

    if(!matched_channel)
      return HCF_OK;
  }
  if(channel_version)
  {
    if (!channel_product) return HCF_ERR; # channel_version was sent without channel_product
    if (tolower(channel_product) == "office") kb_channel_versions = get_kb_list("SMB/Office/16.0/ChannelVersion");
    else kb_channel_versions = get_kb_list("SMB/Office/"+channel_product+"/16.0/ChannelVersion");
    matched_channel_version = FALSE;
    foreach kb_channel_version (kb_channel_versions)
    {
      if(empty_or_null(kb_channel_version))
        continue; # Product not found or doesn't have a Channel set
      if(kb_channel_version == channel_version)
      {
        matched_channel_version = TRUE;
        break;
      }
    }

    if(!matched_channel_version)
      return HCF_OK;
  }

  share = ereg_replace(pattern:"^([A-Za-z]):.*", string:path, replace:"\1$");
  if(file[0] == "\" || (strlen(path) > 0 && path [ strlen(path) - 1 ] == "\"))
    backslash = "";
  else
    backslash = "\";

  file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1" + backslash + file);

  # Get the file version
  if(!isnull(fversion))
  {
    v2 = split(fversion, sep:'.', keep:FALSE);
    v = make_list(v2[0], v2[1], v2[2], v2[3]);
  }
  else
  {
    kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
    str_v = get_kb_item(kb_name);
    if ( ! isnull(str_v) )
    {
      v2 = split( str_v, sep:'.', keep:0);
      v = make_list(v2[0], v2[1], v2[2], v2[3]);
    }
  }
  if(isnull(v) && !fversion_only)
  {
    login  = kb_smb_login();
    pass   = kb_smb_password();
    domain = kb_smb_domain();

    r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
    if(r != 1)
      return HCF_NOAUTH;

    handle = CreateFile(file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                        share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
    if(isnull(handle))
      return HCF_NOENT;

    v = GetFileVersion(handle:handle);
    CloseFile(handle:handle);
    if(! isnull(v))
      set_kb_item(name:kb_name, value:v[0] + "." + v[1] + "." + v[2] + "." + v[3]);
    else
      return HCF_NOVER;
  }

  if(int(v[0]) == 0 && int(v[1]) == 0 && int(v[2]) == 0 && int(v[3]) == 0)
    return HCF_NOVER;

  if(!isnull(min_version))
  {
    min_version = split(min_version, sep:'.', keep:0);
    min_version = make_list(int(min_version[0]), int(min_version[1]), int(min_version[2]), int(min_version[3]));

    for(i = 0; i < max_index(v) ; i ++ )
    {
      if((v[i] < min_version[i]))
        return HCF_OK;
      else if(v[i] > min_version[i])
        break;
    }
  }

  version = split(version, sep:'.', keep:0);
  version = make_list(int(version[0]), int(version[1]), int(version[2]), int(version[3]));

  for(i = 0; i < max_index(version) ; i++)
  {
    if((v[i] < version[i]))
    {
      report = '\n';
      if (product)
        report += '  Product : ' + product + '\n';
      if (kb)
        report += '  KB : ' + kb + '\n';

      driveletter = (share - '$') + ':';
      if(!isnull(rollup_check))
        report += rollup_check;
      report +=
        '  - ' + driveletter + file + ' has not been patched.\n' +
        '    Remote version : ' + v[0] + '.' + v[1] + '.' + v[2] + '.' + v[3] + '\n' +
        '    Should be      : ' + version[0] + '.' + version[1] + '.' + version[2] + '.' + version[3] + '\n';

      sql_report = hotfix_make_sql_report(file:file, drive: driveletter);
      if(!empty_or_null(sql_report))
        report += sql_report;

      hotfix_add_report(
        report,
        bulletin:bulletin,
        kb:kb
      );
      dbg::detailed_log(lvl:2, family:'SMB', src:FUNCTION_NAME, msg:
        'File ' + file + ' check returned HCF_OLDER');

      if(!empty_or_null(cpe))
        hotfix_add_structured_report(kb:kb, path:file, version:v[0] + "." + v[1] + "." + v[2] + "." + v[3], cpe:cpe);
      return HCF_OLDER;
    }
    else if(v[i] > version[i])
      return HCF_OK;
  }

  return HCF_OK;
}


##
# Checks if the series of file locations are older than 'version'
#
# @param [file_name:string] of the binary to check
# @param [fversion:string] specifies a value to compare "version" to, instead of reading the version from the file (optional)
# @param [version:string] version to compare to
# @param [path_list:list] absolute paths (including drive letter) of the directories hold the containing "file"
# @param [min_version:string] a minimum cutoff 'version'. If 'version' is lower than this value, no check is performed (optional)
# @param [bulletin:string] Microsoft bulletin ID in the MSyy-xyz format
# @param [kb:string] Microsoft KB number (number only)
# @param [product:string] name of the product that "file" is a part of (optional)
# @param [channel:string] name of the Office 2016 Click-to-Run update channel e.g. 'Deferred' (optional)
# @param [channel_version:string] version number of the Office 2016 Click-to-Run channel e.g. '1509' (optional)
# @param [channel_product:string] name of the Office 2016 Click-to-Run product e.g. 'Word' (required if channel or channel_version is present)
# @param [rollup_check:string] used to format report output for smb_check_rollup.nasl
#
# @return [int] HCF_OK if not affected, HCF_OLDER if affected or an HCF error code.
# @remark HCF error codes are negative.
##
function hotfix_check_fversion_multipath(file_name, fversion, version, path_list, min_version, bulletin, kb, product, channel, channel_version, channel_product, rollup_check){
  var login, file, pass, domain, share, r, handle, v, str_v,v2, i, kb_name, backslash, report, kb_channel, kb_channels, kb_channel_version, matched_channel, kb_channel_versions, matched_channel_version, sql_report, driveletter;
  dbg::detailed_log(lvl:2, family:'SMB', src:FUNCTION_NAME, msg:
    'Running hotfix_check_fversions for file ' + file + ' and version ' + version + ' at paths ' + obj_rep(path_list));

  report = '';
  if ( hcf_init == 0 )
  {
    if ( hotfix_check_fversion_init() != HCF_OK ) return HCF_OK;
  }

  var path_valid = TRUE;

  ## Since there are multiple possible paths, we must check for each individually.
  ## Only returns an Error if NONE of them come up valid. This is overkill, rly.

  var paths_checked = make_list();

  foreach (var path in path_list)
  {
    if (empty_or_null(path))
      path = hotfix_get_systemroot();
    if (!empty_or_null(path))
    {
      append_element(var: paths_checked, value:path);
      path_valid = TRUE;
    }
  }
  if (!paths_checked)
    return HCF_ERR;

  # Return HCF_OK if the check is for a different channel or channel_version
  if (channel)
  {
    if (!channel_product) return HCF_ERR; # channel was sent without channel_product
    if (tolower(channel_product) == "office") kb_channels = get_kb_list("SMB/Office/16.0/Channel");
    else kb_channels = get_kb_list("SMB/Office/"+channel_product+"/16.0/Channel");
    matched_channel = FALSE;
    foreach kb_channel (kb_channels)
    {
      if (empty_or_null(kb_channel))
        continue; # Product not found or doesn't have a Channel set
      if (tolower(kb_channel) == tolower(channel))
      {
        matched_channel = TRUE;
        break;
      }
    }
    if (!matched_channel)
      dbg::detailed_log(lvl:2, family:'SMB', src:FUNCTION_NAME, msg:
        'Language file returned condition because non matched channel');
    if (!matched_channel) return HCF_OK;
  }
  if (channel_version)
  {
    if (!channel_product) return HCF_ERR; # channel_version was sent without channel_product
    if (tolower(channel_product) == "office") kb_channel_versions = get_kb_list("SMB/Office/16.0/ChannelVersion");
    else kb_channel_versions = get_kb_list("SMB/Office/"+channel_product+"/16.0/ChannelVersion");
    matched_channel_version = FALSE;
    foreach kb_channel_version (kb_channel_versions)
    {
      if (empty_or_null(kb_channel_version))
        continue; # Product not found or doesn't have a Channel set
      if (kb_channel_version == channel_version)
      {
        matched_channel_version = TRUE;
        break;
      }
    }
    if (!matched_channel_version)
      dbg::detailed_log(lvl:2, family:'SMB', src:FUNCTION_NAME, msg:
        'Language file returned condition because non matched channel versions');
    if (!matched_channel_version) return HCF_OK;
  }

  foreach (path in paths_checked)
  { v = NULL;
    dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
      'Checking potential path ' + path);
    file = file_name;
    share = ereg_replace(pattern:"^([A-Za-z]):.*", string:path, replace:"\1$");
    if ( file[0] == "\" || ( strlen(path) > 0 && path [ strlen(path) - 1 ] == "\") )
      backslash = "";
    else
      backslash = "\";

    file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1" + backslash + file);

    # Get the file version
    if ( !isnull(fversion))
    {
      v2 = split(fversion, sep:'.', keep:FALSE);
      v = make_list(v2[0], v2[1], v2[2], v2[3]);
    }
    else
    {
      kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
      str_v = get_kb_item(kb_name);
      if ( ! isnull(str_v) )
      {
        v2 = split( str_v, sep:'.', keep:0);
        v = make_list(v2[0], v2[1], v2[2], v2[3]);
      }
    }
    if (isnull(v))
    {
      login  = kb_smb_login();
      pass   = kb_smb_password();
      domain = kb_smb_domain();

      r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
      if ( r != 1 )
      {
        dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
          'Exited Loop due to missing Authentication');
        continue;
      }
      #return HCF_NOAUTH normally
      dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
        'Authentication Achieved');

      handle = CreateFile(file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
      if ( isnull(handle) )
      {
        dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
          'Exited Loop due to missing File (This should be common)');
        continue;
      }
      dbg::detailed_log(lvl:2, family:'SMB', src:FUNCTION_NAME, msg:
        'File Found');

      v = GetFileVersion(handle:handle);
      CloseFile(handle:handle);
      if ( ! isnull(v) )
      {
        set_kb_item(name:kb_name, value:v[0] + "." + v[1] + "." + v[2] + "." + v[3]);
        dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
          kb_name+' was set to ' + v[0] + '.' + v[1] + '.' + v[2] + '.' + v[3]);
      }
      else
      {
        dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
          'Exited Loop due to no version');
        continue;
      }
    }

    if ( int(v[0]) == 0 && int(v[1]) == 0 && int(v[2]) == 0 && int(v[3]) == 0 ) return HCF_NOVER;

    if ( !isnull(min_version) )
    {
      min_version = split(min_version, sep:'.', keep:0);
      min_version = make_list(int(min_version[0]), int(min_version[1]), int(min_version[2]), int(min_version[3]));
      for ( i = 0; i < max_index(v) ; i ++ )
      {
        if ( (v[i] < min_version[i]) ) return HCF_OK;
        else if (v[i] > min_version[i])  continue;
      }
    }
    version = split(version, sep:'.', keep:0);
    version = make_list(int(version[0]), int(version[1]), int(version[2]), int(version[3]));

    for ( i = 0; i < max_index(version) ; i ++ )
    {
      if ( (v[i] < version[i]) )
      {
        report = '\n';
        if (product)
          report += '  Product : ' + product + '\n';
        if (kb)
          report += '  KB : ' + kb + '\n';

        driveletter = (share - '$') + ':';
        if (!isnull(rollup_check))
          report += rollup_check;
        report +=
          '  - ' + driveletter + file + ' has not been patched.\n' +
          '    Remote version : ' + v[0] + '.' + v[1] + '.' + v[2] + '.' + v[3] + '\n' +
          '    Should be      : ' + version[0] + '.' + version[1] + '.' + version[2] + '.' + version[3] + '\n';

        sql_report = hotfix_make_sql_report(file:file, drive: driveletter);
        if(!empty_or_null(sql_report))
          report += sql_report;

        hotfix_add_report(
          report,
          bulletin:bulletin,
          kb:kb
        );
      }
      else if (v[i] > version[i]) return HCF_OK;
    }
  }
  if (report != '')
  {
    dbg::detailed_log(lvl:2, family:'SMB', src:FUNCTION_NAME, msg:
      'File ' + file + ' and version ' + version + ' returned HCF_OLDER');
    return HCF_OLDER;
  }
  if (!matched_channel_version)
    dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
      'Language file returned condition because no fail conditions reached');
  return HCF_OK;
}

##
# Expands the filepath for a check by the detected languages found on the host.
#
# @param [language_lists:list] List of languages supported on the target.
# @param [file_directory:string] Detected location of the target app.
#
# @return [list] List of file locations, one for each language.
##
function language_pack_iterate(language_lists, file_directory)
{
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Running language path iterate');
  if (empty_or_null(language_lists) || empty_or_null(file_directory))
  {
    audit(AUDIT_PATH_NOT_DETERMINED, 'language appropriate');
  }
  var language = '';
  var new_directories = make_list();
  foreach(var language_found in language_lists)
  {
    language = str_replace(string:file_directory, find:'*', replace:language_found);
    append_element(var:new_directories, value:language);
  }
  return new_directories;
}

##
# Determines whether a target is affected by a vulnerability based on detected details
# of the host and details of the security advisory.
#
# @param [os:string] Windows OS version number of target
# @param [sp:int] (optional) Windows service pack level
# @param [arch:string] (optional) CPU archtecture
# @param [os_build:string] (optional] Windows OS build number
# @param [file:string] File on target to check - usually directly related to the vulnerability
# @param [version:string] Version to compare to
# @param [dir:string] Location of the file to check relative to the supplied path
# @param [path:string] Location of the affected product in vulnerable installs.  This is an absolute path
# @param [min_version:string] First version that is vulnerable.
# @param [bulletin:string] Microsoft bulletin ID in the MSyy-xyz format
# @param [kb:string] Microsoft KB number (number only)
# @param [product:string] name of the product that "file" is a part of (optional)
# @param [channel:string] name of the Office 2016 Click-to-Run update channel e.g. 'Deferred' (optional)
# @param [channel_version:string] version number of the Office 2016 Click-to-Run channel e.g. '1509' (optional)
# @param [channel_product:string] Office 2016 Click-to-Run product name, e.g. 'Word' (required if channel or channel_version is present)
# @param [fversion:string] specifies a value to compare "version" to, instead of reading the version from the file (optional)
# @param [fversion_only:boolean] only check against the version in the fversion param (optional)
# @param [cpe:string] Platform enumeration of the affected software.
#
# @return [int] 1 if vulnerable, 0 otherwise
# @remark
#   The "cpe" parameter is required, but was recently added.  It would be nice if all legacy clients supplied it.
#   An OS cpe will be generated for those that don't, but it may not be accurate
##
function hotfix_is_vulnerable(os, sp, arch, os_build, file, version, dir, path, min_version, bulletin, kb, product,
                              channel, channel_product, channel_version, fversion, fversion_only, cpe)
{
  var r;
  var my_sp, my_os, my_arch, my_os_build;

  dbg::detailed_log(
    lvl:2,
    family:'SMB',
    src:FUNCTION_NAME,
    msg:'Running hotfix is vulnerable',
    msg_details:{
      "OS":{"lvl":3, "value":os},
      "SP":{"lvl":3, "value":sp},
      "OS Build":{"lvl":3, "value":os_build},
      "File":{"lvl":3, "value":file},
      "Version":{"lvl":3, "value":version},
      "Minimum Version":{"lvl":3, "value":min_version},
      "Directory":{"lvl":3, "value":dir},
      "Bulletin":{"lvl":3, "value":bulletin},
      "KB":{"lvl":3, "value":kb}
    });

  my_os = get_kb_item("SMB/WindowsVersion");
  my_sp = get_kb_item("SMB/CSDVersion");
  my_arch = get_kb_item("SMB/ARCH");
  my_os_build = get_kb_item("SMB/WindowsVersionBuild");
  if(my_sp)
  {
    my_sp = ereg_replace(pattern:".*Service Pack ([0-9]).*", string:my_sp, replace:"\1");
    my_sp = int(my_sp);
  }
  else my_sp = 0;

  if(os >!< my_os ) return 0;
  if(! isnull(sp) && my_sp != sp ) return 0;
  if(! isnull(arch) && my_arch != arch ) return 0;
  if(! isnull(os_build) && my_os_build != os_build ) return 0;

  r = hotfix_check_fversion(file:dir + "\" + file, version:version, path:path, min_version:min_version,
                            bulletin:bulletin, kb:kb, product:product, channel:channel,
                            channel_product:channel_product, channel_version:channel_version, fversion:fversion,
                            fversion_only:fversion_only, cpe:cpe);
  if(r == HCF_OLDER)
  {
    smb_hf_add(os:os, sp:sp, file:file, version:version, bulletin:bulletin, kb:kb);
    dbg::detailed_log(lvl:2, family:'SMB', src:FUNCTION_NAME, msg:
      'Returning 1, it is vuln');
    return 1;
  }
  else
  {
    dbg::detailed_log(lvl:2, family:'SMB', src:FUNCTION_NAME, msg:
      'Returning 0, it is not vuln');
    return 0;
  }
}


##
# Checks if the host has the given rollup applied
#
# @param [os:string] os version that is being checked
# @param [sp:int] sp of the host that is being checked
# @param [os_build:string] build edition of windows 10 to be checked
# @param [rollup_date:string] MM_YYYY formatted string of the PT rollup
# @param [bulletin:string] bulletin to include in the report output
# @param [rollup_kb_list:list] kbs related to the monthly rollup
# @param [arch:string] architecture to check against
# @return [boolean]
#   TRUE if vulnerable (rollup not applied)
#   FALSE if rollup is applied or host is not applicable (ex: wrong os)
##
function smb_check_rollup(os, sp, os_build, rollup_date, bulletin, rollup_kb_list, arch)
{
  var host_rollup, key_segs, new_rollup;
  var my_sp, my_os, my_arch, my_os_build;
  var my_cpe, my_file, my_file_ver;
  var kb, report, file_report, int_var;
  dbg::detailed_log(
    lvl:2,
    family:'SMB',
    src:FUNCTION_NAME,
    msg:'Running smb check rollup',
    msg_details:{
      "OS":{"lvl":3, "value":os},
      "SP":{"lvl":3, "value":sp},
      "OS Build":{"lvl":3, "value":os_build},
      "Rollup Date":{"lvl":3, "value":rollup_date},
      "Bulletin":{"lvl":3, "value":bulletin},
      "Rollup KB List":{"lvl":3, "value":obj_rep(rollup_kb_list)}
    });

  # Verify host constraints
  my_os = get_kb_item("SMB/WindowsVersion");
  my_sp = get_kb_item("SMB/CSDVersion");
  my_arch = get_kb_item("SMB/ARCH");
  my_os_build = get_kb_item("SMB/WindowsVersionBuild");
  my_cpe = get_kb_item("installed_os/local/SMB/0/cpe/v23");
  my_file = get_kb_item("smb_rollup/" + rollup_date + "/file");
  my_file_ver = get_kb_item("smb_rollup/" + rollup_date + "/file_ver");
  if ( my_sp )
  {
    my_sp = ereg_replace(pattern:".*Service Pack ([0-9]).*", string:my_sp, replace:"\1");
    my_sp = int(my_sp);
  }
  else my_sp = 0;

  if ( os >!< my_os ) return FALSE;
  if ( !isnull(sp) && my_sp != sp ) return FALSE;
  if ( !isnull(arch) && my_arch != arch ) return FALSE;
  if ( !isnull(os_build) && my_os_build != os_build ) return FALSE;

  # Ensure rollups were enumerated successfully
  smb_check_rollup_done = get_kb_item("smb_check_rollup/done");
  if (!smb_check_rollup_done) return FALSE;

  # Check for oneoff update
  if(get_kb_item("smb_rollup/" + rollup_date) == 1) return FALSE;

  # Get the latest cumulative rollup for the host
  host_rollup = get_kb_item('smb_rollup/latest');

  # If none, host does not have a cumulative rollup applied
  if (isnull(host_rollup) || host_rollup == 'none')
  {
    report = 'The remote host is missing one of the following rollup KBs : ';
    foreach kb (rollup_kb_list)
    {
      report += '\n  - ' + kb;
      hotfix_add_report(report, bulletin:bulletin, kb:kb);
      report = '';
      hotfix_add_structured_report(kb:kb, path:my_file, version:my_file_ver, cpe:my_cpe);
    }

    file_report = get_kb_item("smb_rollup/version_report/"+rollup_date);
    if (!empty_or_null(file_report))
      hcf_report += '\n\n'+ file_report;
    dbg::detailed_log(lvl:2, family:'SMB', src:FUNCTION_NAME, msg:
      'Returning 1, it is vuln');

    return TRUE;
  }
  # 09_2020, 09_2020_2, 09_2020_02_1, etc
  if (host_rollup !~ "^[0-9]+_[0-9][0-9_]*$" || rollup_date !~ "^[0-9]+_[0-9][0-9_]*$")
  {
    dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
      'Rollup strings failed regex check - host_rollup: ' +
      obj_rep(host_rollup) + ' rollup_date: ' +  obj_rep(rollup_date));
    return FALSE;
  }
  key_segs = split(host_rollup, sep:'_', keep:FALSE);
  int_var = key_segs[0];
  key_segs[0] = key_segs[1];
  key_segs[1] = int_var;
  host_rollup = join(key_segs, sep:'.');

  key_segs = split(rollup_date, sep:'_', keep:FALSE);
  int_var = key_segs[0];
  key_segs[0] = key_segs[1];
  key_segs[1] = int_var;
  new_rollup = join(key_segs, sep:'.');

  # Determine if host rollup >= supplied rollup
  if (ver_compare(ver:host_rollup, fix:new_rollup, strict:FALSE) >= 0)
  {
    dbg::detailed_log(lvl:2, family:'SMB', src:FUNCTION_NAME, msg:
      'Returning 0, it is not vuln');
    return FALSE;
  }
  else
  {
    report = 'The remote host is missing one of the following rollup KBs : ';
    foreach kb (rollup_kb_list)
    {
      report += '\n  - ' + kb;
      hotfix_add_report(report, bulletin:bulletin, kb:kb);
      report = '';
      hotfix_add_structured_report(kb:kb, path:my_file, version:my_file_ver, cpe:my_cpe);
    }
    file_report = get_kb_item("smb_rollup/version_report/" +rollup_date);

    if (!empty_or_null(file_report))
      hcf_report += '\n\n'+ file_report;

    hotfix_add_report(report, bulletin:bulletin, kb:kb);
    dbg::detailed_log(lvl:2, family:'SMB', src:FUNCTION_NAME, msg:
      'Returning 1, it is vuln');
    return TRUE;
  }
}

##
# Checks if the host has the given .NET rollup applied
#
# @param [rollup_date:string] MM_YYYY formatted string of the PT .NET rollup
# @param [dotnet_ver:string] .NET version to check against
# @return [boolean]
#   TRUE if vulnerable (rollup not applied)
#   FALSE if rollup is applied or host is not applicable (ex: wrong os)
##
function smb_check_dotnet_rollup(rollup_date, dotnet_ver)
{
  var kb_base = "smb_dotnet_rollup/" + rollup_date + "/" + dotnet_ver;
  var not_inst = get_kb_list(kb_base + "/not_inst/*");

  var bulletin, bulletin_yr, bulletin_mo;
  var report, file_report, kb;
  var path, version, cpe;

  path = get_kb_item(kb_base + "/file");
  version = get_kb_item(kb_base + "/file_ver");
  cpe = "cpe:2.3:a:microsoft:.net_framework:" + dotnet_ver + ":*:*:*:*:*:*:*";

  dbg::detailed_log(
    lvl:2,
    family:'SMB',
    src:FUNCTION_NAME,
    msg:'Running smb check dotnet rollup',
    msg_details:{
      "Dotnet Version":{"lvl":3, "value":dotnet_ver},
      "Rollup Date":{"lvl":3, "value":rollup_date}
    });
  bulletin = split(rollup_date, sep:'_', keep:FALSE);
  bulletin_mo = bulletin[0];
  bulletin_yr = bulletin[1];
  if (strlen(bulletin_yr) == 4) bulletin_yr = substr(bulletin_yr, 2);

  smb_check_dotnet_rollup_done = get_kb_item("smb_check_dotnet_rollup/done");
  if (!smb_check_dotnet_rollup_done) return FALSE;

  var host_rollup = get_kb_item('smb_dotnet_rollup/' + dotnet_ver + '/latest');

  if (get_kb_item("smb_dotnet_rollup/" + rollup_date + "/error_code") == HCF_NOENT) return FALSE;

  if (empty_or_null(not_inst)) return FALSE;

  if (isnull(host_rollup) || host_rollup == 'none')
  {
    report = 'Microsoft .NET Framework ' + dotnet_ver + '\n';
    report += 'The remote host is missing one of the following rollup KBs : ';
    foreach kb (keys(not_inst))
    {
      report += '\n';
      if (kb =~ "\/cum$")
        report += '\nCumulative\n  - ' + not_inst[kb];
      if (kb =~ "\/sec$")
        report += '\nSecurity Only\n  - ' + not_inst[kb];

      # e.g. MS17-04
      bulletin = 'MS'+bulletin_yr+'-'+bulletin_mo;
      hotfix_add_report(report, bulletin:bulletin, kb:not_inst[kb]);

      replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
      report = '';
      hotfix_add_structured_report(kb:not_inst[kb], path:path, version:version, cpe:cpe);
    }
    file_report = get_kb_item("smb_dotnet_rollup/version_report/"+rollup_date+"/"+dotnet_ver);
    if (!empty_or_null(file_report))
      hcf_report += '\n\n'+ file_report +'\n';
    dbg::detailed_log(lvl:2, family:'SMB', src:FUNCTION_NAME, msg:
      'Returning 1, it is vuln');
    return TRUE;
  }
  host_rollup = split(host_rollup, sep:'_');
  var h_month = int(host_rollup[0]);
  var h_year = int(host_rollup[1]);
  var new_rollup = split(rollup_date, sep:'_');
  var n_month = int(new_rollup[0]);
  var n_year = int(new_rollup[1]);

  # Determine if host rollup >= supplied rollup
  if (h_year > n_year || (h_year == n_year && h_month >= n_month)) return FALSE;
  if (h_year < n_year || (h_year == n_year && h_month < n_month))
  {
    report = 'Microsoft .NET Framework ' + dotnet_ver + '\n';
    report += 'The remote host is missing one of the following rollup KBs : ';
    foreach kb (keys(not_inst))
    {
      report += '\n';
      if (kb =~ "\/cum$")
        report += '\nCumulative\n  - ' + not_inst[kb];
      if (kb =~ "\/sec$")
        report += '\nSecurity Only\n  - ' + not_inst[kb];

      bulletin = 'MS'+bulletin_yr+'-'+bulletin_mo;
      hotfix_add_report(report, bulletin:bulletin, kb:not_inst[kb]);
      replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
      report = '';
      hotfix_add_structured_report(kb:not_inst[kb], path:path, version:version, cpe:cpe);
    }

    file_report = get_kb_item("smb_dotnet_rollup/version_report/"+rollup_date+"/"+dotnet_ver);
    if (!empty_or_null(file_report))
      hcf_report += '\n\n'+ file_report+'\n';
    dbg::detailed_log(lvl:2, family:'SMB', src:FUNCTION_NAME, msg:
      'Returning 1, it is vuln');
    return TRUE;
  }

  dbg::detailed_log(lvl:2, family:'SMB', src:FUNCTION_NAME, msg:
    'Returning 0, it is not vuln');
  return FALSE;
}


##
# Checks the version of an Office Product
#
# @param [product:string] The product to check
# @param [display_name:string] An optional display name to use for reporting
# @param [checks:array] checks to perform
# @param [bulletin:string] The bulletin that is being checked
#
# @return [boolean|NULL] TRUE if the host is vulnerable
#         FALSE if the host is not affected
#         NULL otherwise
##
function hotfix_check_office_product(product, display_name, checks, bulletin)
{
  var office_ver_mapping, spmatch, info, vuln, disp_product;
  var check, install, version, ver, i, installs, path, sp, channel, channel_version, sp_kb_item;
  var channels, channel_versions, install_path, path64, key;
  vuln = FALSE;

  dbg::detailed_log(
    lvl:2,
    family:'SMB',
    src:FUNCTION_NAME,
    msg:'Running office product checks',
    msg_details:{
      "Product":{"lvl":3, "value":product},
      "Display Name":{"lvl":3, "value":display_name},
      "Bulletin":{"lvl":3, "value":bulletin}
    });
  office_ver_mapping = make_array(
    "8.0", "97",
    "9.0", "2000",
    "10.0", "XP",
    "11.0", "2003",
    "12.0", "2007",
    "14.0", "2010",
    "15.0", "2013",
    "16.0", "2016"
  );
  if (isnull(product))
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'product');
    return NULL;
  }
  if (isnull(checks))
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'checks');
    return NULL;
  }
  if (isnull(bulletin))
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'bulletin');
    return NULL;
  }

  installs = get_kb_list("SMB/Office/"+product+"/*/ProductPath");
  if (!isnull(installs))
  {
    foreach install (keys(installs))
    {
      info = '';
      version = install - ('SMB/Office/'+product + "/");
      version = version - '/ProductPath';
      path = installs[install];

      # b64 install path 
      install_path = IF_base64(path);
      path64 = install_path[1];
  
      ver = split(version, sep:'.', keep:FALSE);
      ver = ver[0] + '.' + ver[1];
      if (checks[ver])
      {
        # If there is only one check, convert it to a nested list
        # so we are always looping over a list.
        if (!is_list(checks[ver]))
        {
          checks[ver] = make_nested_list(checks[ver]);
        }
        # There should only ever be one Channel/ChannelVersion key per b64 path but call as list
        if (ver == "16.0") channels = get_kb_list("SMB/Office/"+product+"/16.0/specs/"+path64+"/Channel");
        # verify and assign channel
        foreach (key in keys(channels))
        {
          if (!empty_or_null(channels[key]))
            channel = channels[key];
          else channel = NULL;
        }
        if (ver == "16.0") channel_versions = get_kb_list("SMB/Office/"+product+"/16.0/specs/"+path64+"/ChannelVersion");
        # verify and assign channel_version
        foreach (key in keys(channel_versions))
        {
          if (!empty_or_null(channel_versions[key]))
            channel_version = channel_versions[key];
          else channel_version = NULL;  
        }

        foreach check (checks[ver])
        {

          if (check["min_ver"] && (ver_compare(ver:version, fix:check["min_ver"]) < 0))
            continue;

          # If a channel or channel_version is included in the check, the target product channel or channel_version must exist and match
          if (check["channel"] && (empty_or_null(channel) || (tolower(channel) != tolower(check["channel"]))))
            continue;
          if (check["channel_version"] && (empty_or_null(channel_version) || (tolower(channel_version) != tolower(check["channel_version"]))))
            continue;

          if (office_ver_mapping[ver])
          {
            sp_kb_item = 'SMB/Office/'+office_ver_mapping[ver]+'/SP';
            if (product == 'Project') sp_kb_item = 'SMB/'+product+'/'+office_ver_mapping[ver]+'/SP';
            if (product == 'Visio') sp_kb_item = 'SMB/Office/'+product+'/'+office_ver_mapping[ver]+'/SP';
            sp = get_kb_item(sp_kb_item);

          }
          else return FALSE;
          # Check if the Office SP is the expected SP
          if (!isnull(check["sp"]))
          {
            if (typeof(check["sp"]) == "array" && is_list(check["sp"]))
            {
              for (i=0; i < max_index(check["sp"]); i++)
              {
                if (int(sp) == int(check["sp"][i]))
                {
                  spmatch = TRUE;
                  break;
                }
              }
            }
            else
            {
              if (int(sp) == int(check["sp"]))
                spmatch = TRUE;
            }
          }
          else
            spmatch = TRUE;
          if (spmatch && (ver_compare(ver:version, fix:check["version"]) < 0))
          {
            if (check['channel'] == 'LTSC 2021' || check['channel'] == '2021 Retail')
              info =  '\n  Product           : ' + product + " " + check['channel'];
            else if (isnull(display_name))
              info =  '\n  Product           : ' + product + " " + office_ver_mapping[ver];
            else
              info =  '\n  Product           : ' + display_name + " " +office_ver_mapping[ver];

            info +=
              '\n  - ' + path + " has not been patched." +
              '\n    Remote version    : ' + version +
              '\n    Fixed version     : ' + check["version"] + '\n';
            vuln = TRUE;
            hotfix_add_report(info, bulletin:bulletin, kb:check["kb"]);
          }
        }
      }
    }
  }
  dbg::detailed_log(lvl:2, family:'SMB', src:FUNCTION_NAME, msg:
    'Returning ' + vuln);
  return vuln;
}

##
# Tests a share name to see if it is accessible to the scan.
# 
# @param [share:string] (optional) The share to test, if none is provided the system root 
#                                  administrative share is checked.
#
# @reeturn [boolean] 1 - the share is accessible, 0 - the share is not
##
function is_accessible_share(share)
{
  var login, pass, domain, r;
  dbg::detailed_log(lvl:2, family:'SMB', src:FUNCTION_NAME, msg:
    'Checking if share ' + share + ' is accessible');

  if (isnull(share))
  {
    share = hotfix_get_systemroot();
    if ( ! share ) return 0;
    share = ereg_replace(pattern:"^([A-Za-z]):.*", string:share, replace:"\1$");
  }

  r =  get_kb_item("SMB/AccessibleShare/" + share);
  if ( r == HCF_UNACCESSIBLE_SHARE ) return 0; # Not Accessible
  else if ( r == HCF_ACCESSIBLE_SHARE ) return 1;

  login  = kb_smb_login();
  pass   = kb_smb_password();
  domain = kb_smb_domain();

  if ( hcf_init == 0 ) hotfix_check_fversion_init();
  r = NetUseAdd(login:login, password:pass, domain:domain, share:share);

  if ( r != 1 )
  {
    hotfix_check_fversion_end();
    r = HCF_UNACCESSIBLE_SHARE;
  }
  else
  {
   NetUseDel(close:FALSE);
   r = HCF_ACCESSIBLE_SHARE;
  }

  replace_kb_item(name:"SMB/AccessibleShare/" + share, value:r);

  if (r == HCF_ACCESSIBLE_SHARE)
    return 1;
  else
    return 0;
}


##
# Converts a Windows file path to the name of the administrative share for the root drive.
#
# @param [path:string] File path to convert
# @return [string] A Windows administrative share name
##
function hotfix_path2share(path)
{
  return ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
}

##
# Handles errors from hotfix functions
#
# @param [error_code:int] Value of error code returned from hotfix function.
# @param [file:string] Required.  File path to the file you are checking.
# @param [appname:string] (optional) If the checked file doesn't exist, this parameter
#                will allow audit() to be called with AUDIT_UNINST and the name
#                of the application.  Useful for installation detection plugins.
#
# @remark If checking more than one file in a loop, setting exit_on_fail
#
# @return [boolean|string] If no error, the function returns NULL.  If there is an error,
#         the function will trigger an exit or return an error string
#         depending on type of error and the value of exit_on_fail
##
function hotfix_handle_error(error_code, file, appname, exit_on_fail)
{
  var fatal_error, match, share;

  # the fatal errors below should not happen unless there is a plugin bug
  fatal_error = '';
  if(isnull(error_code))
    fatal_error = 'missing \'error_code\' argument to hotfix_handle_error()';
  if(isnull(file))
    fatal_error = 'missing \'file\' argument to hotfix_handle_error()';

  if(fatal_error != '')
  {
    hotfix_check_fversion_end();
    dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
      'Fatal error detected: ' + fatal_error);
    exit(1, fatal_error);
  }

  # if everything is OK, don't return anything
  if(error_code == HCF_OK)
    return FALSE;

  if(isnull(exit_on_fail)) exit_on_fail = FALSE;

  if (error_code == HCF_PARSE)
  {
    dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
      'Unable to parse pathname \'' + file + '\'.');
    if(!exit_on_fail)
    {
      return 'Unable to parse pathname \'' + file + '\'.';
    }
    else
    {
      hotfix_check_fversion_end();
      if(isnull(appname))
      {
        exit(1, 'Unable to parse pathname \'' + file + '\'.');
      }
      else
        audit(AUDIT_UNINST, appname);
    }
  }
  else if (error_code == HCF_NOENT)
  {
    dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
      'The file \'' + file + '\' does not exist.');
    if(!exit_on_fail)
      return 'The file \'' + file + '\' does not exist.';
    else
    {
      hotfix_check_fversion_end();
      if(isnull(appname))
      {
        exit(1, 'The file \'' + file + '\' does not exist.');
      }
      else
        audit(AUDIT_UNINST, appname);
    }
  }
  else if (error_code == HCF_CONNECT)
  {
    dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
      'Error connecting to SMB service on remote host.');
    if(!exit_on_fail)
      return 'Error connecting to SMB service on remote host.';
    else
    {
      hotfix_check_fversion_end();
      exit(1, 'Error connecting to SMB service on remote host.');
    }
  }
  else if (error_code == HCF_UNACCESSIBLE_SHARE)
  {
    dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
      'Failed to connect to the \'' + share + '\' share.');
    share = hotfix_path2share(path:file);
    if(!exit_on_fail)
      return 'Failed to connect to the \'' + share + '\' share.';
    else
    {
      hotfix_check_fversion_end();
      audit(AUDIT_SHARE_FAIL, share);
    }
  }
  else if (error_code == HCF_NOAUTH)
  {
    dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
      "Error accessing '" + file + "'. Invalid credentials or share doesn't exist.");
    if(!exit_on_fail)
      return "Error accessing '" + file + "'. Invalid credentials or share doesn't exist.";
    else
    {
      hotfix_check_fversion_end();
      exit(1, "Error accessing '" + file + "'. Invalid credentials or share doesn't exist.");
    }
  }
  else if (error_code == HCF_NOVER)
  {
    dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
      'Failed to get the file version of \'' + file + '\'.');
    if(!exit_on_fail)
      return 'Failed to get the file version of \'' + file + '\'.';
    else
    {
      hotfix_check_fversion_end();
      audit(AUDIT_VER_FAIL, file);
    }
  }
  else if (error_code == HCF_NOTIME)
  {
    dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
      "Failed to get the timestamp of '" + file + "'.");
    if(!exit_on_fail)
      return 'Failed to get the timestamp of \'' + file + '\'.';
    else
    {
      hotfix_check_fversion_end();
      exit(1, "Failed to get the timestamp of '" + file + "'.");
    }
  }
  else
  {
    dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
      "Unknown error when attempting to access '" + file + "'.");
    if(!exit_on_fail)
      return 'Unknown error when attempting to access \'' + file + '\'.';
    else
    {
      hotfix_check_fversion_end();
      exit(1, "Unknown error when attempting to access '" + file + "'.");
    }
  }
}

##
# Appends value to path properly separated by "/"
#
# @param [path:string] Path to append to
# @param [value:string] Value to append to path
#
# @return [string] Appended path string
##
function hotfix_append_path(path, value)
{
  if(isnull(path) || path == '')
  {
    dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
      'no path specified');
    exit(1, 'no path specified in hotfix_append_path()');
  }
  if(isnull(value) || value == '')
  {
    dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
      'no value specified');
    exit(1, 'no value specified in hotfix_append_path()');
  }

  # force path to end with a \
  if(path[strlen(path) - 1] != "\")
    path = path + "\";

  # value shouldn't begin with \
  if (value[0] == "\")
    value = substr(value, 1);

  return path + value;
}

##
# WinSxS file checks
#
# @param [dir:string]  WinSxS directory
# @param [os:string]  Operating System
# @param [files:list] Files to check
# @param [versions:list] Vulnerable versions (LDR/GDR)
# @param [max_versions:list] Max versions
# @param [bulletin:string]  Bulletin that is being checked
# @param [kb:string]  KB that is being checked
# @param [key:string]  Registry in case we couldn't get all file versions
# @param [session:array] Existing SMB session values
# @param [none_found:boolean] Set to TRUE if a WinSxS file was found, FALSE otherwise
# @return [boolean|NULL] 1 if vulnerable
#         0 if not vulnerable
#         NULL if the function was called incorrectly
##
function hotfix_check_winsxs(dir, arch, files, os, sp, versions, max_versions, bulletin, kb, key, session, &none_found)
{
  var patched, report, file, fname, vulnfile;
  var my_os, my_arch, my_sp;
  var rootfile, ver, i, winsxs;
  var highestver, lowestcutoff;
  var null_ver, r, handle, key_h;
  var login, pass, domain;

  dbg::detailed_log(
    lvl:2,
    family:'SMB',
    src:FUNCTION_NAME,
    msg:'Running WinSxS checks',
    msg_details:{
      "OS":{"lvl":3, "value":os},
      "SP":{"lvl":3, "value":sp},
      "Versions":{"lvl":3, "value":obj_rep(versions)},
      "Max Versions":{"lvl":3, "value":obj_rep(max_versions)},
      "Bulletin":{"lvl":3, "value":bulletin},
      "KB":{"lvl":3, "value":kb}
    });

  rootfile = hotfix_get_systemroot();
  my_os = get_kb_item("SMB/WindowsVersion");
  my_sp = get_kb_item("SMB/CSDVersion");
  my_arch = get_kb_item("SMB/ARCH");
  none_found = FALSE;
  if (my_sp)
  {
    my_sp = ereg_replace(pattern:".*Service Pack ([0-9]).*", string:my_sp, replace:"\1");
    my_sp = int(my_sp);
  }
  else my_sp = 0;

  if (os >!< my_os) return 0;
  if (!isnull(sp) && my_sp != sp) return 0;
  if (!isnull(arch) && my_arch != arch) return 0;

  if (max_index(max_versions) && (max_index(versions) != max_index(max_versions))) return 0;
  if (!isnull(files) && max_index(files) > 0)
  {
    patched = FALSE;
    highestver = [];
    vulnfile = FALSE;
    null_ver = '';

    # When the patched DLL is added to the SxS dir, the older (vulnerable)
    # versions of the file remain in the SxS dir. This checks to see if there is
    # _any_ file that has been patched
    foreach file (files)
    {
      if (!fname) fname = ereg_replace(pattern:'^\\\\.*\\\\(.*)$', string:file, replace:"\1");

      ver = _winsxs_get_file_version(file);

      # We should always get a file version. If we don't we need to note it.
      if (isnull(ver))
      {
         null_ver += '  - ' + file + '\n';
         continue;
      }
      # Track the highest version installed so we can report on
      # it if the host is vulnerable

      for (i=0; i < max_index(versions); i++)
      {
        if (isnull(highestver[i]))
          highestver[i] = '0.0.0.0';

        # If an empty string is passed as the value for max_versions[i]
        # don't check the ceiling version
        if (isnull(max_versions) || !max_versions[i])
        {
          if (_winsxs_version_cmp(a:ver, b:versions[i]) >= 0)
          {
            patched = TRUE;
            break;
          }
          else
          {
            vulnfile = TRUE;
            if (ver_compare(ver:ver, fix:highestver[i]) >= 0)
              highestver[i] = ver;
          }
        }
        else
        {
          if (_winsxs_version_cmp(a:ver, b:versions[i]) >= 0)
          {
            if (_winsxs_version_cmp(a:ver, b:max_versions[i]) < 0)
            {
              patched = TRUE;
              break;
            }
          }
          else
          {
            vulnfile = TRUE;
            if (ver_compare(ver:ver, fix:highestver[i]) >= 0)
              highestver[i] = ver;
          }
        }
      }
    }

    # We want to check the registry for the KB if we got a null version
    # and we suspect the host may not be patched
    if(!empty(null_ver) && !patched)
    {
      if(isnull(key))
      {
        report =
        '\nNessus does not have a registry key to check for KB' + kb + '.\n' +
        '\nNessus did not find a version for the following files :\n' +
        null_ver;
        hotfix_add_report(report, bulletin:bulletin, kb:kb);
        return 1;
      }

      # Now we will need to open to the IPC share to check the registry
      login  = kb_smb_login();
      pass   = kb_smb_password();
      domain = kb_smb_domain();

      NetUseDel(close:FALSE); # close existing SMB share
      r = NetUseAdd(login:login, password:pass, domain:domain, share:'IPC$');
      var ret = NULL;
      if ( r != 1 )
      {
        report =
        '\nNessus was unable to connect to the $IPC share.\n' +
        '\nNessus did not find a version for the following files :\n' +
        null_ver;
        hotfix_add_report(report, bulletin:bulletin, kb:kb);
        ret = 1;
      }

      if (isnull(ret))
      {
        handle = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
        if(isnull(handle))
        {
          report =
          '\nNessus was unable to open a connection to the HKLM hive.\n' +
          '\nNessus did not find a version for the following files :\n' +
          null_ver;
          hotfix_add_report(report, bulletin:bulletin, kb:kb);
          ret = 1;
        }
      }

      if (isnull(ret))
      {
        key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
        if(isnull(key_h))
        {
          RegCloseKey(handle:key_h);
          RegCloseKey(handle:handle);
          report =
          '\nAccording to the registry, KB' + kb + ' is missing.\n' +
          '\nNessus did not find a version for the following files :\n' +
          null_ver;
          hotfix_add_report(report, bulletin:bulletin, kb:kb);
          ret = 1;
        }
        else
        {
          RegCloseKey(handle:key_h);
          RegCloseKey(handle:handle);
          ret = 0;
        }
      }

      if (!empty_or_null(session))
      {
        NetUseDel(close:FALSE); # close IPC$ share
        # restore existing SMB session
        NetUseAdd(
          login    : session['login'],
          password : session['password'],
          domain   : session['domain'],
          share    : session['share']
        );
      }
      dbg::detailed_log(lvl:2, family:'SMB', src:FUNCTION_NAME, msg:
        'Returning ' + ret);
      if (!isnull(ret)) return ret;
    }

    if (vulnfile && !patched)
    {
      lowestcutoff = '0.0.0.0';
      # Determine the appropriate cutoff value
      for (i=0; i < max_index(versions); i++)
      {
        if (ver_compare(ver:highestver[i], fix:versions[i]) < 0 && ('0.0.0.0' >< lowestcutoff || ver_compare(ver:versions[i], fix:lowestcutoff) < 0))
        {
          lowestcutoff = versions[i];
        }
      }

      winsxs = rootfile + "\WinSxS";
      report =
        '\n' +
        'KB : ' + kb + '\n' +
        'None of the versions of \''+fname+'\' under '+winsxs+'\n' +
        'have been patched.\n' +
        '  Fixed version : ' + lowestcutoff + '\n';
      hotfix_add_report(report, bulletin:bulletin, kb:kb);
      dbg::detailed_log(lvl:2, family:'SMB', src:FUNCTION_NAME, msg:
        'Returning 1, it is vuln');
      return 1;
    }

    if (!patched && !vulnfile)
      none_found = TRUE;
  }
  dbg::detailed_log(lvl:2, family:'SMB', src:FUNCTION_NAME, msg:
    'Returning 0, it is not vuln');
  return 0;
}

##
# Lists directories or files in a directory
#
# @param [basedir:string] Starting directory
# @param [level:string] Current traversal depth
# @param [dir_pat:string] Regular expression for filtering subdirectories to traverse
# @param [file_pat:string] Regular expression for filtering file names to return
#
# @return [list|NULL] Found directories / files
##
function list_dir(basedir, level, dir_pat, file_pat, max_recurse, share)
{
  var contents, ret, subdirs, subsub;
  var login, pass, domain, r;

  dbg::detailed_log(
    lvl:3,
    family:'SMB',
    src:FUNCTION_NAME,
    msg:'listing directory',
    msg_details:{
      "Basedir":{"lvl":3, "value":basedir},
      "Directory Pattern":{"lvl":3, "value":dir_pat},
      "File Pattern":{"lvl":3, "value":file_pat},
      "Max Recurse":{"lvl":3, "value":max_recurse}
    });


  # If init_connection is set, then setup the smb connection.
  if (!isnull(share))
  {
    login  = kb_smb_login();
    pass   = kb_smb_password();
    domain = kb_smb_domain();

    if ( hcf_init == 0 ) hotfix_check_fversion_init();
    r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
    if ( r != 1 )
    {
      _debug_smb_null_return(fname:FUNCTION_NAME, label:'NetUseAdd()');
      return NULL;
    }
  }

  if (isnull(max_recurse)) max_recurse = 1;
  # limit how deep we'll recurse.
  if (level > max_recurse)
  {
    dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
      'Max recursion level of ' + max_recurse + ' exceeded.');
    return NULL;
  }

  subdirs = NULL;
  if (isnull(dir_pat)) dir_pat = "";
  ret = FindFirstFile(pattern:basedir + "\*" + dir_pat + "*");

  contents = make_list();
  while (!isnull(ret[1]))
  {
    if (file_pat && preg(pattern:file_pat, string:ret[1], icase:TRUE))
      contents = make_list(contents, basedir+"\"+ret[1]);

    subsub = NULL;
    if ("." != ret[1] && ".." != ret[1] && level <= max_recurse)
      subsub  = list_dir(basedir:basedir+"\"+ret[1], level:level+1, file_pat:file_pat, max_recurse:max_recurse);
    if (!isnull(subsub))
    {
      if (isnull(subdirs)) subdirs = make_list(subsub);
      else subdirs = make_list(subdirs, subsub);
    }
    ret = FindNextFile(handle:ret);
  }

  # If we initiated a connection, now close it.
  if (!isnull(share)) NetUseDel(close:FALSE);
  if (isnull(subdirs))
  {
    dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
      'Returning ' + obj_rep(contents));
    return contents;
  }
  else
  {
    dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
      'Returning ' + obj_rep(make_list(contents, subdirs)));
    return make_list(contents, subdirs);
  }
}

##
# Perform a version comparison for winsxs
#
# @param [a:string] version 1
# @param [b:string] version 2
#
# @return [int] -1 if a < b
#          0 if a == b
#          1 if a > b
##
function _winsxs_version_cmp(a, b)
{
  var i;

  a = split(a, sep:'.', keep:FALSE);
  b = split(b, sep:'.', keep:FALSE);

  for (i=0; i < max_index(a); i++)
  {
    if (int(a[i]) < int(b[i]))
      return -1;
    else if (int(a[i]) > int(b[i]))
      return 1;
  }
  return 0;
}

##
# Returns the file version as a string, either from the KB or by
# calling GetFileVersion(). Assumes we're already connected to the
# correct share.
#
# @anonparam [First:string] winsxs file.
#
# @return [string|NULL] Version of the winsxs file.
##
function _winsxs_get_file_version()
{
  var fh, file, ver, version;
  var pattern, matches, root;
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Getting WinSxS file version');
  if (isnull(_FCT_ANON_ARGS[0]))
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'_FCT_ANON_ARGS[0]');
    return NULL;
  }

  file = _FCT_ANON_ARGS[0];
  version = get_kb_item("SMB/FileVersions"+tolower(str_replace(string:file, find:"\", replace:"/")));
  if (isnull(version))
  {
    fh = CreateFile(
      file:file,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (!isnull(fh))
    {
      ver = GetFileVersion(handle:fh);
      CloseFile(handle:fh);
      if (!isnull(ver))
      {
        version = ver[0] + "." + ver[1] + "." + ver[2] + "." + ver[3];
        set_kb_item(
          name:"SMB/FileVersions"+tolower(str_replace(string:file, find:"\", replace:"/")),
          value:version
        );
      }

      # At this point we know the file exists, we just don't have a version
      # We will have to attempt to get the version from the folder name
      if (isnull(version))
      {
        pattern = "_([0-9]+.[0-9]+.[0-9]+.[0-9]+)_";
        matches = pregmatch(pattern:pattern, string:file);
        if(!isnull(matches)) version = matches[1];
      }
    }
  }

  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Returning ' + version);
  return version;
}


##
# Parses a properties file on Windows.
#
# @param [path:string] Path of file to parse.
# @param [appname:string] Application name for error messages if applicable.
# @remark Requires inclusion of misc_func.inc.
# @return [array|NULL] key->value file property pairs if successful
#         NULL otherwise
##
function smb_get_properties(path, appname)
{
  var contents;
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Getting smb properties for appname ' + appname + ' on path ' + path);

  if (isnull(path) || (strlen(path) == 0))
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'path');
    return NULL;
  }

  if (isnull(appname))
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'appname');
    return NULL;
  }

  contents = hotfix_get_file_contents(path);

  hotfix_handle_error(error_code: contents['error'], appname:appname, file:path, exit_on_fail:TRUE);

  return parse_properties(contents['data']);
}

##
# Retrieves the list of all user directories and saves it in the KB
#
# @return [list|NULL] List of user paths if successful
#         NULL otherwise
##
function hotfix_get_user_dirs()
{
  var appdir, dirpat, domain, hklm, iter, lcpaths, lcpath, login, pass;
  var path, paths, pdir, port, rc, root, share, user, ver;
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Saving user directories to KB');

  paths = get_kb_list("SMB/User Directory");
  if (!empty_or_null(paths))
  {
    paths = make_list(list_uniq(paths));
    return paths;
  }
  paths = make_list();

  registry_init();
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
  pdir = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\ProfilesDirectory");
  if (pdir && stridx(tolower(pdir), "%systemdrive%") == 0)
  {
    root = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot");
    if (!isnull(root))
    {
      share = hotfix_path2share(path:root);
      pdir = share - '$' + ':' + substr(pdir, strlen("%systemdrive%"));
    }
  }
  RegCloseKey(handle:hklm);
  close_registry(close:FALSE);

  if (!pdir)
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'get_registry_value()');
    return NULL;
  }

  ver = get_kb_item_or_exit("SMB/WindowsVersion");

  share = hotfix_path2share(path:pdir);
  dirpat = ereg_replace(string:pdir, pattern:"^[A-Za-z]:(.*)", replace:"\1\*");

  port    =  kb_smb_transport();
  if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
  login   =  kb_smb_login();
  pass    =  kb_smb_password();
  domain  =  kb_smb_domain();

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel(close:FALSE);
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'NetUseAdd()');
    return NULL;
  }

  # 2000 / XP / 2003
  if (ver < 6)
    appdir += "\Local Settings\Application Data";
  # Vista / 7 / 2008
  else
    appdir += "\AppData\Local";

  lcpaths = make_array();
  paths = make_list();
  iter = FindFirstFile(pattern:dirpat);
  while (!isnull(iter[1]))
  {
    user = iter[1];
    iter = FindNextFile(handle:iter);

    if (user == "." || user == "..")
      continue;

    path = pdir + '\\' + user + appdir;

    lcpath = tolower(path);
    if (isnull(lcpaths[lcpath]))
    {
      lcpaths[lcpath] = path;
      paths = make_list(paths, path);
      set_kb_item(name:"SMB/User Directory", value:path);
    }
  }

  NetUseDel(close:FALSE);

  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Found user directories ' + obj_rep(paths));
  return paths;
}

##
# Searches uninstall key subkeys for installed product with display
# name matching a given pattern
#
# @param [pattern:string] pattern to match
# @param [return_all_keys:boolean] (optional)(defaults to FALSE), if TRUE every matching display name key will be returned, not just the first
# @param [inspect_hklm:boolean] (optional)(defaults to TRUE), if FALSE omits results from registry subdirectories of Computer\HKEY_LOCAL_MACHINE\ (KB items SMB/Registry/HKLM/*)
# @param [inspect_hku:boolean] (optional)(defaults to FALSE), if FALSE omits results from registry subdirectories of Computer\HKEY_USERS\ (KB items SMB/Registry/HKU/*)
#
# @return [boolean|string] FALSE if displayname not found, subkey name if found
##
function hotfix_displayname_in_uninstall_key(pattern, return_all_keys, inspect_hklm, inspect_hku)
{
  var idx, key_list;
  var hku_names, hklm_names, lmkey, ukey;
  var return_first_key = FALSE;
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Looking for display name ' + pattern + ' in uninstall keys');

  # set passed / default values
  if (!return_all_keys || isnull(return_all_keys))
  {
    return_all_keys = FALSE;
    return_first_key = TRUE;
  }
  else
  {
    return_all_keys = TRUE;
  }

  if (isnull(inspect_hku))
    inspect_hku = FALSE;

  if (isnull(inspect_hklm))
    inspect_hklm = TRUE;


  key_list = make_list();

  if (inspect_hklm)
  {
    # get keys from HKey Local Machine Registry section
    hklm_names = hotfix_displayname_in_hklm_uninstall_key(pattern:pattern, return_all_keys:return_all_keys);

    if (hklm_names)
    {
      if (!empty_or_null(max_index(hklm_names)) &&
          max_index(hklm_names) > 0)
      {
         # handle multiple keys returned
         if (return_first_key)
         {
           dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
             'Returning single key in uninstall keys ' + hklm_names[0]);
           return hklm_names[0];
         }
         else
         {
           foreach idx (hklm_names)
             append_element(var:key_list, value:idx);
         }
      }
      else
      {
        # handle single key returned
        dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
         'Found single key in uninstall keys ' + hklm_names);
        return hklm_names;
      }
    }
  }

  if (inspect_hku)
  {
    # get key from HKey Users Registry section
    hku_names = hotfix_displayname_in_hku_uninstall_key(pattern:pattern, return_all_keys:return_all_keys);

    if (hku_names)
    {
      if (max_index(hku_names) > 0)
      {
        if (return_first_key)
        {
          dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
           'Returning single key in uninstall keys ' + hku_names[0]);
          return hku_names[0];
        }
        else
          foreach idx (hku_names)
            append_element(var:key_list, value:idx);
      }
      else
      {
        dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
          'Found single key in uninstall keys ' + hku_names);
        return  hku_names;
      }
    }
  }

  if (!empty_or_null(key_list))
  {
    dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
     'Found key in uninstall keys: ' + obj_rep(key_list));
    return key_list;
  }
  else
  {
    dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
     'Key not found');
    return FALSE;
  }

}

##
# Searches HKU uninstall key subkeys for installed product with display
# name matching a given pattern
#
# @param [pattern:string] pattern to match
# @param [return_all_keys:boolean] (optional)(defaults to FALSE), if TRUE every matching display name key will be returned, not just the first
#
# @return [boolean|string] FALSE if displayname not found, subkey name if found
##
function hotfix_displayname_in_hku_uninstall_key(pattern, return_all_keys)
{
  var key, display_names, key_list;
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Looking for display name ' + pattern + ' in uninstall keys');

  if (!return_all_keys || isnull(return_all_keys))
    return_all_keys = FALSE;

  display_names =
    get_kb_list("SMB/Registry/HKU/*/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");

  if(isnull(display_names)) return FALSE;

  if (return_all_keys)
  {
    key_list = make_list();
    foreach key (keys(display_names))
      if (display_names[key] =~ pattern)
        key_list[max_index(key_list)] = key;

    if (empty_or_null(key_list))
    {
      dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
       'Key not found');
      return FALSE;
    }
    else
    {
      dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
        'Returning keys: ' + obj_rep(key_list));
      return key_list;
    }
  }
  else
  {
    foreach key (keys(display_names))
      if (display_names[key] =~ pattern)
      {
        dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
         'Returning single key ' + key);
        return key;
      }
  }

  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
   'Key not found');
  return FALSE;
}


##
# Searches HKLM uninstall key subkeys for installed product with display
# name matching a given pattern
#
# @param [pattern:string] pattern to match
# @param [return_all_keys:boolean] (optional)(defaults to FALSE), if TRUE every matching display name key will be returned, not just the first
#
# @return [boolean|string] FALSE if displayname not found, subkey name if found
##
function hotfix_displayname_in_hklm_uninstall_key(pattern, return_all_keys)
{
  var key, display_names, key_list;

  if (!return_all_keys || isnull(return_all_keys))
    return_all_keys = FALSE;

  display_names = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");

  if(isnull(display_names)) return FALSE;

  if (return_all_keys)
  {
    key_list = make_list();
    foreach key (keys(display_names))
      if (display_names[key] =~ pattern)
        key_list[max_index(key_list)] = key;

    if (empty_or_null(key_list))
    {
      dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
       'Key not found');
      return FALSE;
    }
    else
    {
      dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
        'Returning keys: ' + obj_rep(key_list));
      return key_list;
    }
  }
  else
  {
    foreach key (keys(display_names))
      if (display_names[key] =~ pattern)
      {
        dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
         'Returning single key ' + key);
        return key;
      }
  }

 dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
   'Key not found');
  return FALSE;
}
