#TRUSTED 16fac58ff5b54cf9f60ebb173f862407d28d622ac43871cb7aa60d0b3955da6ac78a471d940bc0a047f427c38fc85a35acd44b4ca4ba9201c34ea6ac06fe0ffe8460d8b331267623843971635e36dce614418808469cec4632b1e053c6f6634d8a8047a08961fe732bf0da21152104bb7b35aac2c7018e7829ba2280c0cf4ee4ee58a9d3803b44346d9bf6af6acfaf88ca235f2bc4e4b34910b74bd50e9c4bc2a7bb46ac4aa1ae4ce733ff3cae4f9aaeb67b87fa260127dea395341de0bcc2df2e02f70f0160c29a9f06bce73311d69fcb24114cbd5d1449e8c2d5a1e70861c88327664fd09cc3556726d38c50e14ee898967bfceee69070429ada4cf4845f47922f3da04ada1f456de881e56ecb5170022ea9dfe48dfc0e389a298773f102b3bf3f14515a2cabeb0607c686da42eaf185b408d22f1970fc97a09fe3f32fa75a7620a43ea3c185237e05073294b5112ab9bd355b7f13fa831ff7c7c4cb3daafb2d217644b2494e6151cc6322acbdce007e6a75ff785994ad87cf9cf17e3e6bb1747482899f6dba9fb8013785dc79112d5d930c8151c6763d598cc53a6d078fbd361e869edad8dd47a0d7a5177fece60fcc42ac39898d692a015f2a3c0ffb6fe6bcaddb6ce40265a8505fcc2bab4e6009599d201f6ff3be322f75edd605ebe24acb5fec3f2e4aab5d4144a8fa79fac79151fb1fe2561bc46b3e57912e83115de3
#TRUST-RSA-SHA256 32d6f633ae8a82152cc27305e8e8637f285cb2e76804ab55d0410107bf5adb0d226bbecc0d22f1c6da94af13283c5ef68c1d520d6ad143c6a35e0ce873d7be80b8a2589709aeb197b8f5ce147a03915796cc3ea3ce95f4b53a0f20e8ebd298d8702d7e918997915c7db04edba260786d2f20f6165299677d3cbe5cb609700331658720bcf00c116ae90bef31dbf241275b06cd30b0942d66a8c4bb7b8fbdbece7023fe07911ded1c8909183274cbe0fa06e015e169a7ddfbd5587589bf3a19830a24e26e574839d3c42895d31a99e43dba7cbd82b189ba479e66799211c607faa8368c267035e6c9ab5077b194cdc2fa4e8174cbcab26350dcb20cb41fcc2d11fb45daf465191422253dc949030eafc037fe0e6d7c7f0d40cbf2e023bc2b51446b0505ea950838d24c71e0c0dfa875bd2b94986b50515196c4e61a1cc74ab451d8fbc3ea969af6c5e59cec5fc3b8c651e261f04b8c296f6c49b2ff26f77d4453dc9e87f070e3661d39827d523da895b515b3bca94060863bdeefaf446ca1bbb958cb5e4d060bc5915f1389c546ab431baff2e4ce58d2ada28a373a45056a4b55b216ee8ce5711f9d7bf0bef2156adbd6bdf6f62ec6631a7db58630f3b7152e70a79e2115c0e65dfc4d06eb6b6b274a823bcb88f62bef1dccd28aaf64b06e789ba2fabeb1a16ddbb4a00b3d6d45d73043556bf9fa13ace0c322cc1f996907cd3c
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# sap.inc
# Revision: 1.6
##

include("compat_shared.inc");
include("spad_log_func.inc");
include("debug.inc");
include("hostlevel_funcs.inc");
include("local_detection_nix.inc");

##
# Runs pregmatch on an ase dataserver binary to find the version.
#
# @param [dataserver_bin:string] String with the \x00 already removed if needed.
#
# @return [string] the full version. Ex: 16.0 SP03 PL02. Null otherwise
##
function _ase_dataserver_version(dataserver_bin)
{
  if(empty_or_null(dataserver_bin))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Missing dataserver_bin argument");
    return NULL;
  }
  var version_string, match;
  #search bin for string
  version_string = "Adaptive Server Enterprise/([\d]+\.[\d.]+( +SP[\d]+)?( +PL[\d]+)?)";
  match = pregmatch(pattern:version_string, string:dataserver_bin);
  if(empty_or_null(match))
    return NULL;
  return match[1];
}

##
# Parses a .krg file to find the process id.
# 
# @param [krg:string] The contents of an ASE .krg file.
#
# @return the process id string, NULL otherwise.
##
function _parse_krg(krg)
{
  if(empty_or_null(krg))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Missing krg argument");
    return NULL;
  }
  var pid;
  krg = split(krg, keep:FALSE);
  #The pid is line 2, major version is line 7 (for future reference)
  pid = krg[1];
  #sanity check that we found a number
  #If any character isn't a digit then return null
  if(pid =~ "^.*[^\d].*$")
    return NULL;
  return pid;
}

##
# Attempts to retreive the version of SAP ASE using the dataserver bin.
# Calls out to the target to retreive the contents of dataserver then parses the contents.
#
# @param [path:string] The path to the dataserver bin.
#
# @return the full version found in the bin. Ex: 16.0_sp03_pl02. NULL otherwise
##
function run_get_dataserver_version(path)
{
  if(empty_or_null(path))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Missing path argument");
    return NULL;
  }
  var dataserver_contents;
  var ver;
  dataserver_contents = run_cmd_template(template:'cat $1$ | grep -a "Adaptive Server Enterprise" 2>/dev/null', args:make_list(path));
  if(dataserver_contents['error'])
  {
    dbg::detailed_log(
      lvl: 1,
      src: FUNCTION_NAME,
      msg: "Error in run_cmd_template",
      msg_details: {
        "Error": {"lvl": 1, "value": dataserver_contents['error']}});
    return NULL;
  }
    
  dataserver_contents = str_replace(string:dataserver_contents['data'], find:'\x00', replace:'');
  ver = _ase_dataserver_version(dataserver_bin:dataserver_contents);
  return ver;
}

##
# Attempts to find and analyze all the .krg files in the given ASE home directory
# This gives enough information to find the running db instances
#
# @param [home:string] The path of the ASE home directory
# @return A list of arrays containing instance information
#  for example [{'ip'     : '1.1.1.1',
#               'port'    : '123',
#               'data'    : '/user/master.dat',
#               'dbname'  : 'asedb'}]
# Returns NULL otherwise.
##
function run_process_krgs(home)
{
  if(empty_or_null(home))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Missing home argument");
    return NULL;
  }

  var krgs, krg, contents, pid;
  var network_info, masterdat, net; 
  var instances = make_list();
  
  krgs = run_cmd_template(template:'ls $1$ 2>/dev/null | grep ".krg"', args:make_list(home));
  if(krgs['error'])
  {
    dbg::detailed_log(
      lvl: 1,
      src: FUNCTION_NAME,
      msg: "Error finding krg files",
      msg_details: {
        "Error": {"lvl": 1, "value": krgs['error']}});
    return NULL;
  }
 
  krgs = split(krgs['data'], keep:FALSE);
  
  foreach krg (krgs)
  {
    contents = run_cmd_template(template:'cat $1$ 2>/dev/null', args:make_list(home + '/' + krg));
    if(contents['error'])
    {
      dbg::detailed_log(
        lvl: 2,
        src: FUNCTION_NAME,
        msg: "Error getting krg contents",
        msg_details: {
          "Error": {"lvl": 2, "value": contents['error']}});
      continue;
    }
    pid = _parse_krg(krg:contents['data']);
    network_info = ldnix::pid_to_ip(pid:pid); #this verifies the pid we found is a running proc
    #find the master.dat that is associated with the pid. There is no server name type parameter to find
    masterdat = _find_ase_database(pid:pid);
    foreach net (network_info)
    {
      #I don't believe ase allows a single db instance to listen on multiple ports but in case it does
      #the master database name and path will be the same for each port/ip combo
      append_element(var:instances, value:{ip:net.ip, port:net.port, data:masterdat, dbname:krg - '.krg'});
    }
  }
  return instances;
}

##
# Finds the path of the database using the pid and referencing
# the running procs list in the kb.
#
# @param [pid:string] A string containing the process identifier
#
# @return The path as a string, NULL otherwise
##
function _find_ase_database(pid)
{
  if(empty_or_null(pid))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Missing pid argument");
    return NULL;
  }
  if(pid =~ ".*[^\d].*")
  {
    dbg::detailed_log(
      lvl: 1,
      src: FUNCTION_NAME,
      msg: "Pid argument is malformed",
      msg_details: {
        "pid": {"lvl": 1, "value": pid}});
    return NULL;
  }
  
  #look at ps -auxww in kb
  #find the master.dat file associated with the pid
  var ps, match, pattern, line;
  ps = get_kb_item("Host/ps_auxww");
  if(empty_or_null(ps))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "No process info in kb");
    return NULL;
  }
  
  #for this regex we want the line of ps auxx output with the given pid
  #then within that line we want the -d parameter. Look for '-d' the grab the path after that that ends in .dat
  ps = split(ps, keep:FALSE);
  pattern = strcat("^.* +", pid, " +.*-d ?(/[^ ]*.dat).*$");
  foreach line (ps)
  {
    match = pregmatch(pattern: pattern, string:line);
    if(!empty_or_null(match)) break;
  }
  if(empty_or_null(match))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Unable to find master database from processes");
    return NULL;
  }
  
  return match[1];
}

##
# SAP products may have multiple versions, service packs, patches
# and hotfixes installed and these show up in the kb as 
# separate installs. Return only the latest patch
#
# @param [version_strings:list] A list of version strings.
#
# @return the latest version as it appears in the kb, NULL if an error occurred.
##
function find_latest_version(version_strings)
{
  var major, minor, patch, hotfix, latest;
  var sap_versions = make_array();
  if(empty_or_null(version_strings))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Missing version_strings argument");
    return NULL;
  }

  foreach var sap_install (version_strings)
  {
    #the version info can look like this 4.2 SP4 Patch 2 Hotfix 3 update
    #reorgnaize this to look like 4.2.2.3 then use VCF to find the latest

    #find major
    major = pregmatch(string:sap_install, pattern:"^([\d]+\.[\d]+).*");
    if(empty_or_null(major)) major = 0;
    else major = major[1];
    
    minor = pregmatch(string:sap_install, pattern:".*SP([\d]+).*");
    if(empty_or_null(minor)) minor = 0;
    else minor = minor[1];

    patch = pregmatch(string:sap_install, pattern:".*Patch ([\d]+).*");
    if(empty_or_null(patch)) patch = 0;
    else patch = patch[1];

    hotfix = pregmatch(string:sap_install, pattern:".*Hotfix ([\d]+).*");
    if(empty_or_null(hotfix)) hotfix = 0;
    else hotfix = hotfix[1];

    sap_versions[sap_install] = join([major,minor,patch,hotfix], sep:'.');
  }

  #find the latest version
  latest = version_strings[0];
  foreach sap_install (keys(sap_versions))
  {
    if(ver_compare(ver:sap_versions[sap_install], fix:sap_versions[latest]) == 1)
      latest = sap_install;
  }
  
  return latest;

}
