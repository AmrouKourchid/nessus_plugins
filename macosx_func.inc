#TRUSTED 9b7d28f1090ad5e8c30621d458b03beb103d949b519b1807fe2f5fa54f68096e657f3089fac1b2c7e51159dd70549f22614c07df7d2da80e3be4878ba6e612ad50c9ab58e3222e1f0784a8b57127b1ba4da0cf8782c58964c8dd599bdfebf5440b20f2394659f62d33e63b6914198cc5bb95bff633ae3561ee0c6acb3b240101da543206a1d91d2b17e4c27e85e6f0aa408cea61d2e1c0fa898cab43aa4fc11870c38353fecaec4871270ddffcce24f4f9edd343f493021e513c4ac0db52c81701f3ae613e2d19e03598bd0d3f84adc45b0e58b857cbe47e2917f77c30c28ca318fe8a29799028495d5802dc0c90ac48c2b462218c243f5b540bc52f7d8e46688c481db2d258ce637d235b2ef282b8dd2aa37ca46732232429270adda602cbf0330a49eb8b4139ab152d37fd96846830aec0b3e0556019b8aa5cd5a6ccc364b97a8d6fb7aafff2ae063f8703ff0769e0b305f64ae002780c5c50207f00a654d1a19f3274bd41980ba3cee63664868061c2b319dfa2da69a35225df3d8d6a2234f2843ad1e497a6d1c687ccbafe247030e9fd15574f78af7d06b7cafa938b8c0c97f8f63bf04004003070e50433d6b61a302a9d8d0fc36455f985c0cf0a655f84dccee3b27b5d08dfab90bfa911b6b555037ed86a9b5a37390e368dab4fb7df9e6d853abaf7576f10def7ad07a95eede95c0d43b26a52cab86f7116a596bb49d6
#TRUST-RSA-SHA256 7988ce3fb60377f82cde4e069aea7420d59586b2946e69f807c7867a7358c8c701d17d137e626deea2b11d0000365060f1dc41597f0d7d1101e29514a266179509ca45485ecd411c4fd92908f1fb6a3e63d93c08af779461b351d10308ba7dbc1afe06c49cb439f7d5e6cc80d2e47f8efb8482a51484ba65e47b5e4b9d3a5fbd0aecd3f2d0097642ff4214c0ee3fdb487174c8e9147fcc8eb0a84598ff48682e576ece6ccf4ca12f773b9421b0f935a6b4ca37db16468f63692cbc56988150addb612a97fb1a140f31d58ca6d771344ec8250eb9de2e20bd0cb880949e680e361052f118e9fd0dd584d1d11c0efd36edcfedfb6eb113ae96f5c85acafe2459a137ed538734df6d3928afdb79e7e3b53b5137512e4c02f5237d28d68330e6b7adbc8436076a9d4d7f51601ab017da21568016735c70aa756d111bfa7291e80d9728fde6c52435ad4081e92095073bb9b4aecd4ff11a53e19bdc9c47c0314ff6bf3d2986727ee98d6545b2323629448ddb94d67906c9a05f19b6a9dfa41ba3e651b9833d86462941b55320f0dc196e58fd0c1d158b1224c856f9fc350b3fc234960d242edcea4c13c3269910fefbfaed8c622601c2c09b781f1cfb5a40ae37797164c8476a083e953ab37d4abf59f0d78b177755420fb747f52c0c95386c243bf590795b84489a6a475747af6d3900212a583d1ea736279d67111e0aebfa079012
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision: 1.17

##
# Generates OSX Bundle Version
#
# @param file filename of bundle
# @param path path to bundle
# @param label plist tag for the version info
# @param rsrc True for rsrc, otherwise false
#
# @category OSX
#
# @return Command to be used to get a bundle version
##
include("compat_shared.inc");
include("ssh_globals.inc");
include("ssh_func.inc");
include("ssh_lib.inc");
include("debug.inc");
include("hostlevel_funcs.inc");
include("local_detection_nix.inc");

function _GetBundleVersionCmd(file, path, label, rsrc)
{
  local_var ret, suffix;
  local_var cmd;

  # This is only invoked by GetCarbonVersionCmd
  if ( rsrc )
  {
    suffix = "/rsrc";
    cmd = "perl -pe 's/[^ -~]/\\n/g'";
  }
  else
  {
    suffix = "/Contents/version.plist";
    cmd    = "cat";
 }

 file = str_replace(find:' ', replace:'\\ ', string:file);

 if ( !isnull(path) )
   {
   path = str_replace(find:' ', replace:'\\ ', string:path);
   ret = "cd " + path + " 2>/dev/null && ";
   }
 else
   ret = "";


 ret += cmd + " " + file + suffix + "|grep -A 1 " + label + " " + '| tail -n 1 | sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
 return ret;
}

##
# Generates OSX Bundle Version
#
# @param file filename of bundle
# @param path path to bundle
# @param long If true uses CFBundleVersion otherwise CFBundleShortVersion
#
# @category OSX
#
# @return Command to be used to get a bundle version
##
function GetBundleVersionCmd(file, path, long)
{
 if ( long )
  return _GetBundleVersionCmd(file:file, path:path,label:"CFBundleVersion", rsrc:FALSE);
 else
  return _GetBundleVersionCmd(file:file, path:path,label:"CFBundleShortVersion", rsrc:FALSE);
}

##
# Generates OSX Bundle Version
#
# @param file
# @param path
#
# @category OSX
#
# @return Command to be used to get a bundle version
##
function GetCarbonVersionCmd(file, path)
{
 return _GetBundleVersionCmd(file:file, path:path,label:"CFBundleVersion", rsrc:TRUE);
}

##
# Executes a command on localhost or via ssh.
# WARNING: Passing untrusted input to this function may result in unexpected command execution
#
# @param cmd Command to be executed on the target host.
# @param exit_on_fail True/False if the script should exit on fail, returns NULL if False and fails.
#
# @category OSX
#
# @return The result of the executed command or NULL on failure.
##
function exec_cmd(cmd, exit_on_fail)
{
  local_var ret, buf;

  if (isnull(exit_on_fail))
    exit_on_fail = FALSE;

  if (islocalhost())
    buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
  else
  {
    ret = info_connect();

    if (!ret)
    {
      if (exit_on_fail) exit(1, "ssh_open_connection() failed.");
      else return NULL;
    }

    buf = info_send_cmd(cmd:cmd);
    if (info_t == INFO_SSH)
      ssh_close_connection();
  }

  if (buf) buf = chomp(buf);
  return buf;
}

##
# Executes a array of unique commands on localhost or via ssh.
# WARNING: Passing untrusted input to this function may result in unexpected command execution
#
# @param cmds Array of unique commands to be executed on the target host.
# @param exit_on_fail True/False if the script should exit on fail, returns NULL if False and fails.
#
# @category OSX
#
# @return An hash of the results of the executed commands or NULL on failure.
##
function exec_cmds(cmds, exit_on_fail)
{
  local_var command, ret, buf, results;

  if (typeof(cmds) != 'array')
    exit(1, "Invalid type for the 'cmds' argument.");

  if (isnull(exit_on_fail))
    exit_on_fail = FALSE;

  results = make_array();
  cmds = list_uniq(cmds);

  if (!islocalhost())
  {
    ret = ssh_open_connection();

    if (!ret)
    {
      if (exit_on_fail)
        exit(1, "ssh_open_connection() failed.");
      else
        return NULL;
    }
  }

  foreach command (cmds)
  {
    buf = "";

    if (islocalhost())
      buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", command));
    else
    {
      buf = ssh_cmd(cmd:command);

      if(isnull(buf))
      {
        if(exit_on_fail == TRUE)
          exit(1, "ssh_cmd() failed.");
      }
    }

    if (buf)
      buf = chomp(buf);

    results[command] = buf;
  }

  if (!islocalhost()) ssh_close_connection();

  return results;
}


##
# Gets the list of user directories
#
# @param all True/False if the script should extract all user directories or just those of regular users (ie, with an id > 499)
#
# @category OSX
#
# @return An array in which the keys are the usernames and the values are the home directories.
##
function get_users_homes(all)
{
  local_var cmd, data, home, homes, id, key, line, match, res, val;

  cmd = 'echo ; /usr/bin/dscl  . -readall /Users NFSHomeDirectory UniqueID';
  res = exec_cmd(cmd:cmd);
  if (!strlen(res)) return NULL;

  homes = make_array();
  foreach line (split(res, keep:FALSE))
  {
    match = pregmatch(pattern:"^([^: ]+): +(.+)$", string:line);
    if (match)
    {
      key = match[1];
      val = match[2];
      data[tolower(key)] = val;
    }

    if (!isnull(data['uniqueid']) && !isnull(data['recordname']) && !isnull(data['nfshomedirectory']))
    {
      id = data['uniqueid'];
      if (all || id > 499)
      {
        key = data['recordname'];
        val = data['nfshomedirectory'];
        homes[key] = val;
      }

      data = make_array();
    }
  }
  return homes;
}

##
# Builds a template for using mdfind with run_cmd_template()
# @param file_patterns a list of stings containing file patterns
# @return string a template for use with run_cmd_template()
## 
function _build_spotlight_mdfind_template(file_patterns)
{
  var template, i, msg;
  if (empty_or_null(file_patterns) || typeof_ex(file_patterns) != "list")
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:"Invalid file_patterns arg.");
    return NULL;
  }

  #mdfind 'kMDItemFSName == "*.jar" || kMDItemFSName == "*.war" || kMDItemFSName == "*.ear"'
  template = 'mdfind -onlyin $1$ \'kMDItemFSName == "$2$"';
  i = 3;
  while (i < max_index(file_patterns) + 2) #i to account for i starting at 2 or 3
  {
    template = strcat(template,' || kMDItemFSName == "$', i++, '$"');
  }
  return template + '\'';
}

##
# This makes use of MacOS's Spotlight search to find files by file type or name
# uses kMDItemFSName, supports wildcards
#
# @param file_patterns array of strings File/directory names to search for
# @param dir string The directory to search. Defaults to root
# @return list of file paths
##
function spotlight_mdfind(file_patterns, dir)
{
  var buf, runbuf, indexing_enabled, indexflag, template, fp, args;

  if (empty_or_null(file_patterns) || typeof_ex(file_patterns) != "list")
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:"Empty file_patterns argument");
    return NULL;
  }

  indexflag = FALSE;
  # check if indexing is on
  # store in the kb so we don't need to make this call more than once
  indexing_enabled = get_kb_item("Host/MacOSX/spotlight_indexing_enabled");
  if(!empty_or_null(indexing_enabled) && indexing_enabled == FALSE) return NULL;

  if(empty_or_null(dir)) dir = '/';

  if(empty_or_null(indexing_enabled))
  {
   # indexing is applied to volumes. If different volumes are supported in the future
   # then this should be updated to accomodate. On older macOS systems the root vol was
   # all that was needed to check, on newer systems this is now off. On newer macOS systems, 
   # /System/Volumes/Data is the correct place to check
   # info_send_cmd use here does not have user modifiable input that can be used anywhere else, 
   # not a risk

   # Unit test workarounds
   buf = get_kb_item("Unit_Tests/spotlight_mdfind/mdutil_response");
   if (empty_or_null(buf))
     buf  = info_send_cmd(cmd:'mdutil -sav');
   # Quick exit here
   if ("indexing enabled" >!< tolower(buf))
   {
     replace_kb_item(name:"Host/cmd/spotlight_indexing_enabled", value:FALSE);
     return NULL;
   }

   # Check for indexing enabled / or /SystemVolumes/Data on newer systems 
   var md_res=split(buf);
   dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:obj_rep(md_res));
   for (var i=0; i < max_index(md_res)-1; i++) {
     if ((md_res[i] =~ "^(/|/System/Volumes/Data):$") && (md_res[i+1] =~ "^\tindexing enabled\.")) {
          dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:md_res[i]+":"+md_res[i+1]);
          replace_kb_item(name:"Host/MacOSX/spotlight_indexing_enabled", value:TRUE);
          indexflag = TRUE;
     }
   }
   # Any other volumes we don't care about yet. 
   if (indexflag == FALSE) {
     replace_kb_item(name:"Host/cmd/spotlight_indexing_enabled", value:FALSE);
     return NULL;
   }

  }

  template = _build_spotlight_mdfind_template(file_patterns:file_patterns);

  # Create a single array with all of the command parameters
  args = [dir];
  foreach fp (file_patterns)
  {
    append_element(var: args, value: fp);
  }

  # Unit test workarounds
  var testbuf = get_kb_item("Unit_Tests/spotlight_mdfind/runcmddata");
  var buferr  = get_kb_item("Unit_Tests/spotlight_mdfind/runcmderror");
  if (!empty_or_null(testbuf)) {
    if(empty_or_null(buferr)) buferr=0;
    runbuf = {data:testbuf, error:buferr};
  }

  if (empty_or_null(runbuf))
    runbuf = run_cmd_template(template:template, args:args);

  # check the results against excluded file paths and return
  if(!runbuf.error)
      return exclude_filepath_check(discovered_paths:split(runbuf.data, keep:FALSE));

  var buf_err="run_cmd_template error: "+ runbuf.error;
  dbg::detailed_log(lvl:1, src: FUNCTION_NAME, msg:buf_err);
  return NULL;
}

##
# The user can specify file paths that should not be included in scan results. This
# function takes paths we've discovered and removes any that should be excluded
#
# @param discovered_paths List of file paths
# @return List a pruned list of file paths. Null if something goes wrong
##
function exclude_filepath_check(discovered_paths)
{
  if (empty_or_null(discovered_paths) || typeof_ex(discovered_paths) != "list")
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:"Invalid discovered_paths arg.");
    return NULL;
  }
  var excluded_paths = get_kb_item('Host/sh_commands_find/user_filepath_exclusions');
  if (isnull(excluded_paths))
  {
    dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:"Error: user_filepath_exclusions returned unexpected value.");
    return discovered_paths;
  }
  else if (!excluded_paths)
  {
    dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:"Error: user_filepath_exclusions not specified.");
    return discovered_paths;
  }

  var excmatch, epath, path;
  var noexcpath = make_list();
  var excluded = split(excluded_paths, keep:FALSE);

  for(var idx in excluded)
    excluded[idx] = ldnix::files::file_glob_to_regex(glob:excluded[idx]);

  if (!empty_or_null(excluded))
    dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:"user_filepath_exclusions from user input: "+obj_rep(excluded));

  foreach path (discovered_paths)
  {
    excmatch = FALSE;
    foreach epath (excluded)
    {
      if(preg(string:path, pattern:epath))
      {
        excmatch = TRUE;
        dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:"skipping "+path+" due to filepath exclusion.");
        break;
      }
    }
    if (excmatch == FALSE)
      append_element(var:noexcpath, value:path);
  }
  return noexcpath;
}

