#TRUSTED 71e9f691cf1efde0e067380586794788d85170206a32d4aa4c98a12e29ddf48d241d40749aef2579df52499e7376f2c6d48374996f3a6c367fd441f738875893bb5e097e14616420b18b429d7e399bb601924a0d9aa6f25a103d26ac28420829c394e5a6a336ca17efa19c8dade57fdb872d21db7f19c7422749cdaffdbf702e4f1c6cfc88d699c68b80af5a9c6a00f5ec7ac1d657af54719b4d7b35fd9b4a8f08410d5065f40473cef3824698b13068c4374ec80d288bd8adeeb0a4b12eb3e739054570b973f3571ec890829bc3d4dd195424084a7525138030c981cd114578ce6f008433ba02c84d2563e27282c63c9ddca56ffecef4d9460c424655231d58be943db7c70864176a93f358c69e803b82fc65799546a8d8252b6a32c4d4a38cec90eabb2082a792f43f8754735b129bffa04b14b5a76e5cf66331f2bcceec521b9d46702166851f216b6d33dc489333d7872cdf7686cae052ea9f014fecedc0d9d3e9030f0a4e78c41c3705049d2c4bb1e61d22e02e8b0a8d21035ad1cab08365da1a5762b163fe165890db049b5a4b8208ccf52a6d942580bdbeec44f960c5d85ce8abdaa4c32617458b22aeb14c474227e7ea9f99449c45cd94f8aa2b89fb0bb8f56d70b6a098af8a1b1270fa5ee5d0a83f26969c824fce523ef98dba199d3a0131dc31e4a75b717e09f46dafad234289bef2b0d077dd991a8d0c8f30fe9e
#TRUST-RSA-SHA256 90dcc12f00647e66d2552c37e06b05b29c20bd578fab7dff7bdddf181a7179f52bbf1e3152ff1982a8c1749d97ba2789fc15606f448b758dfc31a231041d6287bb0384e4b3f7602fb0bb15e130062ebb356defca3a9704bc0b9d20607c2c8d8c15a44c363b146fa626b75892272c06213b117906e499d690b0f09447a417415f983d8eb5fbe3473a343b1d5a0ff3f297d56a7e5b2bb3bfb1a6849386d08e6c36670eb89381b98c268346dfa7527e0368888c17422267c2c46eede19ff87f5e4f84726a82863fafa857f35630e4029088554aaa8db036a46787e4a3a54ad7ccbf9737c4155427c0ee4693ccec4d8e3ba278b65be02e4177bbaab82e0c421f764c72bca32a5580cd00a4d580c25920cb003ca1b1d81030b11acab6b7268c21a433d2b33e7491de5f4e9345dd6c6dcfb1f738296d1ff30afe528195b879d2b12fbfe2228a6bbbf5dea117077563389be9e9e6e68a9e974c20d99fff025a4a536cab96daf9283f365582722b348d42625e5096c9564bdd4b2f29a6d6cf027b8a1c816ddf40a98e298bf7f3d4171af0395c7669b9fc04fcc23b96ad9677fa62c9fbff7eda341c4e762490dd0895b8c43800c5b53de3f09d394a67d73a21eea72ad4955395be96de74243887e802787db80fca4a562d06dba7165f35153faf07a0cb0424f256018008170233d80de687349f35ae4853cfba074144648c3be492606dba
###
# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# webapp_func.inc
# Revision: 1.22
#
# @include misc_func.inc
# @include http.inc
###

# Plugins should only include either webapp_func.inc or
# install_func.inc, not both.
include("install_func.inc");
include("compat_shared.inc");
include("http.inc");
include("debug.inc");

##
# Default header used by get_vuln_report()
##
global_var DEFAULT_HEADER;
DEFAULT_HEADER = 'Nessus was able to verify the issue using the following URL';


##
# adds install information to an array of existing install information, and
# saves the info to the KB
#
# @param appname name of installed application. this name is only used internally for KB reading/writing
# @param installs existing list of installs formatted the same as the return value of this function (optional)
# @param dir web dir of install to add
# @param ver version of the install found in 'dir'. this is optional - if no argument is given, the install is given a version of UNKNOWN_VER
# @param port number of the web server where the app was detected
# @param cpe passes CPE attribute to register_install
# @param extra passes extra attributes to register_install
#
# @remark saves www/"appname"=TRUE in the KB, where "appname" is the argument passed to the "appname" parameter
#
# @return an array - 'installs', with the new install added. key = ver, dir = corresponding dirs, delimited by DIR_SEPARATOR
##
function add_install(appname, vendor, product, installs, dir, ver, port, cpe, extra)
{
  if (isnull(appname))
  {
    err_print("add_install() missing required argument 'appname'.");
    return NULL;
  }
  else if (isnull(dir))
  {
    err_print("add_install() missing required argument 'dir'.");
    return NULL;
  }
  else if (isnull(port))
  {
    err_print("add_install() missing required argument 'port'.");
    return NULL;
  }

  if (isnull(installs)) installs = make_array();
  if (isnull(ver)) ver = UNKNOWN_VER;

  if (dir == '') dir = '/';

  set_kb_item(
    name:'www/' + port + '/' + appname,
    value:ver + ' under ' + dir
  );

  # General key to allow optimization with script_require_keys
  set_kb_item(name: 'www/'+appname, value: TRUE);

  register_install(
    app_name:appname,
    vendor:vendor,
    product:product,
    path:dir,
    version:ver,
    port:port,
    cpe:cpe,
    webapp:TRUE,
    extra:extra
  );

  # base64 encodes dirs to prevent any delimiter ambiguity
  dir = base64(str:dir);
  if (isnull(installs[ver])) installs[ver] = dir;
  else installs[ver] += SEPARATOR + dir;

  return installs;
}


##
# Generates plugin output containing information on all installs detected
#
# @param display_name name of the web application being reported on. this is the name that will be displayed in the report
# @param installs installs to report. this should be an array with the same that [add_install] returns
# @param port number of the web server where the app was detected
# @param item page in each install directory where the app was detected. '/' by default.
#
# @return a report of installs detected if any were detected, NULL otherwise
##
function get_install_report(display_name, installs, port, item)
{
  local_var info, version, n, dir, dirs, url, report;

  if (isnull(display_name))
  {
    err_print("get_install_report() missing required argument 'display_name'.");
    return NULL;
  }
  else if (isnull(port))
  {
    err_print("get_install_report() missing required argument 'port'.");
    return NULL;
  }

  # Bail out if there's nothing to report (i.e. nothing was detected)
  if (isnull(installs) || max_index(keys(installs)) == 0) return NULL;

  if (isnull(item)) item = '/';

  info = "";
  n = 0;

  foreach version (sort(keys(installs)))
  {
    info += '\n  Version : ' + version + '\n';
    dirs = split(installs[version], sep:SEPARATOR, keep:FALSE);

    foreach dir (sort(dirs))
    {
      dir = base64_decode(str:dir);
      if (dir == '/') url = item;
      else url = dir + item;

      info += '  URL     : ' + build_url(port:port, qs:url) + '\n';
      n++;
    }
  }

  report = '\nThe following instance';
  if (n == 1) report += ' of ' + display_name + ' was';
  else report += 's of ' + display_name + ' were';
  report += ' detected on the remote host :\n' + info;

  return report;
}

##
# Generates plugin output containing information used to detect/verify a vulnerability is present
#
# @param header header of plugin output. if this arg is omitted, DEFAULT_HEADER is used
# @param trailer plugin output trailer (optional)
# @param items list of web paths (including query strings, if applicable) that demonstrate the vulnerability. this can either be a string (if there is only one item), or a list of strings
# @param port number of the web server where the app was detected
#
# returns plugin output demonstrating the vulnerability, or NULL if there were any errors generating the plugin output
##
function get_vuln_report(header, trailer, items, port)
{
  local_var report, item;

  if (isnull(items))
  {
    err_print("get_vuln_report() missing required argument 'items'.");
    return NULL;
  }
  else if (isnull(port))
  {
    err_print("get_vuln_report() missing required argument 'port'.");
    return NULL;
  }

  items = make_list(items);
  if (max_index(items) == 0) return NULL;

  if (isnull(header))
  {
    header = DEFAULT_HEADER;
    if (max_index(items) > 1) header += 's';
  }

  report = '\n' + header + ' :\n';

  foreach item (items)
    report += '\n  '+ build_url(qs:item, port:port) + '\n"';

  if (!isnull(trailer))
    report += '\n' + trailer + '\n';

  return report;
}

##
# Gets a web app install from the KB
#
# @param appname name of the app, as it was stored in the KB (by [add_install])
# @param port number of the web server where the app was detected
# @param exit_on_fail if TRUE, exits in lieu of returning NULL. FALSE by default
#
# @remark This function will fork if multiple installations of the same web app are read from the KB.
#         If you need a non-forking alternative, consider [get_dirs_from_kb]
#
# @return an array if the application was found in the KB ("ver" => detected version, "dir" => web dir where the app is installed),
#         NULL otherwise
##
function get_install_from_kb(appname, port, exit_on_fail)
{
  local_var install, match, dir, ver, ret;
  local_var installs;

  if (isnull(appname))
  {
    err_print("get_install_from_kb() missing required argument 'appname'.");
    return NULL;
  }
  else if (isnull(port))
  {
    err_print("get_install_from_kb() missing required argument 'port'.");
    return NULL;
  }
  if (isnull(exit_on_fail)) exit_on_fail = FALSE;

  ret = NULL;
  installs = get_installs(app_name:appname, port:port);
  if (installs[0] == IF_NOT_FOUND)
  {
    if (exit_on_fail)
      exit(0, "No installs of " + appname + " on port " + port + " were found.");
    else
      return NULL;
  }
  else if (installs[0] != IF_OK)
  {
    if (exit_on_fail)
      exit(0, "Could not retrieve installs of " + appname + " on port " + port + ".");
    else
      return NULL;
  }

  installs = installs[1];

  # This function is expected to fork if there are multiple installs
  # so we have to do that explicitly now to maintain backwards
  # compatibility.
  install = branch(installs);

  # Strip the trailing slash from the dir, if it has one
  dir = ereg_replace(string:install['path'], pattern:'^(/.*)/$', replace:"\1");
  if (dir == '/') dir = '';

  ret = make_array(
    'dir', dir,
    'ver', install['version']);

  return ret;
}

##
# Gets a list from the KB of all the web dirs where the given app was detected.
#
# @param appname name of the app, as it was stored in the KB (by [add_install])
# @param port number of the web server where the app was detected
# @param exit_on_fail if TRUE, exits in lieu of returning NULL. FALSE by default
#
# @return a list of web dirs if the application was found in the KB, NULL otherwise
##
function get_dirs_from_kb(appname, port, exit_on_fail)
{
  local_var install, installs, match, dir, ret;

  if (isnull(appname))
  {
    err_print("get_dirs_from_kb() missing required argument 'appname'.");
    return NULL;
  }
  else if (isnull(port))
  {
    err_print("get_dirs_from_kb() missing required argument 'port'.");
    return NULL;
  }
  if (isnull(exit_on_fail)) exit_on_fail = FALSE;

  ret = make_list();

  installs = get_installs(app_name:appname, port:port);
  if (installs[0] == IF_OK)
  {
    installs = installs[1];
  }

  else if (installs[0] == IF_NOT_FOUND)
  {
    if (exit_on_fail)
      exit(0, "No installs of " + appname + " on port " + port + " were found.");
    else
      return NULL;
  }
  else if (installs[0] != IF_OK)
  {
    if (exit_on_fail)
      exit(0, "Could not retrieve installs of " + appname + " on port " + port + ".");
    else
      return NULL;
  }

  foreach install (installs)
  {
    # Strip the trailing slash from the dir, if it has one
    dir = ereg_replace(string:install['path'], pattern:'^(/.*)/$', replace:"\1");
    if (dir == '/') dir = '';
    ret = make_list(ret, dir);
  }

  return ret;
}

##
# Finds installations of a web application.
#
# @param all             Whether all contrel regexes need to match, default TRUE
# @param appname         The name of the web application
# @param checks          An array with nested lists of regexes
#
# @param add_headers     Passed to [http_network#http_send_recv3]
# @param content_type    Passed to [http_network#http_send_recv3]
# @param cpe             Passed to [add_install], optional
# @param vendor          Passed to [add_install], optional
# @param product         Passed to [add_install], optional
# @param data            Passed to [http_network#http_send_recv3]
# @param exit_on_fail    Passed to [http_network#http_send_recv3], default TRUE
# @param fetch404        Passed to [http_network#http_send_recv3]
# @param follow_redirect Passed to [http_network#http_send_recv3]
# @param host            Passed to [http_network#http_send_recv3]
# @param method          Passed to [http_network#http_send_recv3], default "GET"
# @param no_body         Passed to [http_network#http_send_recv3]
# @param only_content    Passed to [http_network#http_send_recv3]
# @param password        Passed to [http_network#http_send_recv3]
# @param port            Passed to [http_network#http_send_recv3], required
# @param target          Passed to [http_network#http_send_recv3]
# @param transport       Passed to [http_network#http_send_recv3]
# @param username        Passed to [http_network#http_send_recv3]
# @param version         Passed to [http_network#http_send_recv3]
#
# @return The value from running [add_install] on each instance.
##
function find_install(
  add_headers, all, appname, checks, content_type, cpe, data, dirs,
  exit_on_fail, fetch404, follow_redirect, host, method, no_body,
  only_content, password, port, product, target, transport, username, vendor
)
{
  local_var dir, installed, installs, matched, matches, regex;
  local_var regexes, res, url, version;

  # Sanity check parameters.
  if (isnull(appname) || isnull(checks) || isnull(dirs) || isnull(port))
    return NULL;

  # Set defaults.
  if (isnull(all))
    all = TRUE;
  if (isnull(exit_on_fail))
    exit_on_fail = TRUE;
  if (isnull(method))
    method = "GET";
  if (isnull(cpe))
    cpe = '';

  installs = NULL;

  foreach dir (dirs)
  {
    installed = FALSE;
    version = NULL;

    foreach url (keys(checks))
    {
      dbg::log(src:SCRIPT_NAME,
               msg:"webapp_func.inc: Requesting "+dir+url);
      # Request the page from the web server.
      res = http_send_recv3(
        item            : dir + url,

        add_headers     : add_headers,
        content_type    : content_type,
        data            : data,
        exit_on_fail    : exit_on_fail,
        fetch404        : fetch404,
        follow_redirect : follow_redirect,
        host            : host,
        method          : method,
        no_body         : no_body,
        only_content    : only_content,
        password        : password,
        port            : port,
        target          : target,
        transport       : transport,
        username        : username,
        version         : version
      );

      # Get the regexes that we'll be using to process this page.
      regexes = checks[url];

      # Ensure that the control regexes match, so we're confident that
      # we have the page we expected.
      matched = 0;
      foreach regex (regexes[0])
      {
        dbg::log(src:SCRIPT_NAME,
                 msg:"webapp_func.inc: Checking control regex "+regex);
        if (!egrep(string:res[2], pattern:regex))
          continue;

        dbg::log(src:SCRIPT_NAME,
                 msg:"webapp_func.inc: control regex matched!");
        matched++;
        if (!all)
          break;
      }

      # If the page didn't live up to our expectations, move on to the
      # next URL.
      if (matched == 0 || (all && matched != max_index(regexes[0])))
        continue;

      # Remember that we did find the page we expected, so the
      # application is definitely installed.
      installed = TRUE;

      # Extract the version number from the page. Try every regex
      # until one works.
      foreach regex (regexes[1])
      {
        dbg::log(src:SCRIPT_NAME,
                 msg:"webapp_func.inc: Checking version regex "+regex);
        matches = pregmatch(string:res[2], pattern:regex, icase:TRUE);
        if (!isnull(matches))
        {
          version = matches[1];
          dbg::log(src:SCRIPT_NAME,
                 msg:"webapp_func.inc: version regex matched!");
          break;
        }
      }

      # If we've got a version number, we've no reason to continue.
      if (!isnull(version))
        break;
    }

    # If we haven't discovered an installation on any of the URLs,
    # then we'll move on to the next directory.
    if (!installed)
      continue;

    # Register the installed instance.
    installs = add_install(
      installs : installs,
      port     : port,
      dir      : dir,
      appname  : appname,
      vendor   : vendor,
      product  : product,
      ver      : version,
      cpe      : cpe
    );

    # Only continue looking for additional installations if we're being
    # thorough.
    if (!thorough_tests)
      break;
  }

  return installs;
}

##
# Gets PHP version and source from the KB
# @param port number of the web server where PHP was detected
# @param exit_on_fail if TRUE, exits.  FALSE by default
#
# @return an array if PHP was found in the KB
# ("ver" => detected version, "src" => source used to identify the source)
# Otherwise NULL
##
function get_php_from_kb(port, exit_on_fail)
{
  local_var php, match, src, ver, ret;

  if (isnull(port))
  {
    err_print("get_php_from_kb() missing required argument 'port'.");
    return NULL;
  }
  if (isnull(exit_on_fail)) exit_on_fail = FALSE;

  ret = NULL;

  php = get_kb_item('www/php/' + port + '/version');
  if (isnull(php))
  {
    if (exit_on_fail)
      exit(0, "The 'www/php/"+port+"/version' KB item is missing.");
    else
      return NULL;
  }
  match = pregmatch(string:php, pattern:'(.+) under (.+)$');
  if (!isnull(match))
  {
    ver = match[1];
    src = match[2];
    src = ereg_replace(string:src, pattern:", $", replace:"");

    ret = make_array(
      'ver', ver,
      'src', src
    );
  }
  return ret;
}

# Checks for existance of a plugin / extension for webapp.  Useful for
# WordPress plugins, Joomla extesions, etc.
#
# @param all             Whether all regexes need to match, default TRUE
# @param checks          An arrary with lists of regexes
# @param dirs            A list of dirs to test
# @param ext             The name of the webapp extension
#
# @param add_headers     Passed to [http_network#http_send_recv3]
# @param content_type    Passed to [http_network#http_send_recv3]
# @param data            Passed to [http_network#http_send_recv3]
# @param exit_on_fail    Passed to [http_network#http_send_recv3], default TRUE
# @param fetch404        Passed to [http_network#http_send_recv3]
# @param follow_redirect Passed to [http_network#http_send_recv3]
# @param host            Passed to [http_network#http_send_recv3]
# @param method          Passed to [http_network#http_send_recv3], default "GET"
# @param no_body         Passed to [http_network#http_send_recv3]
# @param only_content    Passed to [http_network#http_send_recv3]
# @param password        Passed to [http_network#http_send_recv3]
# @param port            Passed to [http_network#http_send_recv3], required
# @param target          Passed to [http_network#http_send_recv3]
# @param transport       Passed to [http_network#http_send_recv3]
# @param username        Passed to [http_network#http_send_recv3]
# @param version         Passed to [http_network#http_send_recv3]
#
# @return Boolean : TRUE if extension is found / FALSE if not
##
function check_webapp_ext(
 all, checks, dir, ext, add_headers, content_type, data, exit_on_fail,
 fetch404, follow_redirect, host, method, no_body, only_content, password,
 port, target, transport, username, version
)
{
 local_var res, matched, found, url, regexes, regex;

 if (isnull(checks)  || isnull(dir))
   return NULL;

 # Defaults
 if (isnull(all))
   all = TRUE;
 if (isnull(exit_on_fail))
   exit_on_fail = TRUE;
 if (isnull(method))
   method = "GET";

 foreach url (keys(checks))
 {
   found = FALSE;
   res = http_send_recv3(
     item            : dir + url,
     add_headers     : add_headers,
     content_type    : content_type,
     data            : data,
     exit_on_fail    : exit_on_fail,
     fetch404        : fetch404,
     follow_redirect : follow_redirect,
     host            : host,
     method          : method,
     no_body         : no_body,
     only_content    : only_content,
     password        : password,
     port            : port,
     target          : target,
     transport       : transport,
     username        : username,
     version         : version
   );

   # Get the regexes that we'll be using to process this page.
   regexes = checks[url];

   # Ensure that the control regexes match, so we're confident that
   # we have the page we expected.
   matched = 0;
   foreach regex (regexes[0])
   {
     if (!egrep(string:res[2], pattern:regex))
       continue;

     matched++;
     if (!all)
       break;
   }
   # If the page didn't live up to our expectations, move on to the
   # next URL.
   if (matched == 0 || (all && matched != max_index(regexes[0])))
     continue;

   # Web app ext found
   found = TRUE;
   replace_kb_item(name:'www/'+port+'/webapp_ext/'+ext+' under '+dir, value:TRUE);
   break;
 }
 return found;
}

# Given a list of paths and ports, check for a pattern in the http
# response that matches a known web app.
#
# @param paths List of paths to check.
# @param port Port web app is running on.
# @return Array containing the first successful path/port combination 
#         or NULL if none.
function get_web_app_path(paths, port, pattern)
{
  foreach var path(paths)
    if(http_get_cache(item:path, port:port) =~ pattern) return path;
  return NULL;
}
