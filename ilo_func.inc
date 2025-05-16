#TRUSTED 06ab4bb30f3ff5e3f25a3d55cd9547e095d856e73d4851e6894e6c9f7e6e8522a418fb5f5deba02618a8820261bf3de42537354890cebe02333ae38000dba04355fa944ae4bad9966981eaf03af012d273f0c575e1b14358e0b5ae9d9459395ca5350e57eac41ee968b3eb6e7169e7271b8c33727e64fa8e1b09808ae574be9cb5f766a0707ecf413e10151333b289d96794092e01cb3ceadb3e4b6d384c5ba462ef00d6c0a80702f0b766bc49e3643c31455c272fbb2de59bb16012af1c4fa416832f5e13b5de5ddef2aae64426ba57ef8f32999c88cdca91ad1047ffd0d7dfbce10de7ee8ebdca1afa0d5dcf7744594c2cf3b86e785bce923d7cc82b53ac8972a8daa1c18089d1521d3e250a6a7ad12a0231cde0a72dd12736cecae3f2fb67b00090fe0c5c02353247f5d4f8ca199a44d5773adf232096c024e7b25816a69411a1b330fc1146b22972087711c41c4f31efc4dee88c908cf62e2419245e166f299eea7551aa72788e9b7adbf2219a93101df7adcbbafa25ffeb1a7d8d7ab33c02676da5afb4e3f01f77a270e068f94f689a2ab8f2ce86f477eea0ea2da4198179e4dc45854ff67f2589007a3e53cba48e02c5727d9f78fd98fd405805bcc0ad6e36e98f4fe03f6fe775d1f5ff42e87f4a1974d3abef1898edc6b47f7e977b09f74e101c5b3f0af4d61ac6b54cfd3fa1a94a3895a19dfc08024f8b73028c513e
#TRUST-RSA-SHA256 05d8d7113107eeaf7ee11c944d163361ad6d5d825d3002e9978e512cc4a15ce5c60f6553cd2663580b7981bdf72789f16aa1acf6d971bafb77ddb559f015c0abd360d5b3b2c69246e4dcf37c20e9de28bbb77e976e854d86e0f203ce3d1079f61de58247db6d7fc3c443d60585bb0b28668aa3d6cbdfcf83d0abc4f7240dc913702d9af0a0d1fb011f5c999ccb6f4d00b79cedd249e6c85173277818f42820624662fa9864eb4543581e795ab8bd65fd2118f24711d03afb709730e825103b83857bb81be817f727b3c2c3127d66291abc05d0c4d79ff5c8494d6eb2f628769b5cf8ebc0ca5b0b711460d6fbcb32d67fa88d9488e89f28b035f73d21534e537c2493345c16169589d3aadb38b03e62b11ae0e9d4e3c39ba7c5c92865a456e9fc46987577041b1e7ced9bb92dd858acb39f0fca3eebf4a80e0c7b737ee96b7e95036ff3fb5945181153ceca4abb2c5b83fa090cb01ce0ce9f9e106a098cd23aecb24c3da74aac1bc348c424a4448c1453491193ce59edac9bd995384e9f3f545ab58fb38f68117e7d02bfcc5ce83b75fbf33e5591a0a6c6dea3da23a97ee4022ff045a7a6da60d60031fe90bf28c47cd2efbad76c8c0f8d1f2df9516bc4d6a6dd205e866ec4d0a0e21a9808e3d4170a2fef63f7fd66d1aa6fec595e92f76ba228d283aafa47410ff3369a26474c690c574629d9d620dc875407b19ece4763ba45
##
# (C) Tenable Network Security, Inc.
#
# ilo_func.inc
#
##

include('debug.inc');
include('host_os.inc');
include('http.inc');
include("http_nlib.inc");
include('install_func.inc');
include('json.inc');
include('obj.inc');
include('path.inc');
include('webapp_func.inc');

##
# Extract the contents of the given xml tag without attributes.
#
# @anonparam tag The tag to search for.
# @anonparam xml The xml to search.
#
# @return the value between <tag> and </tag>.
##
function xml_match()
{
  local_var tag, xml;
  tag = _FCT_ANON_ARGS[0];
  xml = _FCT_ANON_ARGS[1];

  xml = str_replace(string:xml, find:'\n', replace:"");

  local_var m;
  m = pregmatch(
    string  : xml,
    pattern : "<" + tag + ">(.*?)</" + tag + ">"
  );

  if (isnull(m))
    return NULL;

  return m[1];
}

##
# Parse & return a numeric value given a pattern.
#
# @param value - value to extract number from
# @param pattern - regex to be extract number with
#
# @Numeric value from element. Or NULL if no match is found.
##
function parse_numeric_element(value, pattern)
{
  local_var m;
  m = pregmatch(string  : value, pattern : pattern);

  if (isnull(m))
    return NULL;

  return int(m[1]);
}

##
# Parse the response from xmldata?item=all
#
# @param xml The xml string to parse.
#
# @return A hash with data from xmldata?item=all if enabled, or an empty
#  hash if iLO is detected but this feature (Insight Management integration)
#  is not.
##
function parse_xmldata_all()
{
  local_var xml;
  xml = _FCT_ANON_ARGS[0];
  xml = str_replace(string:xml, find:'\n', replace:"");

  # Host is iLO, but xmldata is disabled.
  if (xml =~ "<RIMP>\s*</RIMP>")
  {
    dbg::log(src:SCRIPT_NAME,msg:"xmldata disabled");
    return make_array();
  }

  if (xml !~ "<PN>.*?Integrated Lights-Out .*?</PN>")
  {
    dbg::log(src:SCRIPT_NAME,msg:"xmldata does not contain expected PN values");
    return NULL;
  }

  dbg::log(src:SCRIPT_NAME,msg:"target returned xml: \n" + xml + "\n\n");

  # We will populate this with data from the XML file.
  local_var info;
  info = make_array();


  # The PN element contains the full iLO name, including generation.
  local_var pn_element;
  pn_element = xml_match("PN", xml);

  # Attempt to parse PN element, and if successful store generation in info.
  local_var generation;
  generation = NULL;
  if (!isnull(pn_element))
  {
    if (pn_element == "Integrated Lights-Out (iLO)")
      generation = 1;
    else
      generation = parse_numeric_element(value:pn_element, pattern:"^Integrated Lights-Out (\d+)");

    ##
    #   pn_element may include both 'integrity' and 'proliant',
    #   so the order matters here
    ##
    if (xml =~ "integrity")
      info["cardtype"] = "Integrity";
    else if (xml =~ "proliant")
      info["cardtype"] = "Proliant";
    else
      info["cardtype"] = "Unknown";
  }

  if (!isnull(generation))
    info["generation"] = generation;

  # Retrieve and store the firmware version.
  local_var firmware;
  firmware = xml_match("FWRI", xml);
  if (!isnull(firmware))
    info["firmware"] = firmware;

  # Retrieve and store the model of the ProLiant server.
  local_var server_model;
  server_model = xml_match("SPN", xml);
  if (!isnull(server_model))
    info["server_model"] = server_model;

  # Retrieve and store Single Sign-On status. Unavailable in iLO1.
  local_var sso;
  sso = xml_match("SSO", xml);
  if (!isnull(sso))
    info["sso"] = sso == "1";

  return info;
}

##
# /xmldata?item=All is (if not disabled) available for all iLO generations
# and across http and https. Contains all data able to be collected.
# Here we request it from the supplied port and parse its results.
#
# @anonparam port The port to make requests to.
#
# @return NULL if unsuccessful, data from parse_xmldata_all otherwise.
##
function detect_xmldata_all()
{
  local_var port;
  port = _FCT_ANON_ARGS[0];

  local_var res;
  res = http_send_recv3(
    port   : port,
    method : "GET",
    item   : "/xmldata?item=All"
  );

  if (isnull(res) || isnull(res[2]))
    return NULL;

  return parse_xmldata_all(res[2]);
}

##
# /upnp/BasicDevice.xml contains all data able to be collected.
# We request this if /xmldata?item=All request did not provide us w/ the required version information.
# It is also an indication we are dealing w/ a moonshot device.
# See https://jira.eng.tenable.com/browse/RES-40906 for more details.
# Here we request it from the supplied port and parse its results.
#
# @anonparam port The port to make requests to.
#
# @return NULL if unsuccessful, data from parse_basic_device() otherwise.
##
function detect_upnp_basic_device()
{
  local_var port;
  port = _FCT_ANON_ARGS[0];

  local_var res;
  res = http_send_recv3(
    port   : port,
    method : 'GET',
    item   : '/upnp/BasicDevice.xml'
  );

  if (isnull(res) || isnull(res[2]))
    return NULL;

  return parse_basic_device(res[2]);
}

##
# Detect iLO over https, which behaves differently than http.
# Over https, we will reach the login page when we request / and
# requests to /json/login_session will not lead to a redirect.
#
# We start by requesting the login page at /. If iLO3-4, we go on
# to request /json/login_session which will give us the firmware version.
#
# @anonparam port The port to make requests to.
#
# @return make_array(generation) if iLO1-2, "version" as well if
#   iLO3-4 and it can be derived. Return NULL if iLO is not detected.
##
function detect_https()
{
  local_var port;
  port = _FCT_ANON_ARGS[0];

  # Over https, this will retrieve the login page.
  local_var res;
  res = http_send_recv3(
    port   : port,
    method : "GET",
    item   : "/"
  );

  if (isnull(res) || isnull(res[2]))
    return NULL;

  local_var m;

  ##
  #  Vendor name in copyright, but with variations:
  #    Copyright 2012 Hewlett-Packard Development Company
  #    Copyright 2006-2016 Hewlett Packard Enterprise Development LP
  ##
  if (("Hewlett-Packard" >!< res[2] && "Hewlett Packard" >!< res[2]) ||
      ("Development Company" >!< res[2] && "Enterprise Development" >!< res[2]))
  {
    dbg::log(src:SCRIPT_NAME,msg:"/ output does not contain vendor name.");
    return NULL;
  }

  local_var info;
  info = make_array();

  if (
    ("<TITLE>HP Integrated Lights-Out Login</TITLE>" >< res[2]) ||
    ('class="loginTitle">Integrated Lights-Out </span>' >< res[2])
  )
  {
    info["generation"] = 1;
  }
  else if (
    ("<TITLE>HP Integrated Lights-Out 2 Login</TITLE>" >< res[2]) ||
    ('class="loginTitle">Integrated Lights-Out 2 </span>' >< res[2])
  )
  {
    if ("sso=1;" >< res[2])
      info["sso"] = TRUE;
    else if ("sso=0;" >< res[2])
      info["sso"] = FALSE;

    info["generation"] = 2;

    if (res[2] =~ "integrity")
      info["cardtype"] = "Integrity";
    else if (res[2] =~ "proliant")
      info["cardtype"] = "Proliant";
    else
      info["cardtype"] = "Unknown";

  }
  else if ("<title>iLO 3</title>" >< res[2] || 'id="titleHeading">Integrated&nbsp;Lights-Out&nbsp;3</h1>' >< res[2] || 'class="loginTitle">Integrated Lights-Out 3' >< res[2])
  {
    info["generation"] = 3;
  }
  else if ("<title>iLO 4</title>" >< res[2] || 'id="titleHeading">iLO&nbsp;4</h1>' >< res[2])
  {
    info["generation"] = 4;
  }
  // iLO 5 main screen loads login iframe
  else if ('<title>Login</title>' >< res[2] && 'src=js/iLO.js' >< res[2] && 'html/login.html' >< res[2])
  {
    // Check iLO 5 login iframe
    local_var res5;
    res5 = http_send_recv3(
      port   : port,
      method : 'GET',
      item   : '/html/login.html'
    );

    if (isnull(res5) || isnull(res5[2]))
      return NULL;

    if ('id=titleHeading>iLO 5</strong>' >< res5[2])
    {
      info['generation'] = 5;
    }
  }
  else
  {
    return NULL;
  }

  # iLO1-2 do not have /json/login_session
  if (info["generation"] < 3)
    return info;

  local_var res_login = http_send_recv3(
    port   : port,
    method : "GET",
    item   : "/json/login_session"
  );

  if (isnull(res_login) || isnull(res_login[2]))
  {
    dbg::log(src:SCRIPT_NAME,msg:"/json/login_session not available. Trying to pull version from the HTML");
    # try to detect the version from the HTML
    local_var ver = detect_version_html(html:res[2]);

    if (!isnull(ver))
    {
      dbg::log(src:SCRIPT_NAME,msg:"Firmware version successfully pulled from the HTML");
      info["firmware"] = ver;
    }
    return info;
  }

  local_var json;
  json = json_read(res_login[2]);

  if (isnull(json) || isnull(json[0]) || isnull(json[0]["version"]))
    return info;

  info["firmware"] = json[0]["version"];

  return info;
}

function detect_version_html(html)
{
  local_var ver;

  ver = pregmatch(string:html,
                  pattern:"Firmware Revision (\d+(\.\d+)*)");

  if (!isnull(ver))
    ver = ver[1];

  return ver;
}

##
# This function detects iLO1-2 over HTTP.
#
# In iLO1-2, HTTP / leads to a redirect portal. We parse it to
# learn the generation of iLO.
#
# @anonparam port The port to make the request to.
#
# @return make_array(generation). "sso" may be present if iLO2.
#   Returns NULL if iLO1-2 is not detected.
##
function detect_http()
{
  local_var port;
  port = _FCT_ANON_ARGS[0];

  local_var res;
  res = http_send_recv3(
    port   : port,
    method : "GET",
    item   : "/"
  );

  if (isnull(res) || isnull(res[2]))
    return NULL;

  local_var headers;
  headers = parse_http_headers(status_line:res[0], headers:res[1]);

  # iLO3-4 will return an http redirect.
  if (headers["$code"] != 200)
    return NULL;

  local_var info;
  info = make_array();

  # At this point, if this is iLO, we are at the redirect portal for iLO1 or iLO2.
  if (
     ('document.title="Integrated Lights Out 2: "' >< res[2]) ||
     ('class="loginTitle">Integrated Lights-Out 2 </span>' >< res[2])
  )
  {
    info["generation"] = 2;

    if (res[2] =~ "integrity")
      info["cardtype"] = "Integrity";
    else if (res[2] =~ "proliant")
      info["cardtype"] = "Proliant";
    else
      info["cardtype"] = "Unknown";

  }
  else if (
    ('document.title="Integrated Lights Out: "' >< res[2]) ||
    ('class="loginTitle">Integrated Lights-Out </span>' >< res[2])
  )
  {
    info["generation"] = 1;
  }
  else
    return NULL;

  return info;
}

##
# Is the transport for the given port SSL?
#
# @anonparam port Port to lookup.
#
# @return TRUE if SSL, FALSE if not or unknown.
##
function is_ssl()
{
  local_var port;
  port = _FCT_ANON_ARGS[0];

  local_var encaps;
  encaps = get_kb_item("Transports/TCP/" + port);

  return  (!isnull(encaps) && encaps > ENCAPS_IP);
}

##
# Merges hashes.
#
# @param primary_hash The hash to merge hashes into.
# @param hash1, hash2, etc. The hashes to merge into the primary_hash.
#
# @return If all hashes are NULL, returns NULL, otherwise the merger of
#   all hashes. If an argument is NULL, it is ignored.
##
function merge_hashes()
{
  local_var primary_hash;
  primary_hash = NULL;

  local_var hash;
  foreach hash (_FCT_ANON_ARGS)
  {
    if (isnull(hash))
      continue;

    if (isnull(primary_hash))
      primary_hash = make_array();

    local_var key;
    foreach key (keys(hash))
    {
      if (!isnull(hash[key]))
        primary_hash[key] = hash[key];
    }
  }

  return primary_hash;
}

function is_moonshot_device(ports)
{
  var res, port;
  foreach port(ports)
  {
    res = http_send_recv3(port:port, method:"GET", item:"/js/nav.json");
    if(res[0] =~ "^HTTP/1\.[01] +200" && res[2] =~ 'features\" *: *\"moonshot')
      return true;
  }
  return false;
}

##
# Parse the response from /upnp/BasicDevice.xml
#
# @param xml The xml string to parse.
#
# @return A hash with data from /upnp/BasicDevice.xml, or an empty
#  hash if iLO is detected but this feature is not
##
function parse_basic_device()
{
  local_var xml;
  xml = _FCT_ANON_ARGS[0];
  # Flatten XML
  xml = str_replace(string:xml, find:'\n', replace:"");

  if (xml !~ "<modelDescription>iLO\s+[0-9]\s+in.*</modelDescription>")
  {
    dbg::log(src:SCRIPT_NAME,msg:"/upnp/BasicDevice.xml does not contain expected modelDescription values");
    return NULL;
  }
  if (xml !~ "<modelNumber>[0-9.]+</modelNumber>")
  {
    dbg::log(src:SCRIPT_NAME,msg:"/upnp/BasicDevice.xml does not contain expected modelNumber value");
    return NULL;
  }

  dbg::log(src:SCRIPT_NAME,msg:"target returned xml (BasicDevice.xml): \n" + xml + "\n\n");

  local_var info;
  info = make_array();
  local_var model_desc_element;
  model_desc_element = xml_match("modelDescription", xml);

  local_var generation;
  generation = NULL;
  if (!isnull(model_desc_element))
  {
    generation = parse_numeric_element(value:model_desc_element, pattern:"^iLO\s+([0-9])");
    if (!isnull(generation))
      info["generation"] = generation;

    ##
    #   model_desc may include both 'integrity' and 'proliant',
    #   so the order matters here
    ##
    if (xml =~ "integrity")
      info["cardtype"] = "Integrity";
    else if (xml =~ "proliant")
      info["cardtype"] = "Proliant";
    else
      info["cardtype"] = "Unknown";
  }

  local_var firmware;
  firmware = xml_match("modelNumber", xml);
  if (!isnull(firmware))
    info["firmware"] = firmware;

  local_var server_model;
  server_model = pregmatch(string:model_desc_element, pattern:"^iLO\s+[0-9]\s+in(.*)");

  if (!isnull(server_model))
    info["server_model"] = server_model[1];

  return info;
}
