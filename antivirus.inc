#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# antivirus.inc
# Revision: 1.2356
#

include("compat_shared.inc");
#pragma static(include)
include("antivirus_definitions.static");
#pragma static(include:false)

global_var _secs_in_day;

_secs_in_day = 60*60*24;


function get_av_info()
{
  local_var delay, diff, epoch, epochs, i, most_recent_epoch, now, product, product_info;

  product = _FCT_ANON_ARGS[0];
  if (isnull(product)) return NULL;

  delay = get_av_delay();

  if (product == "avast")
    product_info = _av_info_avast;
  else if (product == "avg_is")
    product_info = _av_info_avg_is;
  else if (product == "bitdefender")
    product_info = _av_info_bitdefender;
  else if (product == "checkpoint")
    product_info = _av_info_checkpoint;
  else if (product == "clamav")
    product_info = _av_info_clamav;
  else if (product == "fcs")
    product_info = _av_info_fcs;
  else if (product == "fep")
    product_info = _av_info_fep;
  else if (product == "kaspersky")
    product_info = _av_info_kaspersky;
  else if (product == "linux_sophos")
    product_info = _av_info_linux_sophos;
  else if (product == "linux_sophos_managed")
    product_info = _av_info_linux_sophos_managed;
  else if (product == "macosx_sophos")
    product_info = _av_info_macosx_sophos;
  else if (product == "macosx_sophos_home")
    product_info = _av_info_macosx_sophos_home;
  else if (product == "macosx_sophos_managed")
    product_info = _av_info_macosx_sophos_managed;
  else if (product == "macosx_xprotect")
    product_info = _av_info_macosx_xprotect;
  else if (product == "mcafee")
    product_info = _av_info_mcafee;
  else if (product == "mcafeev3")
    product_info = _av_info_mcafeev3;
  else if (product == "nav")
    product_info = _av_info_nav;
  else if (product == "nod32")
    product_info = _av_info_nod32;
  else if (product == "panda")
    product_info = _av_info_panda;
  else if (product == "savce")
    product_info = _av_info_savce;
  else if (product == "sophos")
    product_info = _av_info_sophos;
  else if (product == "spybot")
    product_info = _av_info_spybot;
  else if (product == "trendmicro")
    product_info = _av_info_trendmicro;
  else if (product == "windows_sophos_managed")
    product_info = _av_info_windows_sophos_managed;
  if (isnull(product_info)) return NULL;

  epochs = make_array();
  now = unixtime();

  # Track diffs between now and the various epochs.
  foreach epoch (sort(keys(product_info)))
  {
    if (now < int(epoch)) exit(1, "The system clock on the scanner is earlier than information in antivirus.inc.");

    diff = int((now - int(epoch)) / _secs_in_day);
    epochs[diff] = epoch;
  }
  most_recent_epoch = epoch;

  # Return info at the specified delay or older, to allow for
  # gaps in coverage.
  for (i=delay; i<=14; i++)
  {
    if (!isnull(epochs[i]))
    {
      epoch = epochs[i];
      if (!isnull(product_info[epoch])) return product_info[epoch];
    }
  }

  # nb : return the latest info available since 'now' is outside the
  #      range of dates in the include file (eg, more recent).
  return product_info[most_recent_epoch];
}

##
# Gets the Antivirus Dely, and set the corresponding kb item
#
# @return int Antivirus Delay
##
function get_av_delay()
{
  local_var delay;

  delay = get_kb_item("antivirus/delay");

  if (isnull(delay))
  {
    delay = get_preference("Antivirus Software Check[entry]:Delay (in days, between 0 and 7) :");

    if (isnull(delay)) delay = 0;
    else delay = int(delay);

    if (delay < 0 || delay > 7) delay = 0;

    replace_kb_item(name:"antivirus/delay", value:delay);
  }

  return delay;
}

##
#
# Checks if the definition date is vulnerable in accordance to the delay.
#
# @params date Date of the definitions
#
# @return bool TRUE  if the date is vulnerable or an error occured
#              FALSE if the date isn't vulnerable
##
function check_av_def_date(date)
{
  local_var now, delay, diff;

  if (isnull(date))
  {
    set_kb_item(name:"Errors/" + SCRIPT_NAME + "/check_av_def_date", value:"The date passed was a NULL value.");
    return TRUE;
  }

  now = unixtime();
  if (isnull(now))
  {
    set_kb_item(name:"Errors/" + SCRIPT_NAME + "/check_av_def_date", value:"Unixtime() returned a NULL value.");
    return TRUE;
  }

  delay = get_av_delay();
  if (isnull(delay))
  {
    set_kb_item(name:"Errors/" + SCRIPT_NAME + "/check_av_def_date", value:"get_av_delay() returned a NULL value.");
    return TRUE;
  }

  diff = int((now - int(date)) / _secs_in_day);

  if (diff > delay)
    return TRUE;
  else
    return FALSE;
}

##
# Sets the 'Antivirus/' KB items
#
# @param [app:string] AV application name
# @param [path:string] path (optional)
# @param [version:string] main version (optional)
# @param [active:boolean] flag for service status (optional)
#
# @remark replace_kb_item() is actually used since there should only be one group of KB items set
#
# @return NULL if an error occurred or TRUE if 
##
function set_av_kb_items(app, path, version, active)
{
  if (empty_or_null(app))
  {
    err_print(FUNCTION_NAME + '(): missing required argument "app".');
    return NULL;
  }

  var kb_base, attribs, attrib, report;

  kb_base = 'Antivirus/' + app;

  replace_kb_item(name:kb_base + '/installed', value:TRUE);

  attribs = {
    'path'    : path,
    'version' : version,
    'active'  : active
  };

  foreach attrib (keys(attribs))
  {
    if (empty_or_null(attribs[attrib]))
      attribs[attrib] = 'unknown';
    else
      replace_kb_item(name:strcat(kb_base, '/', attrib), value:attribs[attrib]);
  }

  report = strcat(
    '\n',
    app, ' is installed on the remote host :\n',
    '\n',
    '  Path    : ', attribs.path, '\n',
    '  Version : ', attribs.version, '\n',
    '\n'
  );

  if (empty_or_null(attribs.active) || attribs.active == 'unknown')
    report = strcat(report, 'The ', app, ' service is in an unknown state.\n');
  if (!attribs.active)
    report = strcat(report, 'The ', app, ' service is not running.\n');

  replace_kb_item(name:kb_base + '/description', value:report);

  return TRUE;
}
