#TRUSTED 6885a2ca6e84a7c647d001bcdc7df8d52b145d2f5b05ce1905b8e1e9d2005caa4c65b702606802cb805e7bdee4b6d582a8c8d5bd1447720c67bbf578aa2b93be426c54db55cf84f6d100bb347baa05cc80d8b306509fbe3b7e3bd1307ea5faf5ef7c6de5949586fb7f1d24932f5f48ef17334eaa7a11883d75b47e991eec8ffa0e071c7cf730397fc76eaf5183397f4a7ab559b2a3e95c37b2fcfdfa1add4c17882a06e632e658939399e471ee3d1e40b71b410a4f12992289713e2f2a16540fa732fe2ce5edeb6a8e3b33796c70ba2c83fa99dfbdc8f96acb09177a9f5c0a3998463d818b4c9150dc5afb2171634d0c5c49f2b9549e210372dc28e0139b23d375bfb43e965a36fec84821dfd5b3361b4cc01a1c852d6254b1dc7887c239eb7e99a0f63c7ceb32073f33aea5fbd8fccbab0cf7d14c253f2cbbbdf412af2000f88b5fdaafb399aa0521ad2939c9092586d7ac62d9abe5dae583fbccbc9b8ea305811472143b814e403ebbd4b0e27f26d157f24c9b53e5da04820ff40b70055aa21af802ce460f67b87c67109462e92273e907d2f8afeb44b22636579743a96ffe8a999c836285b0a1b215b27768ed2885061759f40b34925ca242ae11f991f44a92caf2fcd29503610cba8bdb4b3351049ce267ef46c8a266c8a07a383e3915b9a3f496d21b0f5acccc42322fd3795be9336b4833785bf8f9e9f36aff581f0fa5
#TRUST-RSA-SHA256 005654194509ecdf03540fff4aa8094f122ef637786a8fe72615bd82ec9700034fc6a86db9b846f03cd7a2bc764f956aeac19c5559cacb2313102d57d365c4795c38648b2d7cfea9bc458aa9bb66b20009999cd765d40841f5ba29eebbd6d8ae457da38f80463d6961179fabd3ed1c814b6bf59201cabf2c26e32d7fa13ebbbe07f60ad30bae3f2f9b87cdd7ce482e485cc3a2bdec5af1c02fad786672bcf9c418c3f568b23c948c369fcc2a924e5ae012c05e2c0c3531cb6c6147073559bb93fa57c987a82b63440e48bea9b709be17fc119c0e1caf2529dc87dacc43834e5b03fa526d22588a8bd4ebc62cb30f1e69286615ea5d0f28cfbf8a60bcca7ddd3b82034a9e1651011aad6bf1d76acd45bffaf0df862d1e2dc41c48a12e78784a7bfa1d461f461e81af586cc3797da982ff415d21960db127fb51fc6969df09080c453e49d35d049e3ea5e4f1bbda636529e13fa2d2f164dd9b7469caae9aa3d2cbd0f27361a83540268f0fdcaf63467e2c6d97f693a897c7b64ffc69d952560eeb2eefa760ce050d616b39302cc6ea28a576d365a05f2367f9f62269a1e96a6163e6cbc03df51d70ad0b3b77c8a56d137f3bfc2d92a7225330abde7ae5a6c84d6e8e0a6d6072112ab93509f802b461ddd5f4c5338c02f8a43a0cf1ec16b3fbbdf8d3473c4f3cd52b1e50cfadba5875928208e533c4721175b9c5a97d4ec7e50f59
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(58501);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_name(english:"iTunes Mobile iOS Device Backup Enumeration (Mac OS X)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host is used to backup data from a mobile
device.");
  script_set_attribute(attribute:"description", value:
"The iTunes install on the remote Mac OS X host is used by at least
one user to backup data from a mobile iOS device, such as an iPhone,
iPad, or iPod touch.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT1766");
  script_set_attribute(attribute:"solution", value:
"Make sure that backup of mobile devices agrees with your
organization's acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "macosx_itunes_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/iTunes");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("hostlevel_funcs.inc");


enable_ssh_wrappers();

function parse_device_info(data)
{
  local_var section, value, idx_start, idx_end, datakey;
  local_var device_data, datakeys;

  device_data = make_array();

  datakeys = make_list(
    'Device Name',
    'Last Backup Date',
    'Product Type',
    'Product Version',
    'Serial Number'
  );

  foreach datakey (datakeys)
  {
    section = '';
    value = NULL;
    # Extract each relevant key/value pair
    idx_start = stridx(data, '<key>'+datakey+'</key>');
    if (datakey == 'Last Backup Date')
      idx_end = stridx(data, '</date>', idx_start);
    else
      idx_end = stridx(data, '</string>', idx_start);
    if ((idx_start >= 0) && (idx_end > idx_start))
    {
      section = substr(data, idx_start, idx_end);
      section = chomp(section);
    }

    # Extract the vale from the key/value pair
    if (strlen(section) > 0)
    {
      if (datakey == 'Last Backup Date')
      {
        idx_start = stridx(section, '<date>');
        if (idx_start >= 0)
        {
          value = substr(section, idx_start);
          value -= '<date>';
          value -= '<';
        }
      }
      else
      {
        idx_start = stridx(section, '<string>');
        if (idx_start >= 0)
        {
          value = substr(section, idx_start);
          value -= '<string>';
          value -= '<';
        }
      }
    }
    if (!isnull(value))
    {
      device_data[datakey] = value;
    }
  }
  if (max_index(keys(device_data))) return device_data;
  else return NULL;
}

if (!get_kb_item('Host/local_checks_enabled')) exit(0, 'Local checks are not enabled.');

os = get_kb_item('Host/MacOSX/Version');
if (!os) exit(0, 'The host does not appear to be running Mac OS X.');

if (isnull(get_kb_item('installed_sw/iTunes'))) exit(0, 'iTunes doesn\'t appear to be installed on the remote host.');

info_connect();

invalid_path = FALSE;
template_error = FALSE;

# For each user, look for backups in
# Library/Application Support/MobileSync/Backup
numdevices = 0;
info = NULL;
cmd = '(echo ; /usr/bin/dscl . -readall /Users NFSHomeDirectory UniqueID) |while read sep; do read Home; read Record; read UniqueID; UniqueID=`echo $UniqueID | awk \'{print $2}\'`; test "$UniqueID" -gt 499 && echo $Record:|awk \'{print $2}\' && Home=`echo $Home|awk \'{print $2}\'` && test -d "$Home"/Library/Application\\ Support/MobileSync/Backup/ && echo "$Home"/Library/Application\\ Support/MobileSync/Backup/*; done';

result = info_send_cmd(cmd:cmd);
if (!isnull(result))
{
  lines = split(result, keep:FALSE);
  foreach line (lines)
  {
    devicehash = NULL;
    if ('Library/Application Support/MobileSync/Backup/' >< line)
    {
      # Replace ' /' with ';/' to make it easier to split up the hashes
      # into a list
      line = str_replace(string:line, find:' /', replace:';/');
      hashlist = split(line, sep:';', keep:FALSE);
      if (!isnull(hashlist))
      {
        for (i=0; i<max_index(hashlist); i++)
        {
          data = NULL;
          plistfile = hashlist[i] + '/Info.plist';
          plistfile = str_replace(string:plistfile, find:'Application Support', replace:'Application\\ Support');
          match = pregmatch(pattern:"(^.*)Library/Application\\ Support/MobileSync/Backup/(.*$)", string:plistfile);
          if(isnull(match) || isnull(match[1]) || isnull(match[2]))
            continue;
          cmd = "cat $1$Library/Application\ Support/MobileSync/Backup/$2$";
          args = [match[1], match[2]];

          # Parse the data in the plist file
          data = run_cmd_template(template:cmd, args:args);
          if(data["error"] != HLF_OK)
          {
            if(data["error"] == HLF_INVALID)
              invalid_path = TRUE;
            else
              template_error = TRUE;
            continue;
          }
          data = data["data"];
          if (!isnull(data) && '<?xml version=' >< data)
          {
            ret = parse_device_info(data:data);

            if (!isnull(ret))
            {
              numdevices++;
              # Build the report
              info += '\n  File path : ' + plistfile;
              info +=
                '\n    Device name      : ' + ret['Device Name'] +
                '\n    Product type     : ' + ret['Product Type'] +
                '\n    Product version  : ' + ret['Product Version'] +
                '\n    Serial number    : ' + ret['Serial Number'] +
                '\n    Last backup date : ' + ret['Last Backup Date'] + '\n';
            }
          }
          if (numdevices && !thorough_tests) break;
        }
      }
    }
  }
}

if (info_t == INFO_SSH)
  ssh_close_connection();

errors = "";
if(invalid_path)
  errors += '\n  One or more path names contained invalid characters.';

if(template_error)
  errors += '\n  An error occurred due to a command template mismatch.';

if (errors != '')
  errors = '\nResults may not be complete due to the following errors : ' + errors + '\n';

if (!isnull(info))
{
  if (report_verbosity > 0)
  {
    if (numdevices > 1)
    {
      a = 'Backups';
      s = 's were detected';
    }
    else
    {
      a = 'A backup';
      s = ' was detected';
    }
    report =
      '\n' + a + ' for the following mobile device' + s + ' :\n' +
      info +
      '\n' + errors;
    security_note(port:0, extra:report);
  }
  else security_note(0);
  exit(0);
}
else exit(0, 'No backups were detected for mobile iOS devices on the remote host.' + errors);
