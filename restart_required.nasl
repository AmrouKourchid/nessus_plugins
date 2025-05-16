#TRUSTED 35199597afed6731f2aaa2d23b071da01d275a4339c18c138aa8d565b122075a5caad8cfb6480391fb4788b31710ecdb6b88eb26dbb7dd644f7111c36440d6c392277673edfd54e10269475855e2344df85609813fec01cf9b91fc85a0d5af0cbbb40972c30f0dd0d9cb6e7f04273cb480ed60dbb6c9f192bfbdc44b41d5b7e379318a161e923408fe1b927edce3353fb20937b77224b3c9d471f49da65189fbbeff0d45d0927d566d0b528417b5b7a8ec27bd6f505764b5bf60fa8434079aeb5489c192ad284320dc655e8593139d7cacecb958ed42de95f9d83ecf93e051501b1cf73493d0606c5ad673ac7c4640c25306fbf427bf8899d50ff2f68d81d1c1dff8b56acd8f91f2d0987de128e95847e30bda04b172744dc849fb6eaa760d3fca2635e50039177cf4185166d3badae295b6f945e5153189954d1bfff584c45cb232d05f3f98084a5fc6e68763828afc5512ed0850f853de29adeddfca124b0122bae810996ee929896e837ea433d72c9820b6db665cd7553e7f712299e9648fc6d96adb7de89b12cb437c1002983b6b4bc319922de027be28327fd533aa67e8e164e5430aba1dcf578a5ad318289e1a9429d3cdd01f416f78448fa383c2d333e3e5b4a8e296f0cae7157e187e161774f83640724e50a60c8fc673bef58bee89c136d648c86a365860b40172b3afde62d58ba04e3d2026c361d1229e1cdb79cc
#TRUST-RSA-SHA256 81720f740e96f801b0a13ff1889ecfa9438d28ad3aeb17e76cc0397c9bf16e1c61468a56c3f69869af9358787cce935a129b519aa8c02f9c68efa3b4eb996c1c6be06b68c9f1e13bf6b7f8edaf59404515aa09b33cff6c5c1e95167703906a9f8371069e924cfe3d90fe3e4295eade77f1a0ab38bbae4cf732034944f4ae39d699afdf05d428dc1cf9b91b4318e769d8f17a3fe9fb5afde7fdf21c216c10bc2fb5879d247191a0fc6ca3bcf7bc590574e297221fdf86ca3755f9db5c30493430a37e6d3c0b2189dc06f256e581da2f7f54a10609d7fb9e4a33abddceea997a99372ad383ad0e0cf07c93108d3f52fe0a6903230e76d408ef0b4a6d50ad148848653f16e1ef6d104f12f688b71020ad9c60f7f08a67ea80cee68539775f041166dfc1853ea77f725a168394dbdc47e748f2195c5f7603ec8bfd5d57359e19f7e3059d79c0833c1ca3f60b5624c405c2b2c1ec10aad30a127e16856a9ab5677f833db3fe0eeeaa6f96b86fbcf79514d106a3efd0fc165c3a043cc11cfe9e1536ce33cd7d9f13b12c067b60553055c979a7a1edfb9b1411f925287a3a8e5ae7381ea8ead64cfebe3bd161ed96c60162733f6c56c5a131f6e1aec06bc62c61de1cd29b01f5efa0f3992078d0d2ee139b62e763019289a9b462db4b1dc59fbf5b212096df873b7654af004fedf12a5f8043155bb203a2010c89c681912bf1ea1c48f6
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(163103);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/23");


  script_name(english:"System Restart Required");

  script_set_attribute(attribute:"synopsis", value:
  "The remote system has updates installed which require a reboot.");
  script_set_attribute(attribute:"description", value:
"Using the supplied credentials, Nessus was able to determine that the remote system has updates applied that require
a reboot to take effect. Nessus has determined that the system has not been rebooted since these updates have been
applied, and thus should be rebooted.");
  # https://access.redhat.com/solutions/27943
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9e9ce1c1");
  # https://www.debian.org/doc/debian-policy/ch-opersys.html#signaling-that-a-reboot-is-required
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd8caec2");
  script_set_attribute(attribute:"solution", value:"Restart the target system to ensure the updates are applied.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Linux");

  exit(0);
}

include('rpm.inc');
include('debian_package.inc');
include('ubuntu.inc');
include("ssh_func.inc");
include("hostlevel_funcs.inc");
include("datetime.inc");
include('local_detection_nix.inc');

# Check whether the package install date is more recent than the uptime
# today - uptime gives us the last boot date
# if last boot date is less than the rpm_install_time,
# the package was installed after the last boot
function pkg_installed_after_last_boot(uptime, today, rpm_install_time)
{
  if (empty_or_null(uptime) || empty_or_null(today) || empty_or_null(rpm_install_time))
    audit(AUDIT_HOST_NOT, "providing valid date information.");

  var last_boot = today - uptime;
  dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'comparing pkg time with last boot: uptime: '+uptime+', today: '+today+', rpm_install_time: '+rpm_install_time+', last_boot: '+last_boot+'\n');

  if ( last_boot < rpm_install_time )
    return TRUE;
  return FALSE;
}

function restart_required_zypper()
{
  var report = '';
  var reboot_needed_path = '/run/reboot-needed';
  if (ldnix::file_exists(file:reboot_needed_path))
  {
    dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'reboot_needed file exists\n');
    report += 'The reboot needed flag is set at :\n\n';
    report += reboot_needed_path + '\n\n';
  }

  return report;
}


function restart_required_apt()
{
  var reboot_required, reboot_required_exists, reboot_required_pkgs;
  var report = '';
  var reboot_required_paths = [
    {'rr':'/run/reboot-required',
     'pkgs':'/run/reboot-required.pkgs'},
    {'rr':'/var/run/reboot-required',
     'pkgs':'/var/run/reboot-required.pkgs'}
  ];

  foreach var path (reboot_required_paths)
  {
    reboot_required_exists = ldnix::file_exists(file:path['rr']);
    reboot_required_pkgs = chomp(ldnix::get_file_contents(file:path['pkgs']));
    if ( !reboot_required_exists && empty_or_null(reboot_required_pkgs) )
      continue;

    reboot_required = chomp(ldnix::get_file_contents(file:path['rr']));

    dbg::detailed_log(
      lvl:2,
      src:FUNCTION_NAME,
      msg:'Reboot required found',
      msg_details: {
        'reboot_required': {'lvl': 2, 'value': reboot_required},
        'reboot_required_exists': {'lvl': 2, 'value': reboot_required_exists},
        'reboot_required_pkgs': {'lvl': 2, 'value': reboot_required_pkgs}});

    if (!empty_or_null(reboot_required))
    {
      report += 'The reboot required flag is set :\n\n';
      report += reboot_required + '\n\n';
    }
    else if (reboot_required_exists)
    {
      report += 'The reboot required flag is present in the host.\n\n';
    }

    if ( !empty_or_null(reboot_required_pkgs) )
    {
      report += 'The following packages require a reboot :\n\n';
      report += reboot_required_pkgs + '\n\n';
    }
    break;
  }
  return report;
}

function restart_required_rpm()
{
  # for each rpm in [['kernel', 'glibc', 'linux-firmware', 'systemd', 'udev',
  #            'openssl-libs', 'gnutls', 'dbus']
  # if float(pkg.installtime) > float(boot_time)
  #     reboot required
  # see https://access.redhat.com/solutions/27943

  var rpm_install_time, match, pattern, rpm_name, report;
  var rpm_list_date = get_kb_list('Host/*/rpm-list');
  var rebootpkgs = ['kernel', 'glibc', 'linux-firmware', 'systemd', 'udev', 'openssl-libs', 'gnutls', 'dbus'];
  var today_cmd = 'date \'+%s\'';
  var uptime_file = '/proc/uptime';
  var date_format_pattern = "^\w{3}\s+\w{3}\s+\d{2}\s+\d{2}\:\d{2}\:\d{2}\s+\d{4}$";
  var today = int(chomp(info_send_cmd(cmd:today_cmd)));
  var uptime = ldnix::get_file_contents(file:uptime_file);

  if ( empty_or_null(uptime) || empty_or_null(today) )
    return '';

  uptime = split(uptime, sep:' ');
  uptime = int(uptime[0]);

  dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'today: '+today+', uptime: '+uptime+'\n');

  if ( uptime == 0 || today == 0 )
    audit(AUDIT_HOST_NOT, "providing valid date information");

  if(!empty_or_null(rpm_list_date))
  {
    # split rpm-list on \n
    foreach var key (list_uniq(keys(rpm_list_date)))
    {
      foreach var rpm (split(rpm_list_date[key], sep:'\n', keep:TRUE))
      {
        foreach var pkg (rebootpkgs)
        {
          pattern = "^"+pkg+"-[^-]+-[^\|-]+\|\S+\s+([^|]*).*$";
          match = pregmatch(pattern:pattern, string:rpm);
          if ( match && match[1] )
          {
            # Sanity check the date format even though it is enforced by Nessus
            if(pregmatch(pattern:date_format_pattern, string:match[1]))
              rpm_install_time = logtime_to_unixtime(timestr:match[1]);
            else
            {
              dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'unreadable date format for rpm entry: ' + rpm);
              continue;
            }

            dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'checking pkg: '+pkg+', on host with uptime: '+uptime+', today: '+today+', and rpm_install_time: '+rpm_install_time+'\n');
            if ( rpm_install_time == 0 )
              continue;

            if ( pkg_installed_after_last_boot(uptime:uptime, today:today, rpm_install_time:rpm_install_time) )
            {
              # Showing only the package name, version, release and epoch in the report
              rpm_name = rpm - '      ' - match[1];
              report += '    ' + rpm_name + '\n';
            }
          }
        }
      }
    }
  }
  return report;
}

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var uname=get_kb_item("Host/uname");
if(empty_or_null(uname)) audit(AUDIT_KB_MISSING, "Host/uname");
else if("Linux" >!< uname) audit(AUDIT_OS_NOT, "Linux");

enable_ssh_wrappers();

info_connect(exit_on_fail:TRUE);

var report, report_flag = "";
var debian, rhel;

if ( !empty_or_null(get_kb_list('Host/*/rpm-list')) )
{
  report = restart_required_rpm();

  if ( get_kb_item("Host/SuSE/release") )
  {
    report_flag = restart_required_zypper();
  }
}
# Ubuntu OS populates the Host/Debian/dpkg-l KB list
else if ( !empty_or_null(get_kb_list('Host/*/dpkg-l')) )
{
  report = restart_required_apt();
}
else
{
  if (info_t == INFO_SSH) ssh_close_connection();
  audit(AUDIT_HOST_NOT, 'supported by this check.');
}
if (info_t == INFO_SSH) ssh_close_connection();

dbg::detailed_log(lvl:2, src:SCRIPT_NAME, msg:'got report info: '+report+'\n');

if (!empty_or_null(report) || !empty_or_null(report_flag))
{
  if (!empty_or_null(object:report))
    report = 'The following security patches require a reboot but have been installed since the most recent system boot: \n\n' + report + '\n\n';
  if (!empty_or_null(object:report_flag))
    report += report_flag;
  security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);
}
else
  audit(AUDIT_HOST_NOT, 'affected');
