#TRUSTED 15e711a8edbf545c2dc8302ef9e2e76139bbd75084b3b3d259c00ab118404ec28a0b37f767e241ed3e241b4c36c885a28babc4c438f2183e214d0d4b794da532983dfbe5a9f85bd021f9413b894747db9f0b3173e931e12a0cc7bd6c8eee7f055009b6d5a04b2e3b5d71ac63621890cc7f77fbf4d679e7e5a6045e9979751e0d8345f2aeb27930ae9b0eb5dfbd580561333af72cfe8aa9d1c3bd8cf3cd0434a1a4de0f817fa13f52186b22b2fa7798b9791f580194725ac6bf63c35e5dc41930e21d3fdca9a1f95dada34a701e391de3e1d96c5dfed67f1b1dca80b009a2f5a31ea832359bb1fd5ee3faa9b2330e38b97cc8f98c6606d51992be88774faa6d2c92d46b516de00c2513e73e85c05f67f16f08122dd97d9f660b053f80107b321380428db4eaa2b91b53996e039d702b185eba5a92a61593299e83659dfcb1a44959f37ad856c74adc16cd0eeb9f1f591a6904db717d1f982016c06c1ed3a412f8d3a95f476c0cc40dcf3db734ba75a2dec1b1a128c7c7d70926ff24813ca18452a34ad7905e367a67125f0a16f61ff071c09dc4424239495fed5a6c81574e1fe0c938f2d93e69fe8d04eb8cab50b0e3beaeaf38a5bc14d3faf79135cf7f0e08f79a57e90c978f50ccdeff2dd67f9ac203ae54df39c21447c88a713d85901918734617aa6f7d7cd011a1c595b3161d285ed11ad4e383477a67b6cf27370be72c9f
#TRUST-RSA-SHA256 2f448303d0f91900f0ed235588c754d8aa167f09af78e94eca9c4e6311fa2ad6425372b4b23f71b816c6bef219be48e829d271761b8ca4838b555deb8a5d6683550df62d8e23404520bc0f2b591b4a607480e686ce0d490281953c2cc7a760f4c73a2feb2b59d29f41a34c0ff95642f862112ae745769cd523125812f5804e3f1ed57e026dacbe77ae0c3022f1961e80d7262e3b541baef0e9fd96be8e73b5e868fa4a8a3789ade624b21dcf60de626a8221979f686258b12a49251f0ddf2e71ef8ae498ef5e4e3208e34e768caff7c41a0c1e903f2243a4357e558aeef9311a815b70193311ef2460ba8eecd029d4dca4ce0411c25023504d513ea228acc9bbd5b7e32dc404310066e91cab2e505841853090b69012444f227c17055b62731e189133ebcd639b18ed4048928b75af5e2b79269cb3ce1229ce827977407d1c1c4d7236466608dcdd7589eeb87aa4f947c13d2e73543935ae7f41dfe4dd76587baf5648e91c5882146b2ae218e9ebee794fdee9b902f4d1a0bbe8bd7b989e06450f44c92b07f03662539a9256e1fc511ac9ae22f4c8842b1951a64c6c8e37fa35172c8a845b73d9fffce6718ffad026a02b1278d38546ae8b3851844b2f2a531f7f5ccf0c0105f058d6896519f0ec51479d4c8c3fa342bbf4368e07d5bccf6131ddd0d79370129065e2fef1f6e3ae71c342db0e9c3ffde77e9d5a0f3fbcf92e2c
#
# (C) Tenable Network Security, Inc.
#


include('compat.inc');

if(description)
{
 script_id(33851);
 script_version("1.26");
 script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/06");

 script_name(english: "Network daemons not managed by the package system");

 script_set_attribute(attribute:"synopsis", value:
"Some daemon processes on the remote host are associated with programs
that have been installed manually." );
 script_set_attribute(attribute:"description", value:
"Some daemon processes on the remote host are associated with programs
that have been installed manually.

System administration best practice dictates that an operating
system's native package management tools be used to manage software
installation, updates, and removal whenever possible." );
 script_set_attribute(attribute:"solution", value:
"Use packages supplied by the operating system vendor whenever
possible.

And make sure that manual software installation agrees with your
organization's acceptable use and security policies." );
 script_set_attribute(attribute:"risk_factor",value:"None");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/08/08");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"agent", value:"unix");
 script_end_attributes();

 script_summary(english: "Checks that running daemons are registered with RPM / dpkg / emerge");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2008-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english: "Misc.");
 script_require_keys("Host/uname");
 script_dependencies("ssh_get_info.nasl", "process_on_port.nasl");
 exit(0);
}

include('ssh_func.inc');
include('telnet_func.inc');
include('local_detection_nix.inc');

enable_ssh_wrappers();

var uname = get_kb_item("Host/uname");
if ( ! uname || "Linux" >!< uname ) audit(AUDIT_OS_NOT, "Linux");;

var pkg_system = NULL;

# We cannot solely rely on the fact that the 'rpm' command is installed (it can be
# installed on Debian or Gentoo for instance).
#
# Although there are other RPM based distros, we do not support them to
# avoid FP.
var v = get_kb_list('Host/*/rpm-list');
if (! isnull(v)) pkg_system = "RPM";
else
{
 v = get_kb_list('Host/*/dpkg-l');
 if (! isnull(v)) pkg_system = 'dpkg';
 else
 {
  v = get_kb_item('Host/Gentoo/qpkg-list');
  if (strlen(v) > 0) pkg_system = "emerge";
  else
  {
   audit(AUDIT_OS_NOT, "running rpm, dpkg, or emerge");	# Unsupported distro
  }
 }
}

v = NULL;	# Free memory


var full_path_l = get_kb_list("Host/Daemons/*/*/*");
if (isnull(full_path_l)) exit(0, "No daemons detected running.");
full_path_l = make_list(full_path_l);
if (max_index(full_path_l) == 0) exit(0);

info_connect(exit_on_fail:TRUE);

var prev = NULL;
var bad = "";
var bad_n = 0;
var d, found, buf;
foreach d (sort(full_path_l))
  if (strlen(d) > 0 && d != prev && d[0] == '/' )
  {
    match = pregmatch(pattern:"^(.+) \(deleted\)$", string:d);
    if (match) d = match[1];

    prev = d;
    d = str_replace(find:"'", replace:"'\''", string:d);
    found = ldnix::run_cmd_template_wrapper(template:'LC_ALL=C test -f \'$1$\' && echo FileFound', args:[d]);
    if ('FileFound' >!< found)
    {
      dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:
        'Did not locate file: ' + d);
      continue;
    }

    if (pkg_system == 'RPM')
    {
      buf = ldnix::run_cmd_template_wrapper(template:'LC_ALL=C rpm -q -f \'$1$\' || echo FileIsNotPackaged', args:[d]);
      if ("FileIsNotPackaged" >< buf || strcat("file ", d, " is not by any package") >< buf)
      {
        bad = strcat(bad, d, '\n');
	      bad_n ++;
      }
    }
    else if ( pkg_system == "dpkg" )
    {
      buf = ldnix::run_cmd_template_wrapper(template:'LC_ALL=C dpkg -S \'$1$\' || echo FileIsNotPackaged', args:[d]);
      if ("FileIsNotPackaged" >< buf || strcat("dpkg: ", d, " not found.") >< buf)
      {
        # avoid FP for symlinked systemd
        if ('/usr/lib/systemd/systemd' >< buf)
        {
          dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:
            'Skipping symlinked systemd');
          continue;
        }
        bad = strcat(bad, d, '\n');
	      bad_n ++;
      }
    }
    else if (pkg_system == "emerge")
    {
      buf = ldnix::run_cmd_template_wrapper(template:'LC_ALL=C fgrep -q \'obj $1$ \' /var/db/pkg/*/*/CONTENTS || echo FileIsNotPackaged', args:[d]);
      if ("FileIsNotPackaged" >< buf)
      {
        bad = strcat(bad, d, '\n');
	      bad_n ++;
      }
    }
    else
    {
      if(info_t == INFO_SSH) ssh_close_connection();
      exit(0);
    }
  }

if(info_t == INFO_SSH) ssh_close_connection();

var report;
if (bad_n > 0)
{
  if (bad_n <= 1)
    report = 'The following running daemon is not managed by ';
  else
    report = 'The following running daemons are not managed by ';
  report = strcat(report, pkg_system, ' :\n\n', bad);
  security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : '\n' + report
  );
}
