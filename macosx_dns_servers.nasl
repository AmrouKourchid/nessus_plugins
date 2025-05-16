#TRUSTED 40339c664e1833058fe95156c49f54b41362d1ed04190f37de9d8bc234553527014825dd1508f5d8be5b4f34c75b820e1e3ce02d5b870cb707044901d52d19ff3620410a6565ef3bedd494343ccc9a32d0c82c50fd4ef1f95ec829026c073767012ff087ef16cbfd292e4eaa34a168c94390be2d44a7cfe6586baeb16964586bfc2cf8f15ea34731657745adde9b84198a6fe2179ab4661a0e7115af9bc6a3fc91891a30bed61b2ecd95b238d88805690dd19f892be3ca280f2ce8606678943185c5b055b7ade2abc723e2f53af8e7b181368e76436cfd5ccd973d32d2e06908a207245ab254537c3b758f3cd727a2cb11777a2ebfa2833071c33d4fb85082056fdbbbf5e4bb706c1804d0765f9d9767836c3d9dacd67bef49d67d4d0df4af11d17c9be35b2b2465fe610242a195c93262eda6a228a1051113845c7b4d98cf7d34d69e9e54653fb795d2d6eaba15509357d5b66902f3dbc868706c5d851362127dc1e2fee643354d573f9c99fe3f033b6a8c9ae4c74eae8dbcbcd8f67e75325d46849b3c9bbcbcde5dd5d4b7d927e3810395b15017924617b112ff29ae09cd026e88394541579ada674cce2465ff6baf47eeb90b4a4b89fce2e7c5c65b6a45c0d4b2d99b8bbb2505bbe692b78c23f0457184629eea5cea306f87db5e80ff7bbbcbc4c50a9ef7a058032e3b1deb2071e46c1f073b00ae94274e2f17703df9f164
#TRUST-RSA-SHA256 71f7b5cd234045325139071d0c3db39f3c5b74585db81a7d48445f0801687c04b311bd093b5af0333b279752fd70b27c2c2ba24fd6f7239edc6c25eea27a5e2a065980a4815eeaa75ed3f04b7be73aeff9034037f1edd51be49b0a2b7b745023132e433c4b8f048a9d4bc301b36d1b2adfa4e8442ca103a8553bec37cf5ecb4238f4299a26fabced33b328e724092185f184766fe88e5c562b13abd1b53be6514096320a19fe3de192a663daf4f5bf33f85d8e506a0279278ea0f9274a64ef4264bdfe33477149ab7d3ec242732715c9436d2fe88dda5b4dc26a4e964d32757315c7e2ec6823e552a4964a4a2166c42703e5ef8b4c8eb4932330b4e2338923008f379f8e4a7d13108dcfbd576b861834c9d887e8ec34626bff0e4f3eceea5ce38a0c9ea801206bd745f48966e246100e44a4e72a2058d6778e182502c12d8ece6a08dc3549a90b0eb24c2ad7802c628a45eb56a147c0294d4a9e4e3930ee4a21e0b1fb7c3c2503d44ba387a4e0cca44c1a4c9c67a4bcc966e1dd1bccba4163cc7f9987810ecd3f0caa21e8659f4794bda8a4f8233bbd4b55ebdadd54381ba0a206e1ef180dc77dd02e3db18fb415628a953eeab64508728a4ee75645afd8ee56c32fcac7c0dbb1e92f2b9572c92e9c8019a55f1d2b3418e1984fa8ccd3b68d5f3f2de471e5dbcf0b517669ce7106f699884365d6ca96e13336821edd37881efb
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
  script_id(58180);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_name(english:"Mac OS X DNS Server Enumeration");
  script_summary(english:"Looks in resolv.conf to see which DNS servers are in use");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Nessus enumerated the DNS servers being used by the remote Mac OS X
host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Nessus was able to enumerate the DNS servers configured on the remote
Mac OS X host by looking in /etc/resolv.conf."
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2023 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");


enable_ssh_wrappers();

get_kb_item_or_exit("Host/local_checks_enabled");
get_kb_item_or_exit("Host/MacOSX/Version");

nameserver_file = '/etc/resolv.conf';
cmd = '/bin/cat ' + nameserver_file;
output = exec_cmd(cmd:cmd);
if (!strlen(output)) exit(1, "Failed to get the version of Safari.");

dns_servers = make_list();

foreach line (split(output, sep:'\n', keep:FALSE))
{
  # extract name servers, ignoring commented lines
  match = eregmatch(string:line, pattern:"^[^#;]*nameserver ([0-9.]+)");
  if (isnull(match)) continue;

  dns_servers = make_list(dns_servers, match[1]);
}

report = NULL;

foreach server (dns_servers)
{
  set_kb_item(name:'resolv.conf/nameserver', value:server);
  report += server + '\n';
}

if (isnull(report))
  exit(0, "No DNS servers were found in '" + nameserver_file + "'.");

if (report_verbosity > 0)
{
  report = '\nNessus found the following nameservers configured in ' + nameserver_file + ' :\n\n' + report;
  security_note(port:0, extra:report);
}
else security_note(0);

