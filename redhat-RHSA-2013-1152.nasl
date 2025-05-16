#TRUSTED 8015dad2abf9b55f78ec9264d66a4cbd70729b9704851d1fa2d0a971187daddf74624496899c4075ea80e1b0e2ec1a20eb3055bdc6f86407659af8d9b8c85f7d45a79d5c7785c362743470fa5c62f40e4977712f427c1fa45eb041090bfc22c189f8413408ac27ec229b0511b32cd0645272668d585b8f73afff4fd144a98c07b4ebe2a37a3a470c462b93f6a1fc5edf2ca4878b33eeea5189ef01ed8f6d425315b91a23208181f6d0a89b6cbbe10f630fb3f0322837772f7321804f6400b2ac9dd8c4e596d37b8977f048edc2bee1cf2d5333c98c6ead450f836c765f47bdc412b9d438230f3c2839f4673f5ce60c1b6bf5aff616dec7c12403ef23f2fc694721eeee11692d4c3a1e087bdf14f096ddfbc6fac83892c18f86b52bca194159e4cfbc455db7b3baf37cdc89dc4bb521d9707a33b63e17456694f177fc08d262d13f0d314529d0b6dfb36fbcd4dabc135a493a3a498752c3cda50a7c016dee853a39df27fc61bb98bb617e15acf540c591b5c1d5591abbef801aac88a9778db46d2299bea2bda3332021f151819927c37e24bc01315d45d17831c98bb957af6389075bf6b0723af327c8f5173819e5f13f4673ed41c3d1b42369d04e255d1ba2ce0883740d819d6decb202a382aea0f1fbc4695e51b5109396757c4a5fc671e4157b79c9fbc9e365ec4636d42e392ac4d997c756ae1a79f538eb4ac0eff604f92a
#TRUST-RSA-SHA256 427286c26f93dfb36950eb9b653f28227cb34896fada194012f30c33c06362fd2b768c9321375a6d86059ca962d308f68d3d911da7e26f8cfdd18fac78841d266a6300b78506763932fe11badaec3164a7ec23e01a9b356e0727445ee18cbed94aa2a690ff3e949d9f8c888b7dbbd342100fc0fd98ff012faaa552b0c8a3efd8db759f3b3194c9883b58a2ce8feab5197760c9fedfa867c33105d174674e4d0d70a1dfbe7010dd49f3fe50b73dc0055f910a05ab7e02ccf5cd021d4adf17dfcd64154605a8626367957d7817dc756d6c8ccafd9964e05303ed6ae6f2359d98d818c0236835518f66090a6e1ae45eb1a9635d5b74df506fe9e43f40516022208c58f107810111ee0c3a2e1019b2ab0ef0bf63b1828a6206e4cc41b20162c986f493e5d27916292c4a2eb21c761b493d3821f158393abbce128dc29f28d8c6cc62c3eac7239ac9e8638f59333f7a82ecf33376c15cc0fee9e9e6c69fd92fb153f00eb76ea938495171d6930e935b9de17dc17444427461661124adb4967b641ffaf4b87fd8d54fd28e87f153deedfdf43c74277f010c98ba586b043b9f18d94aabfe8ec2a5ba17d4469c1abb842adf458f2a7399cdd0e858ef0dc12123f182eb6e33355628ee2889cf09ec7b00ab26cf1720fc6f57250548e4c5f03f18adf813003e40bb03171748642f8a684911cf8e652e11d9d00617c19ec1ebe292482ad573
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72261);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2013-4128", "CVE-2013-4213");
  script_bugtraq_id(61739, 61742);
  script_xref(name:"RHSA", value:"2013:1152");

  script_name(english:"Red Hat JBoss Enterprise Application Platform 6.1.0 Security Update (RHSA-2013:1152)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of JBoss Enterprise Application Platform running on the
remote system is vulnerable to the following issues:

  - A flaw in the way authenticated connections are cached
    on the server by remote-naming could allow a remote
    attacker to log in as another user without knowing
    their password. (CVE-2013-4128)

  - A flaw in the way connections for remote EJB
    invocations via the EJB client API are cached on the
    server could allow a remote attacker to use an EJB
    client to log in as another user without knowing their
    password. (CVE-2013-4213)");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2013-4128.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2013-4213.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate JBoss Enterprise Application Platform 6.1.0
security update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-4128");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:redhat:jboss_enterprise_application_platform:6.1.0");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2023 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "jboss_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("local_detection_nix.inc");


enable_ssh_wrappers();

var buf = NULL;
var cmd = NULL;
var cmd_template = NULL;
var found = NULL;
var full_path = NULL;
var info = NULL;
var install = NULL;
var installs = NULL;
var matches = NULL;
var path = NULL;
var release = NULL;
var report = NULL;
var s = NULL;
var sock_g = NULL;
var ver = NULL;

# We are only interested in Red Hat systems
if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
installs = get_kb_list_or_exit("Host/JBoss/EAP");

# We may support other protocols here
if ( islocalhost() )
{
 if ( ! defined_func("pread") ) exit(1, "'pread()' is not defined.");
 info_t = INFO_LOCAL;
}
else
{
 sock_g = ssh_open_connection();
 if (! sock_g) exit(1, "ssh_open_connection() failed.");
 info_t = INFO_SSH;
}

info = "";
jboss = 0;
if(!isnull(installs)) jboss = 1;

foreach install (make_list(installs))
{
  matches = pregmatch(string:install, pattern:"([^:]+):(.*)");

  if (!isnull(matches))
  {
    ver = matches[1];
    path = matches[2];

    # check for install version = 6.1.0
    if (ver =~ "^6.1.0([^0-9]|$)")
    {
      found = 0;

      full_path = path + 'modules/system/layers/base/org/jboss/remote-naming/'
        + 'main/jboss-remote-naming-1.0.6.Final-redhat-2.jar';
      cmd_template = 'test -f "$1$" && echo FOUND';
      buf = ldnix::run_cmd_template_wrapper(template: cmd_template, args: [full_path]);

      if ( (buf) && ("FOUND" >< buf) )
        found = 1;

      full_path = path + 'modules/system/layers/base/org/jboss/ejb-client/main/'
        + 'jboss-ejb-client-1.0.21.Final-redhat-1.jar';
      cmd = 'test -f "$1$" && echo FOUND';
      buf = ldnix::run_cmd_template_wrapper(template: cmd_template, args: [full_path]);

      if ( (buf) && ("FOUND" >< buf) )
        found = 1;

      if (found)
      {
        info += '\n' + '  Path    : ' + path+ '\n';
        info += '  Version : ' + ver + '\n';
      }
    }
  }
}
if (info_t == INFO_SSH) ssh_close_connection();

# Report what we found.
if (!info) audit(AUDIT_HOST_NOT, "affected");

if (max_index(split(info)) > 3) s = 's of JBoss Enterprise Application Platform are';
else s = ' of JBoss Enterprise Application Platform is';

report =
  '\n' +
  'The following instance'+s+' out of date and\nshould be patched or upgraded as appropriate :\n' +
  info;

security_report_v4(port:0, severity:SECURITY_WARNING, extra:report);

