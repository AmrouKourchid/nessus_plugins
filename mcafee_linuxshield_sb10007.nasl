#TRUSTED 53fe805f579df6c9d5b32056446b889afe2fed1f58bb81a9c8f239d6a5e74e7396bae06a463706619e7456e97c1d4a5b0c9bc9fc7ccd64c0183a57ae69911a9039cb609325109832eee6532e0e7d00bf7887dacf7daf7f004bd4ab29b856be580c45c7e2ac2ade7a0d0782827f2d460a8173c900df386c44fa78282d433c12cb5c9ded26d6c6c99f8edf5430a0a783605926c58252d2cd851f34bfd97d330d2fba13384f705ff44350662ea357d4bcf3b758b796ef8caa3f70870c3db16d351500214c5f906f8618b892d50fa3dbadf6f81bf0ad2c91e3d471f0a166807264177dc9fe7b955164c229904f3444aa1fe3969b2d18d71cdeffb05ec01522f628b689869f59c58e5bd65030ccd9104a13139c88bdede3bd33464da0a425d2f38e68a22e5ad3b64e9c1649cc4c8dc1da58900be1031b24d8d7ca65c6c4a0c4e6c672a67e409fc56fa4ab8e23d8e618ec8dcdba1ceda27c56143a975a31521021686af361d244107a20734076612da7b8dd50832d4a4a04d18f018b613716eee50d61fc5e41b015af98b0befefd5cd30cb4fbcade230b5cd2874e6f0248190a1fe564b08fc94e43bea3fc3a67c52cd920ebb1baa779e921698469dced4cb5a3d6cd3f4c6e2efc030e7c9641e9773656b0713cda8ff08287cb38455e1a43181fecbc666baf700e77bfd0246110b60e4cb8e7fc764906f967bfb5335ded97e651fd1982
#TRUST-RSA-SHA256 297fe0f53402d11ee3b58a73190d93ca142ce9124806a4489a2889e9d1137f9d8d1525bcbe868c7fed527d8cc7c60f4e92431b54de22cc3b91082caa9ac29dae489de90bc52f49dc2156089d759620aa98d1c41ec8d0e9e7bff125f3d73ddd61119ca3d44ba3f5cf96e67126c5eddacc9d9a1cffb460e7a1e5c31bcbaf2d22723ceec333f36ff83cc45390f6f58183bb2e19e2b97bad0fcff60d858622326ca826a59f70222e2ea24959bdcf0a5631bfefba85eb054d4234fed064dd49102a9668ed1edade2f6309d779734ea3ddbe671015090fc5f23eaf0162abd83f6ad8720663a19e4ffe161763045772c9143499cec456b5af23cdad87307dacd37a89e4214199bb8aab506d4ab965f6ef9d799d28fe12b09718f211089e576e2b1aefa2067bfa51c8f8f2e36a09c88055969be64e109b6cf9cb1c5355778ebb19ff5f5432e16c3105a3d16818b00076dee1c81fd03644f4a20c829bef837ac7e983f2ea828807711bfa5b1e1c5d392075a342968d4f527cb26bc58584c5c8b6fc04a2305dfb3138715eb671954077e4b1dc366f3edf4623059fe88e53338fc8cb275e18f661af3f22384ac9045f763645889b2e243f2762638f5d15a53cb2ed556beed7a75bc279ae54b3647cccb7bbe3b90154a200fa2c62fa72a433a92dc1b91065136c9031c0fb748c00c680bd3ead1ed74211ff0a2adc7360e5bee47442c322e000
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70195);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id("CVE-2009-5116");
  script_bugtraq_id(38489);
  script_xref(name:"EDB-ID", value:"14818");

  script_name(english:"McAfee LinuxShield <= 1.5.1 nailsd Daemon Remote Privilege Escalation");
  script_summary(english:"Logs in with SSH and checks the version of McAfee LinuxShield");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote host is affected by a privilege escalation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of McAfee LinuxShield installed on the remote host is 1.5.1
or earlier.  As such, it potentially is affected by a privilege
escalation vulnerability because it does not properly authenticate
clients.  An attacker able to log into the remote host can leverage this
vulnerability to authenticate to the application's 'nailsd' daemon and
do configuration changes as well as execute tasks subject to the
privileges with which the 'nailsd' daemon operates.");
  script_set_attribute(attribute:"see_also", value:"http://sotiriu.de/adv/NSOADV-2010-004.txt");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2010/Mar/26");
  script_set_attribute(attribute:"solution", value:
"Upgrade to LinuxShield 1.5.1 if necessary and install hotfix
HF550192");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-5116");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:linuxshield:1.5.1");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2013-2024 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_lib.inc");

vuln_report = '';

enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if ("Linux" >!< get_kb_item_or_exit("Host/uname")) audit(AUDIT_OS_NOT, "Linux");

hotfixable_ver = "1.5.1";
hotfix = "HF550192";
cat_config_cmd = "cat /opt/NAI/LinuxShield/etc/config.xml";
cat_hfversion_cmd = "cat /opt/NAI/LinuxShield/etc/HF-Version";

port = sshlib::kb_ssh_transport();

ret = ssh_open_connection();
if (ret == 0) audit(AUDIT_SVC_FAIL, "SSH", port);

cat_config_output = ssh_cmd(cmd:cat_config_cmd, nosh:TRUE, nosudo:FALSE);
if (
  isnull(cat_config_output) ||
  !eregmatch(pattern:"<InstalledPath>__NAILS_INSTALL__</InstalledPath>", string:cat_config_output)
)
{
  ssh_close_connection();
  audit(AUDIT_NOT_INST, "McAfee LinuxShield");
}

matches = eregmatch(pattern:"<Version>([0-9]+\.[0-9]+\.[0-9]+)</Version>", string:cat_config_output);
if (isnull(matches))
{
  ssh_close_connection();
  audit(AUDIT_VER_FAIL, "McAfee LinuxShield");
}

ver = matches[1];

# We treat a missing HF-Version file and an empty one the same way
cat_hfversion_output = ssh_cmd(cmd:cat_hfversion_cmd, nosh:TRUE, nosudo:FALSE);
if (isnull(cat_hfversion_output)) cat_hfversion_output = "";
ssh_close_connection();

# If this is 1.5.1, has the hotfix been applied?
if (ver == hotfixable_ver && egrep(pattern:"^" + hotfix + "$", string:cat_hfversion_output)) audit(AUDIT_PATCH_INSTALLED, hotfix);

# If this is not 1.5.1, is it > 1.5.1?
if (ver_compare(ver:ver, fix:hotfixable_ver, strict:FALSE) == 1)  audit(AUDIT_INST_VER_NOT_VULN, "McAfee LinuxShield", ver);

if (report_verbosity > 0)
{
  vuln_report += '\n  Version       : ' + ver +
                 '\n  Fixed version : ' + hotfixable_ver + " with " + hotfix + " applied" +
                 '\n';
  security_warning(port:0, extra:vuln_report);
}
else security_warning(0);
