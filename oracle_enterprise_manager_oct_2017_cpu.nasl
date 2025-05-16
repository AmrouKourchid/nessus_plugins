#TRUSTED 8e93679ca263e6a18e6e46bfee6b62216a7b7e446622d5c1c4e640da8c39aa6aca049c1b466e9439b48d5f0ab3297ec84d4944cdaffb04f386180fdb666c9b46307c58a4afb960595876dcaf23c1aec60d988818631ff953f430ec82dad003d64f057233e0677deb0f5c9bbb79332a8c9630f2342efd6c55ab2d4a8712e474a88e1207988c22da4b5fc5447e93413558d2eac7064debe888f6e156b9480c1c870b0bdbb53bc2de019ce50f3e7afb1c0aa5eb4e29ff21ac34f25a16ea0d992dcdcac0b1dfd9a2f5df4fbb841d019f8fce5477b82b621f75fcba05a2c829ab126fb225d6b34b2c753bd36f6b4668a7eabbedfa418f3769f47a5b3b365ea93db7210dd65603215a681bbdac7f2802ab8c048942a8fc8aac612ce20fabbc6dd3b8a1a93e4aff866d2fb181cfc6926a8fe6a15a1709b67b5a58b8290502de0df30e5619ea664cf214fcec9a69b3740300b57f5c05750bb9008e7297a25891f8132bfac5b27ed5792f1554667f7c7653c3b64bd2fba0359990ce5e8ad6f6e92e2ce58b16a26731e090e5ac14a80b50fb9ed3f00d726bfa83b86206368c2d0f1e75d39befb04f0a08c9da5039c97f6fdff4880410d4d47ea05cf78b07bce8775c1cecc2f9de05c99f089c42b663101d0f57322fa4da77eb71f8ca7c769b2cf2742019d93f4d91b8c19da25f70b498b0931377f49255513cb2e35a804350101201489c47
#TRUST-RSA-SHA256 356464774d1ee25cede3df13b17dbd51a1681153534136e0cb47179d3829a2879cddbd5f6576f1fa376c37364c64bf558d00631175c49d87d23cf948dbe17e54e970e9e96b2faaca51c958f69e153f749c77e6f304d1179b6816775a79e3effa1d15a9361590aeb6ee33bc92542a2e03b939f643d78b20e0cd47386758ebc87104d809c76bb101377607f2a3425f3a83cdac33249c30d85b7ffe2f698b16807585582340c457afda805b9b079189d39525eab1006a492f391048e2bfe558ca372bf7f46a223b5552bd602e5d159ed7993e79e6acbeceeef804002a85209fa118cf9c4fcc77b6e4b30a0f5d8d4a23f4bd3c1b82cb7412bf211f27df5eb083f8cd39bb936ba7d9e36db0acd6ee6d4118bd57142b1db211307b27c6fa5317bd8af5f585608f7503edd873e35dcdb30601e24f34c5a4a1e2ed959e8bb0733c293ae981c9f44a98d005a98308c5d119e9ce2eb82d9580cf66c599de6b3354639924e80feaef4fce518c93918bc86ad62ef50de2e892b74cc91ce803329974353e65eaa49f23e1f208fab8898f281c2ae61b1af9a7b297fa05621bdda08b27a8fcbcfd6c46f3c33522734badfb29f4091a4c676040cbeb0c9002cb5b3aa41410996e44c0827eb7e1d8c65f32066effd557413c0e975ccadf6284155a21be1d62e413f3986a47518bc3d156056479b51e21243429e9c5f2dec84d8778ed5596c7095f2e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104052);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id("CVE-2016-6814");
  script_bugtraq_id(95429);

  script_name(english:"Oracle Enterprise Manager Ops Center Remote Code Execution (October 2017 CPU)");
  script_summary(english:"Checks the version of a library.");

  script_set_attribute(attribute:"synopsis", value:
"An enterprise management application installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Enterprise Manager Ops Center installed on
the remote host is missing a security patch. It is, therefore,
affected by a remote code execution vulnerability. Refer to the
October 2017 CPU for details on this vulnerability.");
  # http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e07fa0e");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2017 Oracle Critical
Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6814");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("audit.inc");
include("ssh_func.inc");

enable_ssh_wrappers();

patch = "26974609";

installed_cmd = "bash -c 'if [ -f /opt/sun/xvmoc/bin/satadm ]; then echo 1; else echo 0; fi'";

ret = info_connect();

if(!ret) exit(0);

buf = info_send_cmd(cmd:installed_cmd);

if("1" >!< buf)
{
  if (info_t == INFO_SSH)
    ssh_close_connection();
  audit(AUDIT_NOT_INST, "Oracle Enterprise Manager Ops Center");
}

lib_ver_cmd = "unzip -q -c /opt/sun/n1gc/lib/commons-fileupload.jar META-INF/MANIFEST.MF | grep Implementation-Version";

buf = info_send_cmd(cmd:lib_ver_cmd);
if (info_t == INFO_SSH)
  ssh_close_connection();

if("Implementation-Version" >!< buf) audit(AUDIT_VER_FAIL, "commons-fileupload.jar");

version = pregmatch(pattern:"Implementation-Version:\s+([0-9.]+)", string:buf);

if(isnull(version) || isnull(version[1])) audit(AUDIT_VER_FAIL, "commons-fileupload.jar");

version = version[1];

report = 'The install of Oracle Enterprise Manager Ops Center is missing the\n';
report += 'following patch :\n\n  ' + patch + '\n\nThis was determined by';
report += ' the version of the commons-fileupload.jar library.\n\n';
report += '  Patched version : 1.3.2\n';
report += '  Installed version : ' + version + '\n';

if(ver_compare(ver:version, fix:"1.3.2") < 0)
  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
else
  audit(AUDIT_INST_VER_NOT_VULN, "Oracle Enterprise Manager Ops Center");
