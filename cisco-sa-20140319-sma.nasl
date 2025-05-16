#TRUSTED a8ceca79d6b9297d6d0c7588c33edc4aa5cc9dc9d6ab3f1750f57f1d5913596309316b738e981562fb14c1aacce97459c04183e7cf6c83fab2c7bf560338a4dcea427aea25f3cebcfa49de06b87995435a77fb7350d96e5f1f254e503eb81ade073e4793f19067250af047d03806b0b6243f927880c711c7c874c34fec6e7bcec5b829b9f921ded36ecdef79e170930bad759642db2e834ddae5ed0fc2438842fc7f05abbc7bcae1054d1f57da9301d173618f3d962513e2dbdac2a5f1642628c3cfb153aab737210f559ad95bf5206156439c4ed6654f22f2a551f45913a3f6220c753b8ff35b2161e0b14fa31e05ccd5a8103828155affc114675f5100a13762e641120f06e3271b12d72733cf78c3d63ba687c4ca003077ceff0acab0775ae08f896f12aa12776c4b74797ba161922bcf4073b48304c267ff0a0f7c77a28d184a713e4fe2388f56d506992980119dcb3a2d2a127a9d87007570d0934df9286772f2948773968f1ea495a5987300e3028bfeb8cac51fc0e2b6f724c4e2d1eb361fb60a9df0f5dc3a76157348f4dcad13121b89508547abd4eb99ec0d8a7a5bf34774c62dc069d9b6268d02641e0166561062895a53dd081952bb006037dad759343b491fb1fee9f30e0138dfb4dceacd86493c4ab8ebe22b69b638913ccd882a800490530cc43b48325501161269a9b45ba67a33d8527e90d25b6319096170
#TRUST-RSA-SHA256 112b3f137ac46904e897e9c5827e87d86b0801365d7d3d9538b6c394fc441a8c42020b65896045591e0a7e41521fa26e2d524bb7c8b555f6758dfa67c1b6e84b77e283d12e2e1897d76457c95ffa7a001bef3f488b1697ada2f7f34b4189063d8a5286d4da93c2e3a26c64247e8330fb48dda63c2d8369d6645fb391bcf8634a3e6c909898563ff26eb48ad8e5d385cca41447b45d8e845e4786ae2f819568c819f402a27406cbcaec29dc3da65a327eaa12c7e46c808b652f5b7b68061a3f34265eedadfd6e877dcade04dab0724007af613399a971044e88d107f7e5e1ef06d0448135c9f9181f0d5c5b4e1d9fa085aee533b8f860363ad5b98807bf16587b885da2c0e27446665f68e3debb5c6f32ca74f80e85bd1ff730dab3905d5a33f3dd67c109c4f7a30db62ffe4fff18ea6b7c9923ca4fbabed73de2303f1303d7dc6770dc9c8ce311a52518fa7d821aeca30d9a826b51b0afcc3160600f06cf217ad7ba97d7b4e5470bb102e79a9559a800f026f6b4769bafd2d130b8325e542f564168f6692cd176710472668ddbab17018ce11ef957bd3da68b8423980473a1c70c47da42c622b9a16a60805a55e3f033c3f6b154bafe26f271235ebfdc19ea1a47efb7e004992b27d719325482dfeaef6b3bbe40bd5f0ef461c85860b75eacd62415221e0a1efd07ece0f9a4941f4a01e502ef4f81f0284ab872bd6945cff35c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73211);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/05");

  script_cve_id("CVE-2014-2119");
  script_bugtraq_id(66309);
  script_xref(name:"CISCO-BUG-ID", value:"CSCug80118");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140319-asyncos");

  script_name(english:"Cisco AsyncOS for Content Security Management Appliances Software Remote Code Execution (CSCug80118)");
  script_summary(english:"Checks SMA version");

  script_set_attribute(attribute:"synopsis", value:"The remote security appliance is missing a vendor-supplied patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco Content
Security Management Appliance running on the remote host is affected
by a remote code execution vulnerability due to a flaw in Cisco
AsyncOS. An authenticated attacker could potentially exploit this
vulnerability to execute arbitrary code with the privileges of the
'root' user.

Note: In order to exploit this vulnerability, the FTP service and
Safelist/Blocklist (SLBL) service must be enabled.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140319-asyncos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c66d063e");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant update referenced in Cisco Security Advisory
cisco-sa-20140319-asyncos.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:content_security_management_appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2024 Tenable Network Security, Inc.");

  script_dependencies("cisco_sma_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Content Security Management Appliance/DisplayVersion", "Host/AsyncOS/Cisco Content Security Management Appliance/Version");
  script_require_ports("Services/ftp");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

display_ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Content Security Management Appliance/DisplayVersion');
ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Content Security Management Appliance/Version');

vuln = FALSE;

if (get_kb_item("Host/local_checks_enabled")) local_checks = TRUE;
else local_checks = FALSE;

if (ver =~ "^[0-6]\." || ver =~ "^7\.[012]\.") # 7.2 and earlier
  display_fix = '7.9.1-110';
else if (ver =~ "^7\.7\.")
  display_fix = '7.9.1-110';
else if (ver =~ "^7\.8\.")
  display_fix = '7.9.1-110';
else if (ver =~ "^7\.9\.")
  display_fix = '7.9.1-110';
else if (ver =~ "^8\.0\.")
  display_fix = '8.1.1-013';
else if (ver =~ "^8\.1\.")
  display_fix = '8.1.1-013';
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco SMA', display_ver);

fix = str_replace(string:display_fix, find:'-', replace:'.');

# Compare version to determine if affected. FTP must also be enabled
# or paranoia setting must be above 1.
if (
  ver_compare(ver:ver, fix:fix, strict:FALSE) == -1 &&
  (get_kb_list("Services/ftp") || report_paranoia > 1)
) vuln = TRUE;

# If local checks are enabled, confirm whether SLBL service is
# enabled. If they are not, only report if running a paranoid scan.
if (local_checks && vuln)
{
  vuln = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/slblconfig", "slblconfig");
  if (check_cisco_result(buf) && preg(multiline:TRUE, pattern:"Blocklist: Enabled", string:buf))
    vuln = TRUE;
}
else if (!local_checks && report_paranoia < 2) vuln = FALSE;

if (vuln)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + display_ver +
      '\n  Fixed version     : ' + display_fix +
      '\n';

    if (!local_checks) report +=
      '\n' + 'Nessus was unable to determine whether the End-User Safelist /' +
      '\n' + 'Blocklist service is running because local checks are not' +
      '\n' + 'enabled.' +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Cisco SMA', display_ver);
