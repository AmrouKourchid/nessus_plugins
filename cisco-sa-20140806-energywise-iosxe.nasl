#TRUSTED 1c67eda1cdee4b83885845926946730d2dae0bcb92d66f61cd2b4d08c21d39f6bc28ccba349d179ed23554541cd9d6131412988c5c28b4508f8de4ee1a17de39a15820a37e61cee7f4ebfa5c68f63674c3dbc43aa7ce390094879d7368b37580e1e7837ee6e83f7afe9cba5a0da44ce6a417be281c99ed840dba13895a0841b9546025c32d90d8c195d77242fa39c64449ce7dfed8e4b5e987f19862bf598441d24e64a91f17fa229cf44a83f39dfa63c4b60c2dc90ff229858e48d18b3acf37c37987ca1f39b9d12b43dde4e536e636c0fe416d69d847300a5d7acc98ba3897676f00d1274bae38dd11f19ab186a0b94710ba8d429611a6c34aca211d706320bbbbf53e2b85d254874f805b24c155470fa63a974c255684565ba869dcd38080c25130f7e38e5c900d4380de0ed8076a64cc3c9b1b28a0857479ba7f73c684ad4ac7711ff51804c39cb9aa073b3a1175b6fd33db133d76aaf4999a0306d6fdf9043c8589fe096efdac888e443a8a89569fb2826e0e91a79a28591daf9f63a8bf3ce27d2688875a054bdeee9d74498e43f8aec11ebd4a92900225422fec8690f4e1cafa27369595429632a56d59d507fae49de97348027fb9f108668a7f3d3bf09777664510994b414947cd50a7167d74dc41f03d6951d28cc99d0c9ef624e90db1360988e7b015d468adbd882be46616e583cb4214f446a6c9c396a905bdbcfa
#TRUST-RSA-SHA256 9d7ed318baa4047e230d32f99f82c95b3110717b2688c6ae662648f02bb8b3d46ec2c906bb7f0ac9b495db0cc39012a476689c379e9f391bfa3201b31456e9748af95bcf3fc77de9ea677eb96848140f459f57c9f5d9d39aab830a0b0f240d3fe552496fa67227f1d5ef9d2f61bdf9a7b22e796303b09a632e5f8a6daf5d7d2f7c069476f3d840b46e0311fee263b1ab68a4627aa12368c108d4226370abcde32f4a7ddd703a5d3dfc7a9e570a37c00dbf6931832b8768808ea2b9555c41a1129df608f8c22d9cb077e1f61e223f261001cbc91e01250351f6f986aadaec1d93f59ccb95858278b5cd07a7a09e243a5eda97d528d7280f4eb4be1acaf356cf9e8b01b1bc25e52ed4095980144e106e2ae481828b2f1c4ed44d8e91e3089f59b888c621cb5f898b0be749a4d7b71763c6a5eab0536cbd00ae07819f442c321c4edaa069bbff0b0768f12bd926a9b2337f814ee25ae021e0674a8f48a354eeb27e524a30a0e93e4ecbff7bf6bfaa377e47bd4ee29adf172011f82d67ddda1dc16546b4c33ba0dab04ba6d8d075daa6eb4fad88dd03796f58d89ea8fbadd0cc36c6675b4e6aa12e67f06b1f91661494f60df7db9829b6ef94781db6856b5d161529e7560e8d844761060f31e796ec0ca61e486a69338496204897e7d5680a10ced8653e3bf8fbd999b5a469b8b64214a19fee1b04c2d3fc0791f5c09a23f9b6b548
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77154);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2014-3327");
  script_bugtraq_id(69066);
  script_xref(name:"CISCO-BUG-ID", value:"CSCup52101");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140806-energywise");

  script_name(english:"Cisco IOS XE Software EnergyWise DoS (cisco-sa-20140806-energywise");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS XE
running on the remote host is affected by a denial of service
vulnerability in EnergyWise module.

The issue exists due to improper handling of specially crafted
EnergyWise packets. An unauthenticated, remote attacker could exploit
this issue to cause a device reload.

Note that this issue only affects hosts with EnergyWise enabled.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140806-energywise
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f5dbdaa0");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35091");
  # https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst4500/release/note/OL_27989-01.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7f8a44d6");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco Security Advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3327");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

# The following versions of IOS XE are vulnerable :
#   - 3.2.xXO
#   - 3.3.xSG
#   - 3.4.xSG < 3.4.5SG
#   - 3.5.[012]E
if ( ver =~ "^3\.2\.[0-9]XO$" ) flag++;
if ( ver =~ "^3\.3\.[0-9]SG$" ) flag++;
if ( ver =~ "^3\.4\.[0-4]SG$" ) flag++;
if ( ver =~ "^3\.5\.[0-2]E$" ) flag++;

# Check that EnergyWise is running since it is not
# enabled by default.
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config",
                              "show running-config");
  if (check_cisco_result(buf))
  {
    if (
      preg(multiline:TRUE, pattern:"^\s*energywise\s+domain", string:buf)     ||
      preg(multiline:TRUE, pattern:"^\s*energywise\s+management", string:buf) ||
      preg(multiline:TRUE, pattern:"^\s*energywise\s+endpoint", string:buf)
    ) flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCup52101' +
      '\n  Installed release : ' + ver +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
    exit(0);
  }
  else security_hole(0);
}
else audit(AUDIT_HOST_NOT, "affected");
