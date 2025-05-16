#TRUSTED 1d75685f359a8049f7e8e7c6450abed4b6604fb8f520b1364e6e15e4b857e6a37500b1be2a7895a7f83addada92ec70475c813ed31e54a285d7bc48165d13c3254cff1081876df209e84162f1a31b75556780134ee714254a00e9f02f2a2139ca85cb9bf3ada9d37f483ef53e77b21bc2254c04427d45dc3312be3cd32495934e89010a62e7a1f3024540b488526c6b71e0f10e6470857d31ba31ae1ad52af57fe335fecd37f4f3cf6f2b937feb4ab2c5fa0fde33ade509c24f0882d3045d553298aaf1122d338a1def202f349eba7ad0d64c25e6215ed2a9b0abd85e4aa7e9e5895797de22c80e2904b21acc6bc48c3c66ba1b163a6a65c45c302fc75f83bac80bee0e765312328019dac7bca354d71a116a3958dccef6f296154b5395f41d5d4c76e4b065ba22fb1f1817a43158ef1643578cd88e0731b592f147d24da6e22a129ec6cb8afdf512918b504fa8af6635b04e9d4fb7c49c97a0a93d2b43276168db817f5ba1d7a68227783394d83a0bc75b85fa131ac0c76f75f745fdc4f24dad19d5791f07ee3403f692e9e9d1633a469627d631931d25371735c3b89e455a79fd381cbb4b6c83d66ee71edf4515d9a0f526b4101adaa35e4c76c02e55717df52603a408b14469e5ba0baff934dbeb18e8358319eeb66c7815016a5c879a2034f0b1e586a62bf349ffa6a86ba45266112f3fe987416d73ad889b8d01dbe8cfa
#TRUST-RSA-SHA256 329534d98375662dce457327d7e2fe6daff82a5f09b13682de66ff49f1df778da35c403f9a3312a652013acbb4eb88d8d7aef60de65c39f1e5c39b5216c05831ab39bf6e8ff4d99ef5719e8df270e8a7139d1dd158deb728d21a5ecdd98fcb8d61e76b5262e486f5d79b8086ed09cc6a70d5ba20155b9122c80f29b1b843d5e3dae9896e7f924a30d829770fb685d84297009a3c0b2d96034f545cf2aaa7d4b29e822c6b124422c34bb5c8ce312b8d2513642da2fdb58a189442a88f1a88ce515472d492f01786191fad10d66aaf5334562d37a9349055a9f3d09c3f2875714e2311ed66cb8619cb9fe57e18dafc2aa9d3f4b8641e8041670244421014499f7b74931e6134bf158ba3548176045cd232a920735a1f61e59fe398274066a7f438831355e2eb2aa50ba9ca8270406c1817c19abae7843f001570fddc5331920b7a276bcc6d0a0c011683f3e6b8f33c1ab980c5c321af33fa4536604bc6a2c932897fb5bd883426e27fc3bb7edf4ef21f3f75e280b3ad063c5364622d58872a2db9e4684cce706add21e05742d102319dd110adc7a2bd6ecc3190fcbc29e0653e6497b9aa93fb9a585ce028645daa8017b50482f1acfa481b38ed6d01ae8f2d8170a661bff3e031fb6f0484de65cf2cd855a3a253a34acfd87e69f1e7d36750ff305276e177984869aa45477419dcf3f72e704242ce17947724d71095f2e0c9da9d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90359);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2016-1349");
  script_xref(name:"TRA", value:"TRA-2016-04");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv45410");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160323-smi");

  script_name(english:"Cisco IOS XE Smart Install Packet Image List Parameter Handling DoS (cisco-sa-20160323-smi)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a denial of service
vulnerability in the Smart Install client feature due to improper
handling of image list parameters. An unauthenticated, remote attacker
can exploit this issue, via crafted Smart Install packets, to cause
the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-smi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?14b003f9");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2016-04");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuv45410. Alternatively, disable the Smart Install feature per the
vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1349");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

flag = 0;
override = 0;

# Check for vuln version
if ( ver == '3.2.0JA' ) flag++;
if ( ver == '3.2.0SE' ) flag++;
if ( ver == '3.2.1SE' ) flag++;
if ( ver == '3.2.2SE' ) flag++;
if ( ver == '3.2.3SE' ) flag++;
if ( ver == '3.3.0SE' ) flag++;
if ( ver == '3.3.1SE' ) flag++;
if ( ver == '3.3.2SE' ) flag++;
if ( ver == '3.3.3SE' ) flag++;
if ( ver == '3.3.4SE' ) flag++;
if ( ver == '3.3.5SE' ) flag++;
if ( ver == '3.3.0XO' ) flag++;
if ( ver == '3.3.1XO' ) flag++;
if ( ver == '3.3.2XO' ) flag++;
if ( ver == '3.4.0SG' ) flag++;
if ( ver == '3.4.1SG' ) flag++;
if ( ver == '3.4.2SG' ) flag++;
if ( ver == '3.4.3SG' ) flag++;
if ( ver == '3.4.4SG' ) flag++;
if ( ver == '3.4.5SG' ) flag++;
if ( ver == '3.4.6SG' ) flag++;
if ( ver == '3.5.0E' ) flag++;
if ( ver == '3.5.1E' ) flag++;
if ( ver == '3.5.2E' ) flag++;
if ( ver == '3.5.3E' ) flag++;
if ( ver == '3.6.0E' ) flag++;
if ( ver == '3.6.1E' ) flag++;
if ( ver == '3.6.2aE' ) flag++;
if ( ver == '3.6.2E' ) flag++;
if ( ver == '3.7.0E' ) flag++;
if ( ver == '3.7.1E' ) flag++;
if ( ver == '3.7.2E' ) flag++;

# Check for Smart Install client feature
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_vstack_config", "show vstack config");
  if (check_cisco_result(buf))
  {
    if ( (preg(multiline:TRUE, pattern:"Role:\s*[Cc]lient", string:buf)) &&
         (!preg(multiline:TRUE, pattern:"Role:\s*[Cc]lient\s+\(SmartInstall disabled\)", string:buf)) ) { flag = 1; }
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
      '\n  Cisco bug ID      : CSCuv45410' +
      '\n  Installed release : ' + ver +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
    exit(0);
  }
  else security_hole(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");
