#TRUSTED 70a5e718ea9d86924ab99c8b2e019092d316e5e77edc22353d700110a1942b3b4a0780cedfffd2b6cf31463219fd075f395a812257af76ebce5ebc3b58add361b948377ab450823d008afd04419c3ea002480d3c74c922446ff8c86377eba2fa1ee771cce61e70a4cec65c46d44df13b739744a9821b385c6c827f32304ddb377a2de87acde8dcb9ab5f8d9824e804b963b42feaeaaa515f43f93e283d35b788fea7c843c41434d97293d90b65dfc180f8ab9db1c42f3169be403fd4eaa6410a6c6f6bc239afb61484a0ed426c3194c10a1e2957906916228b217085b98faefae4a2c6deadc78de6bdad194778c6084504abb01596cd7dc9c89794a8af2d982f4955a42f7d8ad6904a959f8fdb7ab58ce151bc1e4efd93f63401509bb28ec2139d21adeb6651d9eadbc1366141b6115c95748cf5460bd305f2353a8c3cac3699298d9fe44e45f81fc178d9de853c710551874bcd656a974320dba5f769f528903ea504029d76be629172e0a4c5504b26da1e1774f2760e1496870b774c9673d5991a8b46f9238b699e107c20c749c3dce7b727554c007f2c739e52cf09c83f5caf19770d2a13c28e710bd8595fc764c72820dc30c475d6612d2d3d8bdf007b0b3b1f86106783f4c9fe6fffd58051d3458bd05af6155ea8d171404678ddee63481ca62af289caa7a45565645fe1ff8389633127429cb0a9bedbeade307e3698df
#TRUST-RSA-SHA256 601ace01ff949d8d28cc2fe55870d289a8627733b67531771d468a76be5db66b4abeb206cda0785e694d2f8dfe894e517f6e4e3af2b07a38fd6cb2f092b85941aae905b4df1ca1907f83dcf99b32f661f05f66ec78e806365e417ff5c9f209b390e270d5fc04a10a9dda4da28cad05a9bb1d49a052bbe6d8b4bfe76366728a1cdc7caf453de24c395f03714dc8ad739a6e48b5ce0e383f79f531ba7509f81f6a62eacafd63451778a680d3c8e7054b2af9848be468bd7146db4c8ef8e6aec25c81ea7ab4ff942248530f8de8ee0389af40990f1045337059e4464f7303c4f7c9786fef361173a902519dafe74bccd00749f6e4bf711d23017c987b5579807b428ffdeaf4f5befdddba9fd2d6a90bcf546a114609a0828525abf700fc784afe811f7c6214a3606883939e39974f76ecbae9f7ad21a3e69bae6f440879e4f1f1fbe7b762d505f3e3fa84f37e6441b9bb6bc4553dd1c72e9e689649b0aebfb5ffa3f4080aa753197c37e950b52d957a77f14f7f1e76298d440b6c1d13a9ab6ee7ff3dfc1160bac5da498f6b12ec7f1b37aea8e4ca2f1fee9d4a3bf751fcabcb4398b059827767b9313f285aa8248c8389bfddc72be394593ffccdc73068779529871487450757e0a4ab552b4f116b6ed632f45c189f65b71c55f42565b76bae84e5f3e861af87ba090b3648b29fc315e4a8f09ac25f2b00e68296921b99bbe64126
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132959);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/29");

  script_cve_id("CVE-2019-0056");
  script_xref(name:"JSA", value:"JSA10954");
  script_xref(name:"IAVA", value:"2019-A-0436");

  script_name(english:"Multiple Vulnerabilities in Juniper Junos (JSA10954)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to the self reported version of Junos OS on the remote device it is affected by a Denial of Service (DoS)
vulnerability. A remote unauthenticated attacker can  exploit this, to cause the device's Open Shortest Path First 
(OSPF) states to transition to Down, resulting in a Denial of Service (DoS) attack.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10954");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10954");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0056");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('audit.inc');
include('junos.inc');
include('junos_kb_cmd_func.inc');
include('misc_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

if (
  model != "MX2008" &&
  model != "MX2010" &&
  model != "MX2020" &&
  model != "MX480" &&
  model != "MX960"
) audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);
fixes['18.1']    = '18.1R2-S4';
fixes['18.1X75'] = '18.1X75-D10';
fixes['18.2']    = '18.2R1-S5';
fixes['18.2X75'] = '18.2X75-D50';
fixes['18.3']    = '18.3R1-S4';
fixes['18.4']    = '18.4R1-S2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check for NG-RE, if not output not vuln
buf = junos_command_kb_item(cmd:'show chassis fpc pic-status');
if (junos_check_result(buf) && buf =~ "Slot 3")
{
  report = get_report(ver:ver, fix:fix);
  security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

