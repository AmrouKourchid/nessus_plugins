#TRUSTED 236a82c6e35d13fae8c1483a73485a019ff6a6b77836b8147a213435f1dc7d9b72eb8efc2932fc1a3922f6ce1a92e6faed3a851f3ced5a988b0d8831ca8c4f61f029bab76162052c6636e7d16f49be1bc5fd9bfa71f9f2c846ae819ffb0187bd4d3015abbffc5d8cdc50758d7236e23fb9c0cc73f72bdbcbb4e470c0326d70833c5eb3599e5f8e6a6e537342d840754e026baab542fc5da36fe4682cbb80e4df64c4da92691b29e6af6eca8b7bc132ea6a3e43aab9453b55832b7cd6d216cb6ab6b80024b413b8246feb882921edee53a7976bc9f0e8eb5740ba6dc5cccebd24fedf64cbe23d63a864da9faee59f7b3f407177a4a8a04761030b55c6c081c92008ab54e66e0e2c3f08b90906f54a3c75433686b4ce54fe17703b0fd5b94288dab8f337a366d47bfa58466cecfaf90cc1731b4e4186da2f109472ee9e037d56bd2177f837d2808a6d71cc3ad8f1d0fcaba4429e4ca6462d511489142919617eb1654cb62d38b35575ba00f336df87c8d6f8def75b30fcb8783424dac8eb59f214bd04f620971dcade890bee30fe48e4359a0eda41d9d922801a53973f880645ba26ea31f31d051fe7b5343f5632fec7edc65d1db11f8312a806f3965d50f08f1e3a5f604a44f76220d0d5e115c4afcf175970de3a597c10aafb05f11e36db04bed9e32f252d70ca9dcfcd92b2e61c890fc6a346b90e25778135853737d620d903
#TRUST-RSA-SHA256 710a3cb786eb74121441966026231080c53039817b47873e69ac199f8fadf3d5ef2b5b883da6bda487ad4852f6dcf37c8857ced9d06070c723d33927b523d82b78370bda375a7bec5a50f92646e5a0feb8de4d0b5c1ac82b92e5031481618ef9b489ef40ab30c773e83e2352a1e27c8df3bf5657abe5a8ebcd3bfc8c9c47fc15939430f27841735b79ae576be8f2154b46c6411952d5a2804936dcf57cd969d9f9f4ef78c4de98b348a8d977320284b7cf78970936daebdb80afe19114f317b49225326950b1c435bb34d6204ef8531c7d9e62cbd59adeb9383117694544bfaef2d81207eccf2d624b2a17291e23aeab435cf461f1b53ae6cce88cb1122ddc83f34241158ffd36242e687566136220cd253bff95c5e4818be11a3509a7828ad37703a0fd440b1d9f98f9bc6f64ce6e668dfff05bbccc1b7f1063ecd5398c650481cd9f6e37fcc591a4d0e5e7922c50c3beacbb20ccde218d61b2c0b17944dc4f2326fd26a723496324766976409e3f5976e748f52e5f7860d38a69de573240e1d1d0a838d44503e713adcf4bf532c8fcf957247fad87fffff8a504e857b3abef44c180df9c69cdfc31b81a5efee2f8fe6c5a9f747d70b511fbff575d3ef8071161cd5662d8002fcc4d0580b866a9e6f2ba1de8c8e165dfb2133a31a5c533cfb94c63d6117ae939d717b2bb9955c8c93ef7ec07f898633929a979adec3a626f7f
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(121642);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id("CVE-2019-0001");
  script_bugtraq_id(106541);
  script_xref(name:"JSA", value:"JSA10900");

  script_name(english:"Juniper Junos MX Malformed Packet - DOS (JSA10900)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"Receipt of a malformed packet on MX Series devices with dynamic 
  vlan configuration can trigger an uncontrolled recursion loop in 
  the Broadband Edge subscriber management daemon (bbe-smgd), 
  and lead to high CPU usage and a crash of the bbe-smgd service. 
  Repeated receipt of the same packet can result in an extended denial of service condition for the device.");
  # https://supportportal.juniper.net/s/article/2019-01-Security-Bulletin-Junos-OS-MX-Series-uncontrolled-recursion-and-crash-in-Broadband-Edge-subscriber-management-daemon-bbe-smgd-CVE-2019-0001
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?98ac83b1");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10900");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0001");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^MX")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'16.1', 'fixed_ver':'16.1R7-S1', 'model':'^MX'},
  {'min_ver':'16.2', 'fixed_ver':'16.2R2-S7', 'model':'^MX'},
  {'min_ver':'17.1', 'fixed_ver':'17.1R2-S10', 'model':'^MX', 'fixed_display':'17.1R2-S10, 17.1R3'},
  {'min_ver':'17.2', 'fixed_ver':'17.2R3', 'model':'^MX'},
  {'min_ver':'17.3', 'fixed_ver':'17.3R3-S1', 'model':'^MX'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R2', 'model':'^MX'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R3', 'model':'^MX'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R2', 'model':'^MX'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
