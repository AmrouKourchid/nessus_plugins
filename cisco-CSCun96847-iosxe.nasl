#TRUSTED 234828a7a88bc44242ff6ab9263bd06d408f2fb8178ed5ccf7858570afe55ed82c3ca02114b82a3dbb303e1a79df8199900a48c63274c3a9d398381a639a645ee5a6d354bf9122c6a82a6ba7940694f034ea4eb208337f1da08452af522af2a86c60dd75a39f5aabd1cf76698bfddf18805f8c57b4b3ab0ee130d54d95dc2a4c35e8ee464b454487bb3415cd13d4e3363b689880d0eeead8fb0ac09b28e642fd804015343e725ce6d056cbf07266a15a54b70d3192a853b165b763445d774e33dc0ef126ae276cbbc70a3df490cac30a24df479f86b2f16658b1169d291ccd641809aae39e801073a7092f112aeed12ac988486af6e1b5efe6ca12b3fffa5cadb7b6b1d34a2c566f6e2ebc95d126a61db9992051a36e78c06be44da5bc09c585728d47732da9d434ab9eef3bb68a6832874fd545f5b1cb177647a0c8293839ac0d8beba896cd006ad647a2ba40849c3b0a88189077750eefe2a007f24e3b00d306b8b288761c34a0105405e8513f15bec726fddf19450818b5377f71f9c2e32cb89149d751253298bd1ae72c7f87b4f078a40bddd13301ca744019704f585f240cd286031e3bbd97a02a7b1bf64bb72f8b9ce1f3e3a0380461ccdb7efafc99d9c4637fc00f293201922165ef06a5ef61a02bf2078b4e7b3509bed50c39560fb1bfc5fcaadb48ca0696463e2d2b334c5c9cfbf1c6b3c0eb6fe1c66fd2768a1c77
#TRUST-RSA-SHA256 5983b794bcbbdd8f8c0170c1da5eaf62ef7104a24e61d6d87768f5928adf72a893ce065d081c298730fc5f9ca6b3a0227a551997b6b856154159c2e50a6555918ebadbf9d2847dcb7d098f5424ddd77a182012be4940241d4e9bea25926e5890ec974f2200a62d10e707f221d61a8653493b84e672eda6eec5c3bbf65d330f0106d30563b948ee084ace1f44a284158fdd54ca141620c1a08441dd117eaf468e690081af6d946cf3825396bb7b019247884ca8cff456e8df2227a14d9a6b14076cf1feea70f99d38ab6f4d0332b3b5e951c133f71f7848c89e69807de7335096d89bfa16e9ea9d72cb832b571faff51e800238d0a7e737bd22d2b82b8978c1d65d2bbd900bd276155390227691720255824164a8dba815964fc51c6c661c1cce5c32ee91d50c9a31c46651a0d3cb53746cc664c3316568627eb57fd6a6fd0bf01e585b1351b784c62918dcda007c69b075a718d3090964e7beee3eb056d02d56756258a72272bcd59a38489128cfff151e451d77e43161d9511e3441688bc7e3ae7fb8c4819d7bd59ba86a89ffb176765330c61609c59efc0455e7a106c34283a2cc05c8c474e0a838b2596c086189592d2bdef604a99ae3ba848959697d1166c65fff0263b10d1480359fbec9f5390795f8e8a8b9de94576bb5b2d5d126400b66af76131e6ab0bfca34e4b161ec73a01386c63919df17b537026fe02b418d5e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91855);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2014-2146");
  script_xref(name:"CISCO-BUG-ID", value:"CSCun96847");

  script_name(english:"Cisco IOS-XE Zone-Based Firewall Feature Security Bypass (CSCun96847)");
  script_summary(english:"Checks the IOS-XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS-XE software
running on the remote device is affected by a security bypass
vulnerability in the Zone-Based Firewall feature due to insufficient
zone checking for traffic belonging to existing sessions. An
unauthenticated, remote attacker can exploit this, by injecting
spoofed traffic that matches existing connections, to bypass security
access restrictions on the device and gain access to resources.");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCun96847");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=39129");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco security advisory.
Alternatively, disable the Zone-Based Firewall feature according to
the vendor advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-2146");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/27");

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

# Fix version = 3.15.0S
if (
  ver =~ "^[0-2](\.[0-9]+){0,2}[a-z]*S" ||
  ver =~ "^3\.[0-9](\.[0-9]+)?[a-z]*S" ||
  ver =~ "^3\.1[0-4](\.[0-9]+)?[a-z]*S"
) flag++; # version affected

if (flag > 0 && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  # verify zone-based firewall is enabled
  buf = cisco_command_kb_item("Host/Cisco/Config/show_zone_security", "show zone security");
  if (check_cisco_result(buf))
  {
    if (preg(pattern:"Member Interfaces:", multiline:TRUE, string:buf))
      flag = 1;
  }
  else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag > 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCun96847' +
      '\n  Installed release : ' + ver +
      '\n  Fixed release     : See solution.' +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
