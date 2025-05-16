#TRUSTED 104741b523485e3154d8649c3bafe18964fcb8fa5370a48e2e5d0eb0ed5d568ab88fe07ede22fab9b41bd970370e127cd3c6639e5c98295131176e4d1d2fad2ec58ffb86e6f6319779e49c44f1cfc62164d8f06dbe3a624f3a65b971cc7bf58627aa2295d57314e3c68ae80999425f0f014402afbb555e1c6f6de38d5146fa373b291ca85f9f5294bbaa1b4bb89382b3f498a59049965625c0ceb29086b581453045361586b6feb6b287e45ab8a6cb128d5d03c0d078789192fe987a1e68c450afd11f5dc0491857cd80e03c7d68a6890198912d1456f483fa4c8dfce91e1dba93e92d7b85bbc9dd76caee9e766607a62cd1f39d5e706ba030fdaf37a211f1ec42f7305d6a3786da37e42628aef11e53b05186f3f26c798bf237c4cc8427713e5e6776c893d8dc0032f4a74d496a122333bf9b0f0cfad9a06182200dafb52671b008ca1c58e816593d08932857146c58b5c874acaece8170399c847a702f6bc2d587a3c67aab424572bdbe98830f9e907931626d3122f01981a32e9db1aa2eb8426bee41d2d0eadb4017a7b468338e4e6d798b83d57d59a7b3415dce07c2da6cf85b8cc5bd459d79968073559541b39d24dd7c8897f8e0ab3a712b9c3d2ae5657ef1a850c8cb694c588e844575033ca5ee7455a9e1b94d33c8c6ed3cc2407450ce6cc1312e82a00788d570921933fd6e0b4c282fb028c5e2b689b32a6174a5f8
#TRUST-RSA-SHA256 5c0d181c4a2b2401d5f3cd31daf2a495d6480d6ce095002a23d23b8902f1e3dbfe14bb4d5eaf71a41dd31a3dcf8e4212962c29d6a7be0c80c2ed74717cec58a47f09c6d9927f4f95e34c684b78879a8e8a4fb50f1588532f41704cd361060f7818522c339f02b8db6cdfeeaa0b71a46ef4e972db2e6e15ed7c1eae680632506840c929a33f5ec3e0a5780e6819efb38bc203fa4db4c2096606e134e5319716ecc96a22437e3a39fe0b9e4dcf2a8f6ae407f4a4e6f7b489e874e4689cfa8e0f1cd01b226863deee9e58c07bba91d5872225d8a465121b5b7b124c01c341948143c2a26c87b6a015d934413dcbd3aa7163daee8d0dcdfd017958f2c787e360c53d563aa5debc38b0317c84f5531653e3343dd24c57ff8dad13e9186e0624843155c9939853c891ef684fbf49f096539e22f9b2da6f2e19a94e0450921f6cb500da2c1e1768a6d0981010c96091f98e438b62152bd206f8e52e94b5ec0bc7b3cc9b3acd7822c86e5ccd7892f9bde54abe2cc036ce432bfddc0c7114336cd77bac92f7f36e28b679001cab06f62a9f0a3058d61665374cd7692278fb72e128f64d75289032180d768f67307cf00ddb503ea9a5227338763d1090aa8d2bb4e54d5144bb004242a869ce9f11dc86011c032533057f3c4808477096081d1b25b24cc1435d14cb06c42202ce0aca99afc2b2560bfecab2c394085625fdd94b3fdeb70f38
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86247);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2015-6278", "CVE-2015-6279");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuo04400");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus19794");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150923-fhs");

  script_name(english:"Cisco IOS XE IPv6 Snooping DoS (cisco-sa-20150923-fhs)");
  script_summary(english:"Checks IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing vendor-supplied security patches.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS XE device is missing vendor-supplied security
patches, and is configured for IPv6 snooping. It is, therefore,
affected by the following vulnerabilities :

  - A flaw exists in the IPv6 Snooping feature due to
    missing Control Plane Protection (CPPr) protection
    mechanisms. An unauthenticated, remote attacker can
    exploit this to cause a saturation of IPv6 ND packets,
    resulting in a reboot of the device. (CVE-2015-6278)

  - A flaw exists in the IPv6 Snooping feature due to
    improper validation of IPv6 ND packets that use the
    Cryptographically Generated Address (CGA) option. An
    unauthenticated, remote attacker can exploit this, via a
    malformed package, to cause a saturation of IPv6 ND
    packets, resulting in a device reboot. (CVE-2015-6279)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150923-fhs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c8077d4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs
CSCuo04400 and CSCus19794.

Alternatively, as a temporary workaround, disable IPv6 snooping and
SSHv2 RSA-based user authentication.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

flag     = FALSE;
override = FALSE;

if (version =='3.2.0SE') flag++;
if (version =='3.2.1SE') flag++;
if (version =='3.2.2SE') flag++;
if (version =='3.2.3SE') flag++;
if (version =='3.3.0SE') flag++;
if (version =='3.3.0XO') flag++;
if (version =='3.3.1SE') flag++;
if (version =='3.3.1XO') flag++;
if (version =='3.3.2SE') flag++;
if (version =='3.3.2XO') flag++;
if (version =='3.3.3SE') flag++;
if (version =='3.3.4SE') flag++;
if (version =='3.3.5SE') flag++;
if (version =='3.4.0SG') flag++;
if (version =='3.4.1SG') flag++;
if (version =='3.4.2SG') flag++;
if (version =='3.4.3SG') flag++;
if (version =='3.4.4SG') flag++;
if (version =='3.4.5SG') flag++;
if (version =='3.4.6SG') flag++;
if (version =='3.5.0E') flag++;
if (version =='3.5.1E') flag++;
if (version =='3.5.2E') flag++;
if (version =='3.5.3E') flag++;
if (version =='3.6.0E') flag++;
if (version =='3.6.0aE') flag++;
if (version =='3.6.0bE') flag++;
if (version =='3.6.1E') flag++;
if (version =='3.6.2E') flag++;
if (version =='3.6.2aE') flag++;
if (version =='3.7.0E') flag++;
if (version =='3.7.1E') flag++;
if (version =='3.9.0S') flag++;
if (version =='3.9.1S') flag++;
if (version =='3.9.2S') flag++;
if (version =='3.10.01S') flag++;
if (version =='3.10.0S') flag++;
if (version =='3.10.0aS') flag++;
if (version =='3.10.1S') flag++;
if (version =='3.10.2S') flag++;
if (version =='3.10.3S') flag++;
if (version =='3.10.4S') flag++;
if (version =='3.10.5S') flag++;
if (version =='3.11.0S') flag++;
if (version =='3.11.1S') flag++;
if (version =='3.11.2S') flag++;
if (version =='3.11.3S') flag++;
if (version =='3.12.0S') flag++;
if (version =='3.12.1S') flag++;
if (version =='3.12.2S') flag++;
if (version =='3.12.3S') flag++;
if (version =='3.13.0S') flag++;
if (version =='3.13.1S') flag++;
if (version =='3.13.2S') flag++;
if (version =='3.14.0S') flag++;
if (version =='3.14.1S') flag++;

if (!flag)
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS XE software", version);

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;
  buf = cisco_command_kb_item("Host/Cisco/Config/show-ipv6-snooping-policies", "show ipv6 snooping policies");
  if (check_cisco_result(buf))
  {
    if ("Snooping" >< buf)
      flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}

if (!flag && !override) audit(AUDIT_HOST_NOT, "affected");

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug IDs     : CSCuo04400 / CSCus19794' +
    '\n  Installed release : ' + version +
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
