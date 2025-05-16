#TRUSTED 4f5338d4556fa95c1290126529c5ab90e7cd18166fa8eb46f1c5ad6b60c4b858e17574ffa919f28eb4c8103e153d07eba0a8b8f531c53665ad8db0f58d9bcb6966839dbf616fa0cccf9b9b3f49aa92df4a0de8965611c1973b92d9078f941f75931b7a65947bfde1a274cea7bb51dc589c27dc0ad6f3f88a30339816c61a57c5b4b323910af28b606a7ea5869ac33127809892151f5f38383d88f0f28753ea573ebfd9901394aab8e0fafa7af15feb7463ec011459ff6666ae986b9d8db2df1bf0eecad4dda72c2eb1fec2738002fcc85fe658f8b24ba36e8e7510aca9ae68faebfcd3fc66834fe5470efd72266e105a32bbf39607eefdd27ef3e564c7a71ebea258dd83c5bca4570f26e7b7c6f0cc4c3ed0ebf29b4eecd62a3685f555b2ad776b45edeebf44fb2e4e620e70bc39c05d732106d0d1cfc80d27772a6dee1c47bda61ab44db15c370d052e2b141cd67d3782394087989440f6d502796036a8ab5c653551427bab56ecfc17bf646d9c9b0514625401a73c3237c47574ec0a3e52eb7282c97e9aa732f20d8ccef6fde1b5755488dde1a2098650fb7b15041820514448f136afbbe0f8e99965de8875117551ec06bbfbcd1f578fe81f047d517fc1eeebe61767f3b36faef7c25ad0e4267b35391d37f389f4a36cc55538bf25c664b3200ea044d1c082e1f23a453a22297dd1f7406a212808eab9d9df7a413dfc9f5d
#TRUST-RSA-SHA256 5bef48f739c5896377c30159930f7d141f5cb6f91741d84d2d391cd5364be65302478e9d8b33d9c8e6666e03087a19c26721294b70616ff637c2de9e98301eed15eb91a772d8d11ddbaa7f8813a31d3f6b3c00c2011d43eb90f47569b07e0b9b2ba53360f33e6946d69af16da60cfea3c541b590708df14e84635fa4e8391d68a259ec8689fe8618b997fd7f449b71edc3f813e69b6b98b8a8ddd05ab13700111da04b3d556e4f242c0db2a83a5198b927635a8ad1ca62f3ff93d989d0a590f5e09056fe5d56a9e7fc2274ebf8e5127e131ef8ce7922d23d7498b555396e23500955053cff695d6889cd4e3af13d652e1f0d4c50f22f57f738ee4367d09790c72e27f4d4928d24f307955da35306049a1d08c934befad613ce59ce6bc32c26c8cce52219c226ad603e642a01162ba4ce82053ef744605cdc015e2a5f63c693344539e7e07a4649a97e705bdcb326b1109db0cb3a3f3e64ad0d2499094e9211f8e04cfe4969485841e795e9f13b413a7b5d8348dcbc62612043648d657dc84d2bc101f0c1cbf18dedfbfe2127e55f877112eb2183f90524d8710a7d28ebfe646ac8b7e82818c348653810f27fba5eeb1f7424242e97d110d1f1bd62d923faf51bc0bf23279cabf2fa2273dea00e8002adc7fdd740a80c9d701ca3e31d1d93a31ac4bc7fda80145666d0da2a4a97912702b2c46f07a34ecd321a63655b936e5dee
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82590);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2015-0645");
  script_bugtraq_id(73337);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuq59131");

  script_name(english:"Cisco IOS XE Layer 4 Redirect DoS");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Cisco IOS XE software running on the remote device is affected by
a denial of service vulnerability due to improper processing of IP
packets by the Layer 4 Redirect (L4R) feature. An unauthenticated,
remote attacker, using crafted IPv4 or IPv6 packets, can exploit this
to cause a device reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150325-iosxe#@ID
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4cbb5bb");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuq59131");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco Security Advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;

model = get_kb_item_or_exit("Host/Cisco/IOS-XE/Model");
if ("ASR" >!< model &&
    "ISR" >!< model &&
    "CSR" >!< model
  ) audit(AUDIT_HOST_NOT, "a ASR / ISR / CSR device");

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

# Bug
if (version == "15.2(4)S0.1") flag++; # Not in map

# CVRF
if (version == "3.1.0S")   flag++;
if (version == "3.1.1S")   flag++;
if (version == "3.1.2S")   flag++;
if (version == "3.1.3S")   flag++;
if (version == "3.1.4S")   flag++;
if (version == "3.1.5S")   flag++;
if (version == "3.1.6S")   flag++;
if (version == "3.10.0S")  flag++;
if (version == "3.10.0aS") flag++;
if (version == "3.10.1S")  flag++;
if (version == "3.10.2S")  flag++;
if (version == "3.10.3S")  flag++;
if (version == "3.11.0S")  flag++;
if (version == "3.11.1S")  flag++;
if (version == "3.11.2S")  flag++;
if (version == "3.12.0S")  flag++;
if (version == "3.12.1S")  flag++;
if (version == "3.13.0S")  flag++;
if (version == "3.2.0S")   flag++;
if (version == "3.2.1S")   flag++;
if (version == "3.2.2S")   flag++;
if (version == "3.2.3S")   flag++;
if (version == "3.3.0S")   flag++;
if (version == "3.3.1S")   flag++;
if (version == "3.3.2S")   flag++;
if (version == "3.4.0S")   flag++;
if (version == "3.4.1S")   flag++;
if (version == "3.4.2S")   flag++;
if (version == "3.4.3S")   flag++;
if (version == "3.4.4S")   flag++;
if (version == "3.4.5S")   flag++;
if (version == "3.4.6S")   flag++;
if (version == "3.5.0S")   flag++;
if (version == "3.5.1S")   flag++;
if (version == "3.5.2S")   flag++;
if (version == "3.6.0S")   flag++;
if (version == "3.6.1S")   flag++;
if (version == "3.6.2S")   flag++;

# From SA (and not covered by Bug or CVRF)
if (version =~ "^2\.") flag++;
if (version =~ "^3\.[789]($|[^0-9])") flag++;

# Check L4 Redirect config
if (flag > 0)
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (
      (preg(multiline:TRUE, pattern:"^\s+redirect server-group ", string:buf)) &&
      (preg(multiline:TRUE, pattern:"^\s+redirect to group ", string:buf))
    ) flag = 1;
  } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco bug ID      : CSCuq59131' +
    '\n  Installed release : ' + version;
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
