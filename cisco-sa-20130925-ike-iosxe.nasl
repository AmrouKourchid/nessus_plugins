#TRUSTED ab37ede9b605320b7b619e20ec88def0ca200ba8c3df0b91422b1591ce9d67650cc1e34b0358fbb143f872e5ebb6480adf4511ec3079ed0be201accc138383a58b836d96ba3e3d8ae118bd08e2491124a55b6c8ba9455d810f6b323b4aed5a8fcd34bda408dcebfa1147d011c5dd29bafb7647c203e7f5384493a269e47be9d6ba43e365896058503d2414b26df60cc274d5ca8842f2c28b87c65038d81f8c97b4f65c69b8630f1c266c2b9c1c24376605dc5e101bc811a12542a3304a279c92a10c8008267d95e1ffb69a713e0be9e81407f5c41e35b022bdc8b3330a2a682b09b72a6a108bfbbbb70bb081fc182dd226dad51d174b5c45c0c573256c723e9ced15eb91e06fe99659a7abfa9592568b5b6f2b6d9b53e8004ab16d509a7691dfafcc2dab3fe5f8aeaab8e1e36397e887c081eb3c99b82d3b7051dc863d187f101b265115b7c9ef34158359b184c4f7f787ba061586c3ce106a7b3c33c19288df1c8064e2750d7bdd285970735662f72e52acb4b6f8a937449c18f29b7a13a76ae5503ca08ee0a01fb2858e5665e1da5bc313ef5e4577d9deeb090b54ee2a26ba4ee02bd51d698913a50b0b502019f37379ed9629e501745de2dbe8864ce878894f33241fc3197519fad5584a81225d716e3ecb147bc514c526cb72484e69eed7377fa89bb814a7a5db63e4c92bc5df62189c904ced1c8b04290f2dd6bcf4a736
#TRUST-RSA-SHA256 4a8882e9702339a4516bbe7aea7a88d72600202acaac2149af42932d5b942edc23132641290fc7ac16a4b1ebba6f36cb141bbb1c4dce2ee31c2490051a28bdbb43e76b579c2b2ed02acb755fbc7ee1ce53c55a9e776eefc117e6de7e040a45fdd84021bcf935bf21887d885dd082b4c808a215a36250fc8932a4fa29966b3292150f7ea5e5e2f529162b2c4dc50ed8eca49c5d6193b117918bf6b91c3650084aec956e54e53769f09af93c618511e9db43baaf81a34c802a9bb232a33725dc528eae041df4163b676c34b4d318e211518b71df6456fb2fca0554fa1bf307b2b5a69ee6e322656fd4e674d0512d96a39f16563e53352c8e3ff84d1f1e209e02fdf81b6ffed625399efeaf1de2d8d829b8b7cdd4d172a167bc0ecc98d0cc35ec935b54146d54c66ffea2bcad85e6980fb8abf84983367f23c75e905e8e8ebd67e6966d4d6b0472c40996f96dab8b8c4ac8b37b3d7ac569c0e4c4e55b59e34e31c9aab9f47be1dd6353f1a83ed24f67e21ba7c838a7ff36b7974461115a7d7ada91455f02b41fce6edc3eb621a8f001ea4160842292a95ec7b1ce9278fe039f8e001395f28e22203b110b7c03df7de1c91ff6938ead633bd0fa3df1019424b320fbbc1481f0962fec3b08192977457afa557e7cb4b8f728f9a289986464996754c150670362fff6a2900dfb8159309dd147dfef15955837b30e857686539e14ac9d
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20130925-ike.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(70317);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2013-5473");
  script_bugtraq_id(62643);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtx66011");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130925-ike");

  script_name(english:"Cisco IOS XE Software Internet Key Exchange Memory Leak Vulnerability (cisco-sa-20130925-ike)");
  script_summary(english:"Checks the IOS XE version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(
    attribute:"description",
    value:
"A vulnerability in the Internet Key Exchange (IKE) protocol of Cisco
IOS XE Software could allow an unauthenticated, remote attacker to cause
a memory leak that could lead to a device reload.  The vulnerability is
due to incorrect handling of malformed IKE packets by the affected
software.  An attacker could exploit this vulnerability by sending
crafted IKE packets to a device configured with features that leverage
IKE version 1 (IKEv1).  Although IKEv1 is automatically enabled on a
Cisco IOS XE Software when IKEv1 or IKE version 2 (IKEv2) is configured,
the vulnerability can be triggered only by sending a malformed IKEv1
packet.  In specific conditions, normal IKEv1 packets can also cause an
affected release of Cisco IOS XE Software to leak memory.  Only IKEv1 is
affected by this vulnerability.  An exploit could cause Cisco IOS XE
Software not to release allocated memory, causing a memory leak.  A
sustained attack may result in a device reload.  Cisco has released free
software updates that address this vulnerability.  There are no
workarounds to mitigate this vulnerability."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130925-ike
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bfaf2180");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130925-ike."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2024 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}



include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
if ( version == '3.4.2S' ) flag++;
if ( version == '3.4.3S' ) flag++;
if ( version == '3.4.4S' ) flag++;
if ( version == '3.4.5S' ) flag++;
if ( version == '3.6S' ) flag++;
if ( version == '3.6.0S' ) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"crypto gdoi enable", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"crypto map", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"tunnel protection ipsec", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
