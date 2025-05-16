#TRUSTED 53243547695156cb375c7e165afc76c258965f90a232f73d9194af795410e98671f50d239fc6551be58474c75c4fcbf40fcc7b30ca66e4b326a4d2850fd95e5fe3b745e790b82a999021868dfcdbde78c59a1dff7a81800fc4c49242d3b650f9b78c440c2964c918b16e8a81c44a6dc84bbbfa57993d30bbf6f69d89839daa491c878d83a83d4bb11951dd3adfed0f6a766b6e597fc5448bfaec53b35d2ffa4f0b735d8a6411c1672c692f755ca9f81fc740370ee35133a26ab0d4f53e1b5fd9ef35531f5465b5fc0099e5a880927d490d6e0bcf28fad144203ef9bc8317ff9060e23111d52cfc8a86b33efd3fc8833965d8179e6dd757a92c0ec41048831374853b3d627b956d63300684833f84e810e39be6cf0337f13e9acf1ac8740712a04366b7db8ed363e9d63c84b23433254b4af3a9282e08e9fce9e67db7d02960adaa29cae233c33c64693ece697c9ab27016ae39be401bc0fefcef5e811591f4e526cd6d45d8ebf934cdd6ae2a63e929dabfe17581ba3f0dcd3f0d5109a00a0492595d199205e3812125854a775e88aaf3d27343ba75a8ff0ddd9220129723c08e59f789ac081167e1b36408b402af26acf349cfc6cb90f9ac3cbe35ae015a7844fb3ab4c9e07dd33c36ea8f7d7ead1479436543ec93a868223d85a329bbd35ce5f1f80dd30113f78cf309f287c5b7e33174a29abe763afa25c083a32c5188e170
#TRUST-RSA-SHA256 a6e35c6c81f7ba2abc134a79c0e72d5a5aa153ad91ecb8a44e3903532847174d6e94ff3061f194b25551adc66ad5be7224a1a42dbe1f208f429e29569a29b37c5a17b73f06c327047e6c159c0daae1ed2182b6de87779a51b63c161f66ab316ec80af8bcf6c2e766673b18d91e2816e74837a8f37c0ee7c1a31b3ec2aa4473d8a4300ba7fbdeb76fe427d92691bfdf40fd47a44b0562f436f16630e8744e4f3361f30c720f97a1dcc2b73809dcb35bb83b4ed72ca70e4779fb72b206d9fcde375db373168144cf10eaa776f8aec4b98b7f36e0b52043b0ae1b31ad7961566bfe6dddb3e19982dffb10a8eec07a6507998692e3b957f82256798f8afa9c298fa7df9471127e3730261fc5cc51a788d6be7bdf27a79f7fad56446d9d4ebbf9ee87da4d5c03fdf64e36fea9ba9669e83b370779a9b6e4353eec7ead59227c46d827769f33ac59863af6fc5a52dc74b12fd1747a17322eadc8a7817ce47902f526a7d5c9fc267df16fa1ab26fbb2b070a0a833093210cf35696049223e84396ea83161ec1b41c2d5cffe104902f994b3d820346e51872210f13058f848fc70ee164cfbe96caab80a45edb0e2f70ed3c87ac178bdff3a4bdb8ff18c7373d864fbb36c929dbb209c5c658272ec44c3e381248692b41553b40bfb3310bbfc443cb2c028e308988e1ff8f5dbde1b81698295b96ecbfe6f4c158b528b51b19c5a613a0ae4
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73346);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2014-2106");
  script_bugtraq_id(66465);
  script_xref(name:"CISCO-BUG-ID", value:"CSCug45898");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140326-sip");

  script_name(english:"Cisco IOS XE Software Session Initiation Protocol Denial of Service (cisco-sa-20140326-sip)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS XE
running on the remote host is affected by a denial of service
vulnerability in the Session Initiation Protocol (SIP) implementation.
An unauthenticated, remote attacker could potentially exploit this
issue to cause a denial of service.

Note that this issue only affects hosts configured to process SIP
messages. SIP is not enabled by default on newer IOS XE versions.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140326-sip
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0dba6e85");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140326-sip.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/04");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2024 Tenable Network Security, Inc.");
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
report = "";
cbi = "CSCug45898";
fixed_ver = "3.10.2S";

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

if (ver == '3.10.0S' || ver == '3.10.0aS' || ver == '3.10.1S') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_processes", "show processes");
    if (check_cisco_result(buf))
    {
      if (
           (preg(multiline:TRUE, pattern:"CCSIP_UDP_SOCKET", string:buf)) ||
           (preg(multiline:TRUE, pattern:"CCSIP_TCP_SOCKET", string:buf))
         ) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  report +=
    '\n  Cisco Bug ID        : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  security_hole(port:0, extra:report + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
