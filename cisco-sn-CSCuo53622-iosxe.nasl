#TRUSTED 4f8dbfb117aeec4cfa7e12b94114af6b732f53d3a036e0f19caba9b748a4e61df11c35e3438b14eb509ddd9c76bb935c35153c6db36dbb752a72d7ed7de98e02c58bb9c8e75769da0578b35472c6a78ba283ef1c4dce070aa608b3b4c28dcc0d016074027d5670835f138e5eb49f6586ce7e6c249a9fc7d9e1f5c702c426aa478569f06ef41a38d896798e9a857d21f7e71e34b415bfaf63efcf515a37c3f627a0aa0a1af380feb83070f49e190f43c95d781d920ba396b1f468d7afacbeafe5a4eb8851153f3a80ea3fd7c829e5165f9a93faf004797c271fb57e75fe522860ca9f57bc761b6857bc0a45ada665889bf8ef9bef6a2ccf0db670607dbb4b871a2d0d92ffb3fd357330cda4d04370fbda39c356811d5cbe90a52fb8198c22499ada34cc15d5e99e21a9025da994b1eadbc9d58b4f12548327167d117bac486ad5f8af0e7f1c78fa888184b92c3afc23f870825f35defead9875f51e1ddfd85a31837586d004a8d8ccc206ab4b3e733d6cc8ca7ed22f16b76d32e71b0eacb081e19af55f02a3de107d7c8236573939f8777166e8a433f551e8b53398a63c869f40931fcd24bfd69b7af688045c2f994381d1dfca457b84524a5253f63cd4a895685924083170bbe7c575d7c603f0abd5a6ab8d9e9d78bef2284108fd10b96b871260c14ee93de361257e04be8910943c7dd60be8e261e79d28c1c6fccbf98ebb99
#TRUST-RSA-SHA256 09d134fb8c226417495c81195400a2135d44062cd4f4190c40b33c267a1a4664df15686bcdee5b1440f725def493ecb24768881a75d9155dba83632fbcf3999332a40a3cb30311949b9355d51ad8f641ad24e055d0e7ee8c66b9836b1ee3341ac19ac5114240b2a8e8a9ef5297934067cfe0b40a9d6c2ce182cb10a33e67d4c28edbdaa42de420864f6e28fd2176542f4ce51178dd81a9912a4a1b1e47074965510413a12eff36e6647e674cc2cec10530d65caa6a86e2cb5a502cfe7af057fe6fe277fda6c8ff15effb37c3fa56eaaa8ca1c828f3ec3645a7c97b669a2d44fb0259d00bcce6ded69f4bf73810fd51b2931f2a03756fd468b975b32b016419108bf44ef31a03057a6e07824cb15fba6aa52992a6da33807b0662c3a48844aa16063b39878c9e328aa7cdea47d478f2599f6f0f7b7dd8de55c1d09401116e5da552c3f5e91af297c0ef432b7c6bbd7d4c9745fcbee8dfa8039f1556c6af43a33b7cd79dc272ebbc24b0e017f03e58615c1f127cee0fe977b7e80d8fefb7c5c7a67992e76897c1f06e0f0dbdc5a4fa097a4d1f352663023c6591afd543d8b9582370a6f544529ffc4b6458e0de12f27937bb5cf2d597825967ff87a058147eb01bb0e85bf86148dd17ba8ee57bcb9dfa686b3c037896529c1b301113c8f8bf4670793ae018769be24204f48ab06a455a8d67da390b20a264d6d3a8befd903418dc
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82589);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2015-0644");
  script_bugtraq_id(73332);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuo53622");

  script_name(english:"Cisco IOS XE AppNav Component RCE");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Cisco IOS XE software running on the remote device is affected by
a vulnerability in the AppNav component due to the improper processing
of TCP packets. An unauthenticated, remote attacker, using a crafted
TCP packet, can exploit this to cause a device reload or to execute
arbitrary code in the forwarding engine.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150325-iosxe#@ID
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4cbb5bb");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuo53622");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco Security Advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0644");

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
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
model   = get_kb_item_or_exit("Host/Cisco/IOS-XE/Model");

# Per Bug CSCuo53622
if (
  !(
    "ASR1k"    >< model ||
    "ISR4400"  >< model ||
    "CSR1000V" >< model
  )
) audit(AUDIT_HOST_NOT, "an affected model");

# Bug (converted) and CVRF
if (version == "3.10.2S") flag++;

# CVRF
if (version == "3.8.0S")   flag++;
if (version == "3.8.0S")   flag++;
if (version == "3.8.1S")   flag++;
if (version == "3.8.2S")   flag++;
if (version == "3.9.1S")   flag++;
if (version == "3.9.0S")   flag++;
if (version == "3.10.0S")  flag++;
if (version == "3.10.1S")  flag++;
if (version == "3.10.2S")  flag++;
if (version == "3.10.0aS") flag++;
if (version == "3.11.1S")  flag++;
if (version == "3.12.0S")  flag++;
if (version == "3.11.2S")  flag++;
if (version == "3.9.2S")   flag++;
if (version == "3.11.0S")  flag++;

# Check NAT config
if (flag > 0)
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_service-insertion_appnav-controller-group", "show service-insertion appnav-controller-group");
  if (check_cisco_result(buf))
  {
    if ("All AppNav Controller Groups in service context" >< buf )
    {
      lines = split(buf);
      count = max_index(buf);
      # Find 'Members:' line, followed by
      # two lines of IP addresses.
      for (i=0; i<count-2; i++)
      {
        if (
          lines[i] == "Members:"
          &&
          lines[i+1] =~ "^\d+\.\d+\.\d+\.\d+$"
          &&
          lines[i+2] =~ "^\d+\.\d+\.\d+\.\d+$"
        )
          flag = 1;
      }
    }
  } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco bug ID      : CSCuo53622' +
    '\n  Installed release : ' + version;
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
