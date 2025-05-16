#TRUSTED 0eec5759100dc831844f263a2a519c338be7d13ee84fa1c508c7ef43e7e036af10018f3088defc689e741d2910f86cc9edeb4a2ac976d5009c47289ac885000627bfd163954bb363a8109f6d9282bd1ad45243faa3e2f0f145f4bbfe4d4593d91a6ebcd2bbe6e965c0a2e3fe20af558d1ae53df75f218940bd992dab4fba1bad0fd45e330bd46783fb2328350598c7b10c31aaf89c91bad59b9b16d6697696b218d7defb262abfc44564db1ce399709dfabda1776cedd14b738ae5b1a7f4bcda9dcfbb9c89bdcd8f628920e78d885861a5db7305690c8fa6e25a9ff74dfa0fb856216cc62682d9f44e785773a89d911df0b63828e7a917366540a30d97650b594e2ae482b3fba7f9bc9b4ee1daeb4b1d1434826c4f6c29e44436e085fdd0ad7115014a088c6b2085f4dad2d5a0a30225f767431bff7aec1a3173eddf59ebe8e47fe29ff0ef54766c0cbb7f4f5b702976f967c124d5d9a07f4985fd8db79267433f03fb09ecadd141caad4f72445bd74f35add2719d3bce9093418eab5453a7926306046e9747b45c65f075d2eeb159112fbdbd03660def2e127169ace58f868662362ecaaf08502752c415199232d0e7bf0a647ac07f2c53d60ced91ab5452730afd210e4bbee0e549cb49e63c8e5bbd7a951aca62affcab8fc4233cd3dacb3fd1d549854fc532a29d47508504c6dad58769560322cb2f4835813b08bc89f055
#TRUST-RSA-SHA256 87b873dedb004dfccbaec2b08799ed1b03e01bd2a98e13201c921f02028842e9073433788df64bb12d00715515492a799c7b1e26ddafccc7071d3d1493e5499aa8535a323c58d5953deeb0a21fd912904074f66a1a88450fc8bf95bdbb1c178c02b630059994c1df7f62a42f132406fe3b2b714c6f06a937fe8876453ad80c6d00860da0f7facae3d74e894706f641238b95c5becfaafec6d451224d43f65bf8505ffae8f631f8176a85f9b55af26669507e4e46ce6b47bf2679446eee66dc80d72741dced92ef35512f93423d28580c1bc80aa743577264eb24f06247c9ca44de6712cc94f0d4c42dc260a715659749509282d6941001c7e4427ee55dd4661d794d508144a7586231f51f1a2ad42859e5dc6b15376ac97c2fe2c439e5f1f725f921212c8cca148c3f513426a0f035c8dd700a335744799ea7f8e74b1c1f80d58beb30b3d51fe3bcdbd453ca7f8e96b8fabb03a63a4b55f4f17b91892413e1ce5e7a20b66b949a1a66662760679d06b254878205710a63373d490485362d12e2f03677cacaa3da9a7c70d67e6d816120241c3487aa6bb33d9edec65273dd2a45301987910a2e9eb05405a679cc3857a0eafb89aa1f98bbf898a24485996d9c5eb7989a692d8423ab93618ab0d072dd220818adb3a34baaf712b0bfd87cbc8ad65ab6e592bec22a2c9c0ed2ae9f3b501624661d9fd8ad7ced91450a38b536bc9b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
  script_id(107071);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/28");

  script_cve_id("CVE-2018-4124");
  script_bugtraq_id(103066);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2018-02-19-2");

  script_name(english:"macOS 10.13.3 Supplemental Update");
  script_summary(english:"Check the version of Mac OS X / macOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS security update that fixes an
input-validation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS 10.13.3 that is missing
the macOS 10.13.3 Supplemental Update.  This update fixes an input-
validation flaw, which allows an attacker to cause memory corruption
leading to application crashes and potentially to arbitrary code
execution.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT208535");
  # https://lists.apple.com/archives/security-announce/2018/Feb/msg00001.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?866048f5");
  script_set_attribute(attribute:"solution", value:
"Install the macOS 10.13.3 Supplemental Update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-4124");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:10.13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X / macOS");
if (!preg(pattern:"Mac OS X 10\.13\.3([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "macOS 10.13.3");


# Get the product build version.
plist = "/System/Library/CoreServices/SystemVersion.plist";
cmd =
  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
  'grep -A 1 ProductBuildVersion | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
build = exec_cmd(cmd:cmd);
if (
  !strlen(build) ||
  build !~ "^17D[0-9]+$"
) exit(1, "Failed to extract the ProductBuildVersion from '"+plist+"'.");


if (build =~ "^17D([0-9]|[0-9][0-9]|10[01])$")
{
  report = '\n  Product version                 : ' + os +
           '\n  Installed product build version : ' + build +
           '\n  Fixed product build version     : 17D102' +
           '\n';
  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
}
else exit(0, "The host has product build version "+build+" and is not affected.");
