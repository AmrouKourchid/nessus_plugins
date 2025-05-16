#TRUSTED 4caf065990f567abfa82af9880fcc77a680782096dd20bcda62e783d2aab9ecbfe2bc0c70f2e57ad3f7213515df66df811c9d0c2b00e7e6604bf445449a7302dc4f4a22b1b3184ddb5733b53b67f10dc45a061c34b0687a10faa737ac09cdd317dae5febc42eb9b8356f26c2c4ba529611b217c1aada8883d7e5659b14b4dfcbbe1eaea21174417f309ce7d71f9bcc968d714d0ab802397fe817d67a1116b5b80b312281e1a6a5e2d2ee7aeef5d008a17cd97aced22500e2704732f544323c43032b301da5c88bfe9552d5174027a794df01f8ba54d5cf96dd8f26d434fefa05248701fce91ee05196964c554525704fa2ea3f35a6ec200142d83fabfea6e758578f555b73ecca70e84a97c7bfa8127b7df2edd69bc6182a3615556147ed4c3d5c5d61b10f57b48d3a227553001e24ac68cce194e305d880785478245680971e3b0e719ef2ae98783b754763905c625b03fe9f321828f71cae46ccab367a6cc9ea221b36d7dc0ad86d7708e4396ced6bf97b67ca32b01034bfa03c98eb4a7f8aa1e6e68f90196df83c650845e95410246a1cddabf4938a9602c53664837c241d88ab930d103852969fe5650c20d6b5cab5d79e651285ff59121930e7011dfb80417faab49d5a34f55a4af5044f55ccb73c38dc2ad25e176595fe499c80f71fc64d5c975b128f50970bc8ae485dfa16ef7b56cc2d9c2d966fcc5bbad4550615e8
#TRUST-RSA-SHA256 1bcf75ea4b24f428d7aac2fde9ab39e7513b67a3cdfe8ba75cf3c7b1ef92cb21685855d04bc279541698aeaa2c82f9d4ef30f070dd380ae6a7f0f81b0b17f09afd616a1239d1e7138f162569d23a20a2c0373deadb3d8e8132bcbc29d309b5710333197b71f9cd2d6e2e331b96b83cd113b94ffa00f02fafd65fdb14eff5f24fb620e83d88443691cc20e1fb2174b62b501bd1520f8b5165035d33ea76a4989a407ff3ebc0fc49f76cd3224000b32a4931060987f5519aee3fed46e99cca2be631038a94faad9e89981e72be478b6a818f7fd28a6380affb95cc7cc7c8a9a95adf78e3224b273a78528b7d1a70f8fbffa1365353c7aaee04f54aa657913ad79796668170fd5951e7be61039422d6b5293efbbbc3fce0664a93f6e0586b1c65aa4f06501dfface77377f88186d613c854bcb74dbe465c8cb615042e9dea6ea689d26479b02dcfb63cfae99f42509df819d3b7de9133b9592af6fd51ef668942d4c94d7220af9f99175956122036a7eacc246cc73731991c2f4d48fad3f89adb2f3ebb80e44cab11167443ce0e1590007f977c9efddc7ab69faf94f8ba41efe923b37f76bfe875071ea5a4932e8c83bbdd2d17336c876968e0b4d965312cdd897b8e1809871ebe6cf90bf3222753fa4d5031a4f84936437b77ce316693a762c3596f5abf5379bf6566bad9ffd0699fa4fb58152a831be1ca5bf0f024433320bdf8
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(66929);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id(
    "CVE-2013-1500",
    "CVE-2013-1571",
    "CVE-2013-2407",
    "CVE-2013-2412",
    "CVE-2013-2437",
    "CVE-2013-2442",
    "CVE-2013-2443",
    "CVE-2013-2444",
    "CVE-2013-2445",
    "CVE-2013-2446",
    "CVE-2013-2447",
    "CVE-2013-2448",
    "CVE-2013-2450",
    "CVE-2013-2451",
    "CVE-2013-2452",
    "CVE-2013-2453",
    "CVE-2013-2454",
    "CVE-2013-2455",
    "CVE-2013-2456",
    "CVE-2013-2457",
    "CVE-2013-2459",
    "CVE-2013-2461",
    "CVE-2013-2463",
    "CVE-2013-2464",
    "CVE-2013-2465",
    "CVE-2013-2466",
    "CVE-2013-2468",
    "CVE-2013-2469",
    "CVE-2013-2470",
    "CVE-2013-2471",
    "CVE-2013-2472",
    "CVE-2013-2473",
    "CVE-2013-3743"
  );
  script_bugtraq_id(
    60617,
    60618,
    60619,
    60620,
    60623,
    60624,
    60625,
    60626,
    60627,
    60629,
    60631,
    60632,
    60633,
    60634,
    60636,
    60637,
    60638,
    60639,
    60640,
    60641,
    60643,
    60644,
    60645,
    60646,
    60647,
    60650,
    60651,
    60653,
    60655,
    60656,
    60657,
    60658,
    60659
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-06-18-1");
  script_xref(name:"CERT", value:"225657");
  script_xref(name:"EDB-ID", value:"27754");
  script_xref(name:"EDB-ID", value:"27943");
  script_xref(name:"EDB-ID", value:"28050");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/18");

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 16");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of Java for Mac OS X 10.6 that
is missing Update 16, which updates the Java version to 1.6.0_51.  It
is, therefore, affected by multiple security vulnerabilities, the most
serious of which may allow an untrusted Java applet to execute
arbitrary code with the privileges of the current user outside the
Java sandbox.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-132/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-151/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-152/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-153/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-154/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-155/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-156/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-157/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-158/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-159/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-160/");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/javase/releasenotes-136954.html");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5797");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Jun/msg00002.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/526907/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Java for Mac OS X 10.6 Update 16, which includes version
13.9.7 of the JavaVM Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-2473");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java storeImageArray() Invalid Array Indexing Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:java_1.6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2023 Tenable Network Security, Inc.");

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
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");
if (!ereg(pattern:"Mac OS X 10\.6([^0-9]|$)", string:os))
  audit(AUDIT_OS_NOT, "Mac OS X 10.6");


plist = "/System/Library/Frameworks/JavaVM.framework/Versions/A/Resources/version.plist";
cmd =
  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
  'grep -A 1 CFBundleVersion | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) exit(1, "Failed to get the version of the JavaVM Framework.");

version = chomp(version);
if (!ereg(pattern:"^[0-9]+\.", string:version)) exit(1, "The JavaVM Framework version does not appear to be numeric ("+version+").");

fixed_version = "13.9.7";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Framework         : JavaVM' +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "JavaVM Framework", version);
