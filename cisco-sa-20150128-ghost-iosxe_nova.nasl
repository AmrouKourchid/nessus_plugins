#TRUSTED 163a9d3b1f62f86a24147e8a99bae2f5a2709f11e66f2acc07cefa21b0c7dfef35f402d6379fa64ebd7f08f3d20a3d9e80a64a39e5e11bf7d2a3b86c477f4054f72140bad7f482640726b888ef2de368a4bf302f56dc7eb26fc2a177c9cd5d8fa4c162d3ed9f638248c39b53b5065ad192cc7d3971acc3c3fc043c50236933299fc14ca7877c0f2cab656834da7fad0438a5d5490867f43d5b8447ec9329ba50006761e2d37f3a5b9ea3d94e906bf3b6ba48bfed5d136db0ff200235527f09b400c6cfd843f648d7f8ba66e999e58a4c7efbfef1b4f05fe7ae28f4b837aad26e99fe7cf088fbd28da5a77a05e1de1b82e8f12f57d8d5b5c4ea95a9c6c35e8078155dfbd059584473c8e8083e0c307d8f4992254b8707bc0666ab07b2b78e4bc5df91df700929cbc4fec7e6dea00bfe77ea32af14f83f69b307cd575b5d39f54db69d0c399f6847be82d3dd1cb065d5f3af99097d2fd6ae97350447a4ebd145a1e13f58fd2bdff222d024114ed0e4df623fe6bc82fbbc720335695cce023101351af3575bd00b757b8bfafec157506ed9b56e17a21c2d938d40d3d1efa36d1e663e39ab44272f539125d2b99a582b3f01f4732ff91bc1a319576e70d79f3a30d6201a9caa7fe03e362caa5c99654dc10d4053afb9fff427881ba7dc42fda19e3a10e024e258f79334a2a97801c9416c38111988616accf6ffc5b6d9668a002be2
#TRUST-RSA-SHA256 4aab9dba2b23d56a54898ad6aef77807031ae0debab2a536b1924af593c9d0c1875f90eec9d36b2e407b02f0a744b3c359f0d4acf621dcf7a1b7568d68c97a779792f2aa0b874b78827864aabbe17f7ea6454bc3bb85162ea56246067916df437e5342cbabffdc96800fcb714e6f11ad74f6fd34e193a664a5abd90aec8fb46ea2725bef8219416353e0045d013aca3920cdb043fb1f5321f91f96f6b9e8e6646a15d6e61fdba4d45e4948a53026b732cdf4e09663858dee301188eff2f3faa3bd6d8ed48d44060de87e1dba2b8eaca4fa069de2553eb6b4441465f64fd0b389edeb4565984237555c396e99c7cebfb70c3d8155ece123b8cebeb233db96e14d281c98ddbb503582e462d8cae14122577b340d1441c62207fbaad632447c42a5683d0545f1955cb7ba4dde067b33b5383440e81f413b9c58b509a87adc4a3db355d6aef63d0bac65dab4c9435da55db7737a26027aa64c0ef386b06d57eee6917120a1a6307536aa4868798300a1fa17d58a556c04409e3225e6aa922e4919eb1983ac00c9567ec22a4f85d1664eb2897efc8292f719783bf35cd664d41cbfbed82d07eb4711cf676e2b2b80336530a9e2c8051d2ba1483ef2df0b47a119aa749d9106e778d7f69fefb2fbeae9b5af3091ae4b96d05719d55c21ccf53151a54709e8cac4a636fd821cdc4e1969ad6ca527add5f8b65d6318f5afdc295406e877
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81595);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2015-0235");
  script_bugtraq_id(72325);
  script_xref(name:"CERT", value:"967332");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus69731");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150128-ghost");

  script_name(english:"Cisco IOS XE GNU GNU C Library (glibc) Buffer Overflow (CSCus69731) (GHOST)");
  script_summary(english:"Checks IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is running a version of Cisco IOS XE software
that is potentially affected by a heap-based buffer overflow
vulnerability in the GNU C Library (glibc) due to improperly
validated user-supplied input to the __nss_hostname_digits_dots(),
gethostbyname(), and gethostbyname2() functions. This allows a remote
attacker to cause a buffer overflow, resulting in a denial of service
condition or the execution of arbitrary code.

Note that this issue only affects those IOS XE instances that are
running as a 'Nova' device, and thus, if the remote IOS XE instance
is not running as a 'Nova' device, consider this a false positive.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCus69731");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150128-ghost
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd2144f8");
  # https://www.qualys.com/research/security-advisories/GHOST-CVE-2015-0235.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7a6ddbd");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco bug ID CSCus69731.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0235");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim GHOST (glibc gethostbyname) Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

# Bug notes these are affected on 'Nova' devices
# only.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

# Per Bug CSCus69731 (converted from IOS vers)
# No model restrictions listed
# Further note that IOS version '15.0(2)EX'
# is not mapped and thus, omitted.
if (
  version == "3.1.0SG" ||
  version == "3.2.0SE" ||
  version == "3.2.0SG" ||
  version == "3.2.0XO" ||
  version == "3.3.0SE" ||
  version == "3.3.0XO" ||
  version == "3.4.0SG" ||
  version == "3.5.0E"  ||
  version == "3.6.0E"  ||
  version == "3.7.0E"
)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco bug ID      : CSCus69731' +
    '\n  Installed release : ' + version +
    '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(port:0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
