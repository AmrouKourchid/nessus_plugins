#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2024-43.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(206741);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/03");

  script_cve_id(
    "CVE-2024-8381",
    "CVE-2024-8382",
    "CVE-2024-8384",
    "CVE-2024-8385",
    "CVE-2024-8386",
    "CVE-2024-8387",
    "CVE-2024-8394"
  );
  script_xref(name:"IAVA", value:"2024-A-0550-S");

  script_name(english:"Mozilla Thunderbird < 128.2");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote macOS or Mac OS X host is prior to 128.2. It is, therefore, affected
by multiple vulnerabilities as referenced in the mfsa2024-43 advisory.

  - When aborting the verification of an OTR chat session, an attacker could have caused a use-after-free bug
    leading to a potentially exploitable crash. (CVE-2024-8394)

  - A difference in the handling of StructFields and ArrayTypes in WASM could be used to trigger an
    exploitable type confusion vulnerability. (CVE-2024-8385)

  - A potentially exploitable type confusion could be triggered when looking up a property name on an object
    being used as the <code>with</code> environment. (CVE-2024-8381)

  - Internal browser event interfaces were exposed to web content when privileged EventHandler listener
    callbacks ran for those events. Web content that tried to use those interfaces would not be able to use
    them with elevated privileges, but their presence would indicate certain browser features had been used,
    such as when a user opened the Dev Tools console. (CVE-2024-8382)

  - The JavaScript garbage collector could mis-color cross-compartment objects if OOM conditions were detected
    at the right point between two passes. This could have led to memory corruption. (CVE-2024-8384)

  - If a site had been granted the permission to open popup windows, it could cause Select elements to appear
    on top of another site to perform a spoofing attack. (CVE-2024-8386)

  - Memory safety bugs present in Firefox 129, Firefox ESR 128.1, and Thunderbird 128.1. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. (CVE-2024-8387)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-43/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 128.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-8387");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_thunderbird_installed.nasl");
  script_require_keys("MacOSX/Thunderbird/Installed");

  exit(0);
}

include('mozilla_version.inc');

var kb_base = 'MacOSX/Thunderbird';
get_kb_item_or_exit(kb_base+'/Installed');

var version = get_kb_item_or_exit(kb_base+'/Version', exit_code:1);
var path = get_kb_item_or_exit(kb_base+'/Path', exit_code:1);

var is_esr = get_kb_item(kb_base+'/is_esr');
if (is_esr) exit(0, 'The Mozilla Thunderbird installation is in the ESR branch.');

mozilla_check_version(version:version, path:path, product:'thunderbird', esr:FALSE, fix:'128.2', severity:SECURITY_HOLE);
