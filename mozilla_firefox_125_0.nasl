#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2024-18.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(193366);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/02");

  script_cve_id(
    "CVE-2024-3302",
    "CVE-2024-3852",
    "CVE-2024-3853",
    "CVE-2024-3854",
    "CVE-2024-3855",
    "CVE-2024-3856",
    "CVE-2024-3857",
    "CVE-2024-3858",
    "CVE-2024-3859",
    "CVE-2024-3860",
    "CVE-2024-3861",
    "CVE-2024-3862",
    "CVE-2024-3863",
    "CVE-2024-3864",
    "CVE-2024-3865"
  );
  script_xref(name:"IAVA", value:"2024-A-0245-S");

  script_name(english:"Mozilla Firefox < 125.0");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Windows host is prior to 125.0. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2024-18 advisory.

  - GetBoundName could return the wrong version of an object when JIT optimizations were applied.
    (CVE-2024-3852)

  - A use-after-free could result if a JavaScript realm was in the process of being initialized when a garbage
    collection started. (CVE-2024-3853)

  - In some code patterns the JIT incorrectly optimized switch statements and generated code with out-of-
    bounds-reads. (CVE-2024-3854)

  - In certain cases the JIT incorrectly optimized MSubstr operations, which led to out-of-bounds reads.
    (CVE-2024-3855)

  - A use-after-free could occur during WASM execution if garbage collection ran during the creation of an
    array. (CVE-2024-3856)

  - The JIT created incorrect code for arguments in certain cases. This led to potential use-after-free
    crashes during garbage collection. (CVE-2024-3857)

  - It was possible to mutate a JavaScript object so that the JIT could crash while tracing it.
    (CVE-2024-3858)

  - On 32-bit versions there were integer-overflows that led to an out-of-bounds-read that potentially could
    be triggered by a malformed OpenType font. (CVE-2024-3859)

  - An out-of-memory condition during object initialization could result in an empty shape list. If the JIT
    subsequently traced the object it would crash. (CVE-2024-3860)

  - If an AlignedBuffer were assigned to itself, the subsequent self-move could result in an incorrect
    reference count and later use-after-free. (CVE-2024-3861)

  - The MarkStack assignment operator, part of the JavaScript engine, could access uninitialized memory if it
    were used in a self-assignment. (CVE-2024-3862)

  - The executable file warning was not presented when downloading .xrm-ms files.   Note: This issue only
    affected Windows operating systems. Other operating systems are unaffected. (CVE-2024-3863)

  - There was no limit to the number of HTTP/2 CONTINUATION frames that would be processed. A server could
    abuse this to create an Out of Memory condition in the browser. (CVE-2024-3302)

  - Memory safety bug present in Firefox 124, Firefox ESR 115.9, and Thunderbird 115.9. This bug showed
    evidence of memory corruption and we presume that with enough effort this could have been exploited to run
    arbitrary code. (CVE-2024-3864)

  - Memory safety bugs present in Firefox 124. Some of these bugs showed evidence of memory corruption and we
    presume that with enough effort some of these could have been exploited to run arbitrary code.
    (CVE-2024-3865)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-18/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 125.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-3863");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include('mozilla_version.inc');

var port = get_kb_item('SMB/transport');
if (!port) port = 445;

var installs = get_kb_list('SMB/Mozilla/Firefox/*');
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Firefox');

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'125.0', severity:SECURITY_HOLE);
