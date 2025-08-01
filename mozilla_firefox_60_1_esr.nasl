#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(110810);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/10");

  script_cve_id(
    "CVE-2018-5156",
    "CVE-2018-5187",
    "CVE-2018-5188",
    "CVE-2018-12359",
    "CVE-2018-12360",
    "CVE-2018-12361",
    "CVE-2018-12362",
    "CVE-2018-12363",
    "CVE-2018-12364",
    "CVE-2018-12365",
    "CVE-2018-12366",
    "CVE-2018-12367",
    "CVE-2018-12368",
    "CVE-2018-12369",
    "CVE-2018-12371"
  );
  script_bugtraq_id(
    104246,
    104555,
    104556,
    104558,
    104560,
    104561,
    104562
  );
  script_xref(name:"MFSA", value:"2018-16");

  script_name(english:"Mozilla Firefox ESR < 60.1 Multiple Critical Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by
    multiple critical and high severity vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox ESR installed on the remote Windows
    host is prior to 60.1. It is, therefore, affected by multiple critical
    and high severity vulnerabilities.");
  # https://www.mozilla.org/en-US/security/advisories/mfsa2018-16
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aa11dad9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 60.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12368");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-5188");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'60.1', min:'60', severity:SECURITY_HOLE);
