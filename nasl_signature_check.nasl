#%NASL_MIN_LEVEL 80900

#
# (C) Tenable, Inc.
#

include("compat.inc");

if (description)
{
  script_id(179042);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/31");

  script_name(english:"NASL Plugin Signature Checks Disabled");
  script_summary(english:"Determines if NASL signature checking is disabled");

  script_set_attribute(attribute:"synopsis", value:
"Determines if NASL signature checking is disabled.");
  script_set_attribute(attribute:"description", value:
"This scan was executed with signature checking for Nessus plugins disabled by a scan setting. This permits plugins to
run which have not been vetted by Tenable. Unless you have an extremely good reason for enabling this setting, it is
recommended that you disable that setting.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/31");

  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_set_attribute(attribute:"always_run", value:TRUE);
  script_set_attribute(attribute:"agent", value:"all");
  script_end_attributes();

  script_category(ACT_INIT);

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_family(english:"Settings");

  exit(0);
}

var nasl_no_signature_check = get_preference("nasl_no_signature_check");
if ( nasl_no_signature_check == "yes" || nasl_no_signature_check == "true" )
{
  var extra = 'This scan was run with a setting that disables NASL signature checks.';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : extra
  );
  exit(0);
}
else
{
  exit(0, "NASL Plugin signature checking is enabled.");
}
