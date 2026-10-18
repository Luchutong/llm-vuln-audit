"""Shared frozen source-file scopes for fixed-prompt coursework benchmarks."""

DVWA_SCOPE = [
    "vulnerabilities/sqli/source/low.php",
    "vulnerabilities/sqli/source/impossible.php",
    "vulnerabilities/xss_r/source/low.php",
    "vulnerabilities/xss_r/source/impossible.php",
    "vulnerabilities/exec/source/low.php",
    "vulnerabilities/exec/source/impossible.php",
]

MUTILLIDAE_SCOPE = [
    "src/dns-lookup.php",
    "src/echo.php",
]

MUTILLIDAE_CROSSFILE_SCOPE = [
    "src/user-info.php",
]

MUTILLIDAE_MULTIFLOW_SCOPE = [
    "src/user-info.php",
    "src/register.php",
    "src/browser-info.php",
]
