Tenda <model> ask_to_reboot Vulnerability (Stack Overflow)
Vulnerability Description

A stack-based buffer overflow vulnerability exists in the ask_to_reboot function, which is reachable from the wireless configuration handler (function FUN_00449844).

In FUN_00449844, the user-controlled HTTP parameter GO is retrieved via websGetVar:

GO = websGetVar(wp, "GO", "wireless_extra.asp");

Later, depending on runtime condition bVar1, the handler either:

calls ask_to_reboot(wp, GO), or

redirects directly via websRedirect(wp, GO).

Inside ask_to_reboot, the input param_2 (derived from GO) is processed and then concatenated into a fixed-size stack buffer using unbounded sprintf:

sprintf(buf, "reboot.asp?page=%s", param_2);

Because sprintf performs no bounds checking, an attacker can supply an overly long GO value to overflow the stack buffer, potentially causing a crash/reboot and (depending on mitigations) enabling control-flow hijacking.

Relevant code (decompiled):

pcVar1 = strchr(param_2, '?'); if (pcVar1) *pcVar1 = ';';

sprintf((char *)aiStack_8c, "reboot.asp?page=%s", param_2);

websRedirect(param_1, aiStack_8c);

Attack Vector

A crafted HTTP request to the affected handler with an excessively long GO parameter can trigger the vulnerable sprintf path when ask_to_reboot is reached.

Notes:

Reachability depends on the handler logic (bVar1 branch) and any authentication/ACLs applied by the embedded web server.

The ? character is rewritten to ;, but this is not an effective safety control and does not mitigate the overflow.

Impact

Denial of Service (httpd crash / device reboot)

Potentially arbitrary code execution (depends on architecture and runtime protections: stack canary, NX, ASLR, etc.)

Affected Component

Embedded web server handler that calls ask_to_reboot

Function: ask_to_reboot(int *param_1, char *param_2)

Root Cause

Use of sprintf into a fixed-size stack buffer without validating or constraining the length of user-controlled input (GO).

Recommended Fix

Replace sprintf with snprintf and enforce strict length limits:

snprintf(buf, sizeof(buf), "reboot.asp?page=%s", page);

Additionally validate GO with a whitelist (expected page names only), e.g. restrict to known .asp pages and reject path traversal / overly long values.

Consider normalizing/encoding the page parameter rather than direct concatenation.

Verification Guidance (Non-weaponized)

To validate in a controlled lab environment:

Identify the exact HTTP endpoint/handler that maps to FUN_00449844 (via handler registration tables / websFormDefine xrefs).

Confirm that GO is sourced from the HTTP request and reaches ask_to_reboot.

Use a debugger/serial console/log to observe stack corruption or process termination when GO exceeds the safe buffer capacity.

Confirm the crash occurs at/after the sprintf call site.

Timeline

<fill in your dates>
