# Tenda W15E Vulnerability(Buffer Overflow)

This vulnerability lies in the `formDelwebAuthPic` function, which affects Tenda W15E V15.11.0.10.
(The latest version is [V15.11.0.10](https://www.tendacn.com/product/help/W15EV2))

## Vulnerability Description
There is a **buffer overflow** vulnerability in function `formDelwebAuthPic`,via registered by handler `websDefineAction("delWebAuthPic",formDelwebAuthPic)`.

In `formDelwebAuthPic`, A user-influenced HTTP parameters are retrieved through `picName`, including:
- `pcVar1 = websGetVar(wp,"picName","");` 

In the next,the attacker-influenced `picName` parameter is used in the following command:
- `sprintf(picPath,"%s%s.jpg","/webroot/images/webpush/",pcVar1);`

that will cause buffer overflow.

Reachability: the vulnerable path is plain

![Vul Path](./1.png)
## Attack Vector
Send a crafted HTTP request to the `formDelwebAuthPic` CGI endpoint with long parameter such as `picName = a*888`(or more)

## Impact
- Denial of Service (process crash or device instability)

## Timeline
- 2026-3-18: CVE request submitted to MITRE(9479)
- 2026-6-6: Public disclosure - CVE-2026-36811