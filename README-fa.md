# mail-auth

**چک کن، درستش کن، ثابتش کن.** یک اسکیل ایجنت + چکر قطعی برای احراز هویت ایمیل یک دامنه — SPF، DKIM، DMARC، MX، MTA-STS، TLS-RPT — که رکوردهای DNS دقیق برای انتشار را چاپ می‌کند و تا کامل شدن انتشار دوباره چک می‌کند.

## مشکل

ایمیلی که می‌رود اسپم معمولا یک مشکل قطعی DNS است، نه یک راز: یک رکورد SPF گمشده، یک سیاست DMARC روی `none`، یک کلید DKIM که هیچ‌وقت منتشر نشده. حالت خرابِ معمول بدتر از خود باگ است — کسی رکورد را منتشر می‌کند، یک ساعت صبر می‌کند و بدون اینکه دوباره چک کند اعلام می‌کند ایمیل درست شد. انتشار DNS دقیقه‌ها تا ساعت‌ها طول می‌کشد؛ درست شدن فقط وقتی ثابت می‌شود که چک *بعد از* تغییر سبز شود.

## شروع سریع

```bash
# چک کردن یک دامنه
python3 skills/mail-auth/scripts/mail_auth.py example.com

# چک + چاپ رکوردهای دقیق برای انتشار
python3 skills/mail-auth/scripts/mail_auth.py example.com --fix

# رکوردها را منتشر کنید، بعد درست شدن را ثابت کنید (۱۲ تلاش، هر ۵ دقیقه)
python3 skills/mail-auth/scripts/mail_auth.py example.com --recheck 12 --interval 300
```

نمونه خروجی (با zone تستی داخل `tests/`):

```
mail-auth check for broken.test

[OK] spf: SPF record present (0 DNS lookups).
[FAIL] spf: SPF ends in +all — it authorises the whole internet to send as this domain.
[FAIL] dmarc: No DMARC record found.
[WARN] dkim: No DKIM key found for any probed selector (default, google, mail, mailchimp, mandrill, …).
[INFO] mx: No MX records — mail to this domain falls back to its A record.
[INFO] mta-sts: No MTA-STS record — opportunistic TLS is not enforced for this domain.
[INFO] tls-rpt: No TLS-RPT record — you will not get reports about TLS delivery failures.

2 errors, 1 warning, 1 passing, 3 informational.

# Fix plan for broken.test
## 1. SPF — change +all to -all in the existing record.
## 2. DMARC — publish this TXT record at _dmarc:
    v=DMARC1; p=none; rua=mailto:dmarc@broken.test
## 3. DKIM — publish the key your mail provider gives you.
```

کدهای خروج: `0` = بدون خطا · `1` = خطا پیدا شد · `2` = resolver اصلا جواب نداد.

## چه چیزی را چک می‌کند

| چک | چه چیزی خطا می‌شود |
|---|---|
| SPF | رکورد گمشده؛ بیشتر از حد ۱۰ لوکاپ (includeها به‌صورت بازگشتی شمرده می‌شوند)؛ `+all` که کل اینترنت را مجاز می‌کند؛ void lookup بیشتر از ۲ |
| DMARC | رکورد گمشده؛ `p=none` (فقط مانیتورینگ)؛ نبود آدرس گزارش `rua=` |
| DKIM | پروب ۱۵ سلکتور؛ کلیدهای زیر ۱۰۲۴ بیت؛ حالت تست `t=y` که روشن مانده |
| MX | فقط اطلاع‌رسانی — یک دامنه فقط-ارسال به‌درستی MX ندارد |
| MTA-STS / TLS-RPT | در نسخه ۱ فقط اطلاع‌رسانی |

چکر کلاینت DNS خودش را دارد (پایتون خالص با استانداردلایب روی UDP — بدون `dnspython`، بدون ساب‌پروسس `dig`)، پس هرجا پایتون هست کار می‌کند. تست‌ها DNS را از یک transport تقلبی جواب می‌گیرند، بدون نیاز به شبکه.

## قرارداد

1. **اول چک کن، هرگز حدس نزن.** ابزار تعداد لوکاپ SPF را همان‌طور می‌شمرد که گیرنده‌ها می‌شمرند (includeهای بازگشتی هم حساب‌اند).
2. **فیکس یعنی رکوردهای دقیق.** مقدارهای مخصوص پروایدر جای‌خالی‌اند — یک include مربوط به SPF و یک کلید DKIM را فقط پروایدر ایمیل می‌تواند بدهد. ابزار هرگز آن‌ها را اختراع نمی‌کند.
3. **درست شدن را ثابت کن.** گزینه `--recheck` چک کامل را دوباره اجرا می‌کند تا exit 0 بدهد. خط نهایی `0 errors` را نقل کنید.
4. **حدش را بدان.** قبولی SPF و DKIM و DMARC لازم است، ولی برای رسیدن به inbox کافی نیست. اعتبار، تعامل و حجم ارسال هنوز تعیین می‌کنند که Gmail ایمیل را به inbox می‌برد یا اسپم. چکر احراز هویت را ثابت می‌کند؛ تحویل‌پذیری را ثابت نمی‌کند.

## چه فرقی با چکرهای ایمیل فعلی دارد

CLIها همین حالا هم هستند (`dnsaudit` با Go، `vamp-mail-audit` در PyPI با پروب DKIM برای ۱۵ سلکتور، `Invoke-SpfDkimDmarc` با PowerShell) — پس فقط چکر، یک بازسازی دوباره بود. خلأ *به شکل اسکیل* است: ایجنتی که یک کسب‌وکار را onboard می‌کند، به شواهد قطعی DNS *به‌علاوه* رکوردهای دقیق برای انتشار *به‌علاوه* حلقه recheck تا زمان انتشار نیاز دارد — به‌صورت اسکیل Claude/Cursor با تست و ابزار MCP. هیچ‌کدام از CLIها آن را ندارند.

## نصب

- **Claude Code / Claude.ai:** پوشه `skills/mail-auth/` را در پوشه اسکیل‌هایتان کپی کنید، یا زیپ داخل `dist/` را همان‌جا باز کنید.
- **Cursor:** فایل `cursor/mail-auth.mdc` را در `.cursor/rules/` کپی کنید (نگاه کنید به `cursor/README.md`).
- **MCP:** فایل `mcp-server/mail_auth_mcp_server.py` یک سرور MCP بدون وابستگی (stdio) است که یک ابزار دارد: `mail_auth` (نگاه کنید به `mcp-server/`).

## تست‌ها

```bash
python3 -m unittest discover -s tests
```

۲۲ تست چکر (پارسرهای رکورد، یک پاسخ DNS فشرده ساخته‌شده با دست، چک‌های end-to-end با DNS تقلبی از جمله حد ۱۰ لوکاپ و includeهای بازگشتی، مدیریت resolver مرده، حلقه recheck) و ۳ تست end-to-end سرور MCP — همه سبز.

## ساختار

```
skills/mail-auth/
  SKILL.md                     اسکیل: قرارداد
  scripts/mail_auth.py         چکر (فقط استانداردلایب، کلاینت DNS خودش)
  references/dns-records.md    معنی هر رکورد + حد احراز هویت در برابر inbox
  references/fix-playbook.md   انتشار مرحله‌ای DMARC + includeهای SPF پروایدرها
cursor/mail-auth.mdc           قانون Cursor (قرارداد خلاصه‌شده)
mcp-server/mail_auth_mcp_server.py  سرور MCP (یک ابزار: mail_auth)
tests/                         تست‌های چکر و MCP، transport تقلبی DNS
dist/mail-auth-skill.zip       اسکیل بسته‌بندی‌شده
```

## لایسنس

MIT — نگاه کنید به `LICENSE`.
