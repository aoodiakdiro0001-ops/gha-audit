# gha-audit

**مجموعة أدوات تدقيق أمان GitHub Actions** — فحص سيرورات العمل (Workflows) دون اتصال وبلا أي تبعيات، مع إصلاحات آمنة تلقائية.

[English](README.md) · [العربية](README.ar.md) · [Türkçe](README.tr.md)

```
$ gha-audit scan .
gha-audit 1.0.0 — GitHub Actions Security Audit Toolkit
target : .
files  : 9 workflow file(s)

██████ CRITICAL (2)
  ● .github/workflows/ci.yml:41
    Untrusted GitHub context interpolated into run:
    Expression `github.event.comment.body` reaches the shell and carries attacker-influenced data

summary: 2 critical, 5 high, 3 medium, 1 low
$ echo $?
2
```

## لماذا؟

سيرورات العمل في GitHub Actions هو كود يعمل بصلاحيات أسرار مستودعك — ومعظمه YAML لا يُراجع كما يُراجع الكود. الأخطاء الكلاسي التي يرصدها هذا الصندوق:

- **حقن في سطر الأوامر** — مثل `${{ github.event.comment.body }}` (أي سياق يتأثر بالمهاجم) يُحقن مباشرة داخل `run:`، فيحصل أي شخص يستطيع فتح issue أو pull request على تنفيذ كود عن بُعد على عدّائاتك.
- **تعرّض الأسرار** — سر معلن على مستوى الـworkflow يُسلَّم لكل مهمة وكل خطوة، بما فيها الخطوات التي تنفّذ كوداً غير موثوق.
- **إجراءات غير مثبَّتة** — `uses: actions/checkout@v4` قد يُنقل تحتك؛ الوسم (tag) ليس التزاماً بـcommit.
- **`pull_request_target` مع كشف كود الـPR** — التركيبة التي أحرقت كثيراً من الصيانة.
- **غياب `permissions:` بأقل صلاحية** — الرمز الافتراضي أقوى من حاجة عملك.

## المزايا

- **12 قاعدة** تغطي الحقن والأسرار والتثبيت والمُشغّلات والصلاحيات — لكل منها شرح بلغة بسيطة وإصلاح محدّد.
- **4 صيغ إخراج**: `human` (طرفية ملوّنة) · `json` · `sarif` (GitHub code scanning / VS Code) · `markdown` (تقارير).
- **4 مُصلِّحات آمنة** لا تُعيد كتابة الملف إلا عند الحاجة وهي idempotent:
  - `envify` — ينقل تعبيرات `${{ github.* }}` من داخل `run:` إلى `env:` مستوى الخطوة
  - `scope-secrets` — يُصغّر بيئة أسرار الـworkflow/المهمة إلى الخطوة التي تقرأه فعلاً (نقل / حذف / إبقاء)
  - `pin` — يعيد كتابة `uses: owner/repo@vN` إلى SHA اكتمل مع إبقاء الوسم كتعليق
  - `permissions` — يُدرج كتلة `permissions:` بأقل صلاحية عند غيابها
- **صفر تبعيات** — Python 3.8+ والمكتبة القياسية فقط، بلا PyYAML وبلا شبكة مطلوبة (إلا حلّ SHA في `pin` وهو اختياري عبر `--no-resolve`).
- **حارس النطاق** — يرفض فحص هدف خارج حدود ملكيتك ما لم تمرّر `--i-own-this`.
- **أكواد خروج مناسبة لـCI**: `0` نظيف · `1` خطأ · `2` نتائج عند/فوق `--fail-on` · `3` رفض من حارس النطاق.

## التثبيت

```bash
pip install gha-audit        # أو: pipx install gha-audit
```

من المصدر:

```bash
git clone https://github.com/aoodiakdiro0001-ops/gha-audit
cd gha-audit && pip install .
```

بدون تثبيت إطلاقاً:

```bash
python3 -m gha_audit scan .
```

## البدء السريع

```bash
# فحص مستودع (خروج 2 عند وجود نتيجة على الأقل بمستوى high)
gha-audit scan .

# معاينة ما سيتغير ثم تطبيقه
gha-audit fix .                          # فرق تجريبي dry-run
gha-audit fix . --apply                  # الكتابة على القرص

# تضييق الأسرار على الخطوات التي تقرأها
gha-audit fix . --rules scope-secrets --apply

# تثبيت كل إجراء على SHA اكتمل (يستخدم git ls-remote؛ و--no-resolve للتعطيل)
gha-audit fix . --rules pin --apply

# مخرجات آلية
gha-audit scan . --format json  > report.json
gha-audit scan . --format sarif > report.sarif   # رفع إلى code scanning
gha-audit scan . --format markdown > report.md

# خط الأساس وكشف الانحراف في CI
gha-audit scan . --format json --fail-on none > baseline.json
gha-audit verify baseline.json .

# عرض كتالوج القواعد
gha-audit rules
```

### حارس النطاق

الأداة تقرأ ملفات محلية فقط، لكن الجهاز المشترك قد يحوي مستودعات تخصّ غيرك. قبل أي فحص تتحقق من أن الهدف يملكه أنت:

1. `--i-own-this` — تُعلن الملكية في سطر الأوامر (يُسجَّل في التقرير)؛
2. ملف `.gha-audit-scope` في الهدف أو أحد أدفاته العليا قد يسرد بادئات مسارات مسموحة؛
3. وإلا يجب أن يكون الهدف داخل `$HOME` وأن يكون، إن كان checkout في git، مالك `origin` مطابقاً لحساب `gh` المصادَق عليه.

وأي شيء آخر → `✗ refused to scan` وكود خروج `3`. هذا يطابق الحدّ نفسه المستخدم في أدوات Bug Bounty المصاحبة: **لا توجّه فاحصاً إلى هدف لا تملكه.**

## القواعد

| المعرّف | الخطورة | ما يرصده |
|---|---|---|
| `gha-script-injection-run` | critical/high | سياق يتأثر بالمهاجم يُحقن داخل `run:` |
| `gha-secret-in-workflow-env` | high | سر مكشوف لكل المهام والخطوات |
| `gha-secret-in-job-env` | medium | سر مكشوف لكل خطوات مهمة |
| `gha-unpinned-action-floating` | high | إجراء مثبَّت على `main` / `master` / `latest` |
| `gha-pr-target-checkout-head` | critical | `pull_request_target` يكشف كود PR غير موثوق |
| `gha-pr-target-checkout-credentials` | high | كشف PR في `pull_request_target` يحتفظ بالبيانات |
| `gha-self-hosted-on-untrusted-trigger` | high | عدّاد ذاتي التنفيذ يشغّل مُشغّلاً غير موثوق |
| `gha-hardcoded-credential` | critical | بيانات اعتماد مكتوبة داخل الملف |
| `gha-pull-request-fork-with-secrets` | medium | مُشغّل غير موثوق مع كشف مُصرَّح |
| `gha-unpinned-action` | medium | إجراء غير مثبَّت على SHA اكتمل |
| `gha-missing-permissions` | low | غياب كتلة `permissions:` صريحة |
| `gha-credentials-persisted` | low | الكشف يحتفظ بالرمز داخل مساحة العمل |

شغّل `gha-audit rules` للوصف الكامل، أو `gha-audit rules --format markdown` لمخرجات جاهزة للتوثيق.

## الخطورة وأكواد الخروج

| الكود | المعنى |
|---|---|
| `0` | نظيف، أو طُبّقت الإصلاحات |
| `1` | خطأ داخلي / خطأ استخدام |
| `2` | نتائج عند/فوق `--fail-on` (الافتراضي `high`) |
| `3` | رفض: الهدف خارج حدود الملكية |

تصنيف التعبيرات: السياقات التي تحمل **محتوى يتحكم به المهاجم** (نص التعليقات والissues والعناوين و`head_ref` ورسائل الـcommit) = `critical`؛ و`inputs` والمراجع = `high`؛ والسياقات الآمنة الموسومة (`github.repository` و`github.sha` و`github.actor` …) لا تُعلَّم أبداً.

## التطوير

```bash
python3 -m unittest discover -s tests    # 22 اختباراً، بيئة قياسية فقط
```

سيرور العمل في `.github/workflows/ci.yml` يشغّل الاختبارات ويدقق هذا المستودع بنفسه عبر `gha-audit`.

## الترخيص

MIT © 2026 Baran Avisat — انظر [LICENSE](LICENSE).

## الدعم

- البلاغات وطلبات المزايا: [GitHub Issues](https://github.com/aoodiakdiro0001-ops/gha-audit/issues)
- البريد: baranavisat@gmail.com
- انظر [SUPPORT.md](SUPPORT.md)

---
© 2026 Baran Avisat. مجاني ومفتوح المصدر (MIT).
