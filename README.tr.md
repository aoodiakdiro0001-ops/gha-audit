# gha-audit

**GitHub Actions Güvenlik Denetim Araç Seti** — çevrimdışı, sıfır bağımlılıklı workflow denetimi ve güvenli otomatik düzeltmeler.

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

## Neden?

GitHub Actions workflow'leri depo sırlarınızın yetkileriyle çalışan koddur — ve büyük kısmı kod olarak gözden geçirilmeyen YAML'dır. Bu araç setinin yakaladığı klasik hatalar:

- **Betik enjeksiyonu** — `${{ github.event.comment.body }}` (saldırgan tarafından etkilenen herhangi bir bağlam) doğrudan `run:` içine gömülür; issue veya PR açabilen herkes runner'larınızda uzaktan kod çalıştırır.
- **Sır ifşası** — workflow seviyesinde tanımlanan sır her işe ve her adıma, güvenilmeyen kod çalıştıran adımlar dahil verilir.
- **Sabitlenmemiş aksiyonlar** — `uses: actions/checkout@v4` sizin haberiniz olmadan taşınabilir; etiket (tag) bir commit değildir.
- **`pull_request_target` + PR kodunun checkout'u** — pek çok bakıcıyı yakan kombinasyon.
- **Asgari yetkili `permissions:` eksikliği** — varsayılan token işinizin ihtiyacından daha güçlüdür.

## Özellikler

- **12 kural** — enjeksiyon, sırlar, sabitleme, tetikleyiciler ve yetkiler; her biri düz bir açıklama ve somut bir düzeltmeyle.
- **4 çıktı biçimi**: `human` (renkli terminal) · `json` · `sarif` (GitHub code scanning / VS Code) · `markdown` (raporlar).
- **4 idempotent düzeltici**:
  - `envify` — `${{ github.* }}` ifadelerini `run:` gövdesinden adım seviyesindeki `env:`'ye taşır
  - `scope-secrets` — workflow/iş seviyesindeki sır env'ini okuyan tek adıma daraltır (taşı / sil / bırak)
  - `pin` — `uses: owner/repo@vN` yazımını tam commit SHA'sına çevirir, etiketi yorum olarak korur
  - `permissions` — açıkça asgari yetkili `permissions:` bloğu ekler
- **Sıfır bağımlılık** — yalnızca Python 3.8+ standart kütüphanesi, PyYAML yok, ağ gerekmez (`pin`'in SHA çözümlemesi isteğe bağlıdır; `--no-resolve` ile kapatılır).
- **Kapsam koruyucusu** — sahiplik sınırının dışındaki hedefi `--i-own-this` verilmeden taramayı reddeder.
- **CI'ya uygun çıkış kodları**: `0` temiz · `1` hata · `2` `--fail-on` seviyesinde/üzerinde bulgu · `3` kapsam tarafından reddedildi.

## Kurulum

```bash
pip install gha-audit        # veya: pipx install gha-audit
```

Kaynaktan:

```bash
git clone https://github.com/aoodiakdiro0001-ops/gha-audit
cd gha-audit && pip install .
```

Hiç kurmadan:

```bash
python3 -m gha_audit scan .
```

## Hızlı başlangıç

```bash
# depoyu tara (high seviyesinde bulgu varsa çıkış 2)
gha-audit scan .

# ne değişeceğini gör, sonra uygula
gha-audit fix .                          # dry-run farkı
gha-audit fix . --apply                  # diske yaz

# sırları okuyan adımlara daralt
gha-audit fix . --rules scope-secrets --apply

# her aksiyonu commit SHA'sına sabitle (git ls-remote kullanır; kapatmak için --no-resolve)
gha-audit fix . --rules pin --apply

# makineye uygun çıktılar
gha-audit scan . --format json  > report.json
gha-audit scan . --format sarif > report.sarif   # code scanning'e yükle
gha-audit scan . --format markdown > report.md

# CI'da temel çizgi / sapma denetimi
gha-audit scan . --format json --fail-on none > baseline.json
gha-audit verify baseline.json .

# kural kataloğunu listele
gha-audit rules
```

### Kapsam koruyucusu

Araç yalnızca yerel dosyaları okur, ancak ortak bir makinede başkasına ait klonlar bulunabilir. Her taramadan önce hedefin size ait olduğunu doğrular:

1. `--i-own-this` — komut satırında sahiplik beyanı (rapora kaydedilir);
2. hedefte veya bir üst dizindeki `.gha-audit-scope` dosyası izin verilen yol öneklerini listeleyebilir;
3. aksi halde hedef `$HOME` içinde olmalı ve bir git checkout'u ise `origin` sahibi kimlik doğrulamalı `gh` hesabıyla eşleşmelidir.

Aksi her şey → `✗ refused to scan`, çıkış kodu `3`. Bu, eşlik eden bug-bounty araçlarıyla aynı sınırdır: **sahip olmadığın hedefe tarayıcı yönlendirme.**

## Kurallar

| Kimlik | Önem | Yakaladığı şey |
|---|---|---|
| `gha-script-injection-run` | critical/high | Saldırganca etkilenen bağlam `run:` içine gömülür |
| `gha-secret-in-workflow-env` | high | Sır tüm işlere ve adımlara açık |
| `gha-secret-in-job-env` | medium | Sır bir işin tüm adımlarına açık |
| `gha-unpinned-action-floating` | high | Aksiyon `main` / `master` / `latest`'e sabitlenmiş |
| `gha-pr-target-checkout-head` | critical | `pull_request_target` güvenilmeyen PR kodunu checkout eder |
| `gha-pr-target-checkout-credentials` | high | `pull_request_target` checkout'u kimlik bilgilerini korur |
| `gha-self-hosted-on-untrusted-trigger` | high | Kendi kendine çalışan runner güvenilmeyen tetikleyici çalıştırır |
| `gha-hardcoded-credential` | critical | Workflow içinde sabitlenmiş kimlik bilgisi |
| `gha-pull-request-fork-with-secrets` | medium | Güvenilmeyen tetikleyici + ayrıcalıklı checkout |
| `gha-unpinned-action` | medium | Aksiyon tam commit SHA'sına sabitlenmemiş |
| `gha-missing-permissions` | low | Açık `permissions:` bloğu yok |
| `gha-credentials-persisted` | low | Checkout token'ı çalışma alanında saklar |

Tüm açıklamalar için `gha-audit rules`, dokümana hazır çıktı için `gha-audit rules --format markdown`.

## Önem ve çıkış kodları

| Kod | Anlamı |
|---|---|
| `0` | Temiz veya düzeltmeler uygulandı |
| `1` / | İç / kullanım hatası |
| `2` | `--fail-on` (varsayılan `high`) seviyesinde/üzerinde bulgu |
| `3` | Reddedildi: hedef sahiplik sınırının dışında |

İfade sınıflandırması: **saldırganca kontrol edilen içerik** taşıyan bağlamlar (issue/yorum metinleri, başlıklar, `head_ref`, commit mesajları) = `critical`; `inputs` ve referanslar = `high`; güvenli beyaz liste bağlamları (`github.repository`, `github.sha`, `github.actor`, …) asla işaretlenmez.

## Geliştirme

```bash
python3 -m unittest discover -s tests    # 22 test, yalnızca standart kütüphane
```

`.github/workflows/ci.yml` içindeki CI workflow'u test paketini çalıştırır ve bu depoyu `gha-audit` ile kendisi denetler.

## Lisans

MIT © 2026 Baran Avisat — bkz. [LICENSE](LICENSE).

## Destek

- Hata ve özellik istekleri: [GitHub Issues](https://github.com/aoodiakdiro0001-ops/gha-audit/issues)
- E-posta: baranavisat@gmail.com
- Bkz. [SUPPORT.md](SUPPORT.md)

---
© 2026 Baran Avisat. Ücretsiz ve açık kaynak (MIT).
