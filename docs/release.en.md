# OPLA publication and document builds

[Русский](release.md) · **English**

Revision: 25 October 2026. This document concerns the **public GitHub** repository `zackshal/opla-security-lab`. At preparation time, `main` pointed to `bca6d66`. Branch `docs/opla-student-materials-20261025` is a documentation migration branch and has not been merged into `main` pending Pull Request checks.

## 1 History and publication boundary

The public GitHub and working GitLab repositories have different histories. I transfer selected documentation files from commit `66a003a` without merging or cherry-picking its ancestors. The working repository's history once contained a private `docs/teacher-key.md`. **Neither that file, its historical commits nor an answer-key PDF may enter public GitHub.** `.gitignore` does not erase historical objects. Audit public history and staged changes before pushing.

Do not publish `docs/teacher-key.md`, `OPLA_Teacher_Key.pdf`, `.env`, private keys, qcow2 images, databases, passwords, raw personal logs or unreviewed dumps. PDFs and temporary figures are generated under ignored `release-artifacts/`.

## 2 Public PDFs

The public exporter generates **only** `OPLA_Lab_Manual.pdf`, `OPLA_Engineering_Report.pdf` and `OPLA_Portfolio.pdf`. Teacher-key export is deliberately unsupported here; a separate private source tree is required.

```bash
python3 -m venv .venv-docs
.venv-docs/bin/python -m pip install -r tools/requirements-docs.txt
make check-docs
make docs
ls -lh release-artifacts/public/*.pdf
```

Layout settings: A4, 30/15/20/20 mm margins, 12 pt body text and 1.5 line spacing. Code and tables use smaller type. Visually inspect diagrams, pagination and tables after each build: a successful export does not guarantee perfect layout. Markdown and SVG are source files; PDFs are not committed.

## 3 Verification and Pull Request

```bash
make check
make check-docs
git diff --cached --check
git status --short
git log -1 --oneline
```

Review staged file names and scan for private material before committing. Publish the documentation as a dedicated commit and Pull Request to `main`. Do not force-push or rewrite prior authorship. Preserve existing GitHub Actions and lab Make targets.

## 4 Evidence status

A working integration copy previously passed 92 Python tests (one skipped) and the portable C packet harness. That is not proof that the same checks passed on the public branch or that kernel verification, KVM, a live Zabbix API or a clean installation were completed. Historical evidence and outstanding checks are separated in the [run protocol](run-protocol.en.md) and [acceptance matrix](acceptance.en.md).

No release tag is created by this migration. Versioning requires checks against the actual published commit, visual PDF review and a final private-data audit.
