# Материалы аудита MoonMCP

База: `0aa2153b51b3ab1ce95dc9abcada17ff52322c38`, 2026-10-14. Основной [отчёт](../../AGENT_TOOLING_RESEARCH.md).

Эти скрипты диагностические: они фиксируют поведение проверенной версии, а не задают правильный результат для будущего кода. После исправлений JSON должен измениться. Платная модель и внешние HTTP-цели не используются.

## Воспроизведение

Из корня checkout с установленным MoonMCP и dev-зависимостями:

```bash
MOONMCP_PROFILE=full MOONMCP_EXPOSE_TOOLS= MOONMCP_HIDE_TOOLS= PYTHONPATH=. \
  python docs/research/2026-10-14/measure_search.py > /tmp/moonmcp-search.json
PYTHONPATH=. python docs/research/2026-10-14/reproduce.py > /tmp/moonmcp-reproductions.json
```

`PYTHONPATH=.` гарантирует проверку текущего checkout при наличии editable-install другого клона. `reproduce.py` использует temporary directories, собственный AppContext/SQLite и отдельный stdio-процесс. Он не вызывает сетевые сценарии `graphql_check`/`analyze_js` из bench. Для сценария continuation `Path.home()` временно заменён на scratch-каталог; настоящий домашний каталог не изменяется. Таймаут отдельного MCP-запроса — 10 секунд. Требуется разрешённый запуск subprocess; в данной среде sandbox мешал stdio-проверке, успешный прогон выполнялся вне него.

Среда измерения: Python 3.12, MCP SDK 1.30.0, Pydantic 2.14.1, pytest 9.1.1, Ruff 0.17.0, mypy 2.4.0. Это зафиксированная среда аудита, не рекомендация поднять нижние границы зависимостей проекта.

## Файлы

- `reproductions.json`: фактические результаты проблем памяти, изменения чужой baseline-задачи, ложной оценки бюджета и MCP-флага ошибки.
- `search-experiment.json`: 12 диагностических запросов до/после локальной подмены токенизатора. Подмена действует только внутри скрипта. Это не held-out оценка качества поиска.
- `inventory-summary.json`: размер пакета и распределение по каталогам; строки включают данные/комментарии.
- `sources.json`: URL прочитанных материалов, дата, размер и SHA-256 сохранённых снимков, а также неудачные попытки получения. Полные сторонние README/HTML не включены в репозиторий; локальные снимки сохранены в рабочем каталоге исследования. Hash фиксирует прочитанную версию, но не гарантирует, что mutable URL вернёт её в будущем.

Размер схем — длина UTF-8 JSON массива `name/description/inputSchema` с `ensure_ascii=False`. Метрика не включает весь MCP wire envelope и не является числом токенов модели. Counts профилей вычислены текущим `catalog.select_profile` по полному registry; это не измерение каждого host/client.

## Выполненные проверки

```bash
ruff check .
mypy moonmcp
PYTHONPATH=. pytest -q tests/test_tool_search.py tests/test_catalog.py \
  tests/test_profiles_cli.py tests/test_runs.py tests/test_confirm_cvss.py tests/test_metrics.py
PYTHONPATH=. pytest -q tests/test_baseline_scenarios.py -x
```

Первые три проверки успешны: Ruff без замечаний, mypy без ошибок в 142 файлах с действующими исключениями проекта, 46 tests passed. Тесты confirm используют локальный HTTP fixture: первоначальный sandbox-прогон дал 44 passed и 2 ошибки запрета сокетов; разрешённый локальный прогон дал 46 passed.

Последняя команда: `1 failed in 0.34s`. Причина:

```text
tests/test_baseline_scenarios.py::test_all_scenarios_run_and_report
moonmcp/bench.py:149: store_dir.mkdir(exist_ok=True)
OSError: [Errno 30] Read-only file system: '/home/agent/.moonmcp_baseline_runs'
```

Успех mypy не покрывает игнорируемые через конфигурацию ошибки в server.py и части I/O-модулей. Полный pytest, coverage gate и удалённый CI в рамках этого аудита не подтверждены.
