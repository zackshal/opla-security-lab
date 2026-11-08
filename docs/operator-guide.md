# Руководство оператора

Последовательность: `opla lab create`, сохранить напечатанный ID, `lab select`,
`lab ready`, `lab activate`, сценарий, `monitoring stop`, `lab stop`, затем
только при необходимости `lab delete ID --confirm-lab ID`.

Операции stop/delete не выбирают latest неявно. Live-команды выполняются только
на явно допущенном dedicated host.
