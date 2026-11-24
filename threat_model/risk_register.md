# Реєстр ризиків OWASP Juice Shop (варіант 26)

Оцінювання за CVSS 3.1 (базові метрики). Рівні: ≥9,0 Critical; 7,0–8,9 High;
4,0–6,9 Medium; 0,1–3,9 Low. Рішення: **Mitigate** (усунути), **Accept** (прийняти
залишковий), **Transfer**. Профіль аудиту — обхід контролю доступу.

| ID | Загроза (STRIDE) | CVSS 3.1 вектор | Бал | Рівень | CWE | CVE | Рішення |
|----|------------------|-----------------|-----|--------|-----|-----|---------|
| R-01 | IDOR: перегляд чужого кошика `GET /rest/basket/:id` (I,E) | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 6.5 | Medium | CWE-639 | — | Mitigate |
| R-02 | Підробка товару `PUT /api/Products/:id` без авторизації (T,E) | AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N | 6.5 | Medium | CWE-285 | — | Mitigate |
| R-03 | Обхід rate-limit через `X-Forwarded-For` + `trust proxy` (S,D,E) | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L | 7.3 | High | CWE-290, CWE-307 | CVE-2023-43655 | Mitigate |
| R-04 | Перелік усіх користувачів `GET /api/Users` (I,E) | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 6.5 | Medium | CWE-284, CWE-200 | — | Mitigate |
| R-05 | Підробка/редагування чужого відгуку `POST,PUT /…/reviews` (T,R,E) | AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N | 6.5 | Medium | CWE-639, CWE-863 | — | Mitigate |
| R-06 | Додавання товару в чужий кошик `POST /api/BasketItems` (T,E) | AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N | 4.3 | Medium | CWE-639 | — | Mitigate |
| R-07 | Підробка фідбеку від імені іншого `POST /api/Feedbacks` (S,R,E) | AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N | 4.3 | Medium | CWE-639 | — | Mitigate |
| R-08 | Доступ до адмін-UI `/#/administration` (лише клієнтський guard) (E) | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 6.5 | Medium | CWE-602, CWE-284 | — | Mitigate |
| R-09 | Вразливі залежності `jsonwebtoken@0.4.0`, `express-jwt@0.1.3` (S,E) | AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N | 7.4 | High | CWE-1035, CWE-1104 | CVE-2015-9235, CVE-2020-15084 | Mitigate |
| R-10 | Реєстрація адміна через роль у тілі `POST /api/Users` (E) | AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N | 7.5 | High | CWE-269 | — | Mitigate |

## Коментарі до оцінювання

- **PR:L** для R-01, R-02, R-04, R-05, R-06, R-07, R-08: експлуатація потребує
  будь-якого дійсного акаунта покупця (реєстрація вільна) — низький привілей.
- **PR:N** для R-03, R-10: атака можлива без автентифікації (скидання пароля /
  реєстрація).
- **R-03** оцінено з частковим впливом на C/I/A, бо обхід ліміту уможливлює брутфорс
  (компрометація облікового запису) та флуд reset-password. Відповідає відомому CVE
  rate-limiting bypass у Juice Shop.
- **R-09** — `AC:H`, бо практична експлуатація застарілих JWT-бібліотек залежить від
  конфігурації; проте наявність застарілих версій підтверджено SCA (npm audit).
- Усі ризики профілю — **Mitigate**; виправлення та регресійні тести наведено в
  Розділі 4. Залишкові ризики (напр., відсутність повноцінного аудит-журналу
  авторизації) винесено до Розділу 5 як план подальшого усунення.
