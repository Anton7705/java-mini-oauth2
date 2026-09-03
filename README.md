# Mini-OAuth2: сервер авторизации с поддержкой RBAC

Выдача access/refresh токенов,
ротация refresh, отзыв, интроспекция и защита ресурсов по ролям и скоупам.

Проект состоит из двух приложений в одном Maven-модуле:

| Приложение | Класс | Порт | Назначение |
|---|---|---|---|
| Auth-сервер | `ru.yandex.practicum.oauth0.auth.AuthApp` | 8080 | выдаёт, обновляет, отзывает и проверяет токены |
| Ресурсный сервер | `ru.yandex.practicum.oauth0.rs.ResourceApp` | 9090 | защищённые бизнес-эндпоинты `/api/payments` |

---

## Быстрый старт

Требуется JDK 17+ и Maven 3.9+.

```bash
mvn clean package

# терминал 1: сервер авторизации
java -jar target/oauth-zero-1.0-SNAPSHOT-auth.jar

# терминал 2: ресурсный сервер
java -jar target/oauth-zero-1.0-SNAPSHOT-rs.jar
```

Через плагин Spring Boot (нужно явно указать main-class, их в проекте два):

```bash
mvn spring-boot:run -Dspring-boot.run.main-class=ru.yandex.practicum.oauth0.auth.AuthApp
mvn spring-boot:run -Dspring-boot.run.main-class=ru.yandex.practicum.oauth0.rs.ResourceApp
```

Тесты:

```bash
mvn test
```

По умолчанию используется файловая база H2 в `./data/mini-oauth2.mv.db`, поэтому состояние
переживает перезапуск без установки СУБД. Для PostgreSQL:

```bash
java -jar target/oauth-zero-1.0-SNAPSHOT-auth.jar --spring.profiles.active=auth,postgres
```

Параметры подключения лежат в `src/main/resources/application-postgres.properties`.

---

## Демо-данные

Создаются автоматически при первом старте, если таблицы пусты (`auth.seed-demo-data=true`).
Пароли и секреты хранятся только в виде BCrypt-хешей (cost 12).

**Роли и скоупы**

| Роль | Скоупы |
|---|---|
| `viewer` | `payments:read` |
| `editor` | `payments:read`, `payments:write` |
| `admin` | `payments:read`, `payments:write`, `payments:admin` |

**Пользователи**

| Логин | Пароль | Роли |
|---|---|---|
| `alice` | `pass` | viewer |
| `bob` | `pass` | editor |
| `root` | `root-pass` | admin |

**Клиенты**

| client_id | secret | Гранты | Скоупы |
|---|---|---|---|
| `cli-001` | `secret` | password, refresh_token | payments:read, payments:write, payments:admin |
| `svc-001` | `svc-secret` | client_credentials | payments:read |

---

## Формат токенов

Компактный токен из трёх частей: `base64url(header).base64url(payload).base64url(HMAC-SHA256)`.
Подпись считается по строке `header.payload`, при проверке подписывается ровно та строка,
которая пришла от клиента, поэтому побайтовое совпадение сериализации не требуется.
В заголовке проверяется `alg`, значение `none` и любая подмена алгоритма отклоняются.

**Access token** (`typ: "AT"`), TTL 900 секунд:

```json
{
  "typ": "AT",
  "iss": "mini-auth",
  "aud": "payments-api",
  "sub": "u-100",
  "client_id": "cli-001",
  "scopes": ["payments:read"],
  "roles": ["viewer"],
  "iat": 1736186400,
  "exp": 1736187300,
  "jti": "a-uuid"
}
```

**Refresh token** — выбран **вариант B** из задания: подписанный JSON с `typ: "RT"` и полем
`refresh_id`, которому соответствует строка в таблице `refresh_index`. TTL 14 дней.
Его `aud` равен `mini-auth`, то есть самому серверу авторизации, поэтому предъявить
refresh на ресурсном сервере невозможно даже при совпадении подписи.

Подпись симметричная (HS256), поэтому ресурсный сервер использует тот же секрет:
`rs.secret` по умолчанию ссылается на `auth.secret`.

---

## Эндпоинты сервера авторизации (8080)

| Метод | Путь | Описание |
|---|---|---|
| POST | `/token` | гранты `password` и `client_credentials` |
| POST | `/token/refresh` | грант `refresh_token`, всегда с ротацией |
| POST | `/revoke` | отзыв access (по `jti`) или refresh (по `refresh_id`) |
| POST | `/introspect` | проверка активности токена |
| GET | `/config` | публичные параметры сервера, без секретов |

### Получение токена по паролю

```bash
curl -s -X POST http://localhost:8080/token \
 -H 'Content-Type: application/json' \
 -d '{
  "grant_type":"password",
  "username":"alice",
  "password":"pass",
  "client_id":"cli-001",
  "client_secret":"secret",
  "scopes":["payments:read"]
 }'
```

Ответ:

```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "payments:read"
}
```

### Машинный сценарий

```bash
curl -s -X POST http://localhost:8080/token \
 -H 'Content-Type: application/json' \
 -d '{
  "grant_type":"client_credentials",
  "client_id":"svc-001",
  "client_secret":"svc-secret"
 }'
```

Refresh-токен в этом сценарии не выдаётся.

### Обновление токена

```bash
curl -s -X POST http://localhost:8080/token/refresh \
 -H 'Content-Type: application/json' \
 -d '{
  "grant_type":"refresh_token",
  "refresh_token":"<rt>",
  "client_id":"cli-001",
  "client_secret":"secret"
 }'
```

### Отзыв

```bash
curl -s -X POST http://localhost:8080/revoke \
 -H 'Content-Type: application/json' \
 -d '{"token":"<access_or_refresh>","token_type_hint":"access_token"}'
```

### Интроспекция

```bash
curl -s -X POST http://localhost:8080/introspect \
 -H 'Content-Type: application/json' \
 -d '{"token":"<access>"}'
```

```json
{
  "active": true,
  "typ": "AT",
  "iss": "mini-auth",
  "aud": "payments-api",
  "sub": "u-100",
  "client_id": "cli-001",
  "scopes": ["payments:read"],
  "roles": ["viewer"],
  "iat": 1736186400,
  "exp": 1736187300,
  "jti": "a-uuid"
}
```

---

## Эндпоинты ресурсного сервера (9090)

| Метод | Путь | Требования |
|---|---|---|
| GET | `/api/payments` | скоуп `payments:read` |
| POST | `/api/payments` | скоуп `payments:write` |
| DELETE | `/api/payments/{id}` | скоуп `payments:write` **и** роль `admin` |

```bash
curl -s http://localhost:9090/api/payments \
 -H "Authorization: Bearer <access_token>"

curl -s -X POST http://localhost:9090/api/payments \
 -H "Authorization: Bearer <access_token>" \
 -H 'Content-Type: application/json' \
 -d '{"amount_minor": 12500, "currency": "RUB", "description": "invoice"}'
```

Проверка запроса идёт двумя слоями, чтобы бизнес-код не занимался авторизацией:

1. `BearerTokenFilter` (`OncePerRequestFilter`) — извлекает заголовок, проверяет подпись,
   `typ`, `iss`, `aud`, интервал `[iat - skew, exp + skew]` и отзыв через интроспекцию,
   затем кладёт `TokenPrincipal` в атрибут запроса.
2. `AuthorizationInterceptor` (`HandlerInterceptor`) — читает аннотацию `@RequiresAuthority`
   на методе контроллера и сверяет скоупы (все нужные) и роли (хотя бы одна).

Отзыв применяется мгновенно: ресурсный сервер вызывает `/introspect` на сервере авторизации.
Отключить это можно параметром `rs.introspection-enabled=false`, тогда сервер работает
полностью автономно, но отозванный access перестанет действовать только по истечении TTL.

---

## Коды ошибок

| Код | Когда |
|---|---|
| 400 | некорректный JSON, отсутствующие параметры, неизвестный `grant_type` |
| 401 | неверные креды пользователя или клиента; неверная подпись; истёкший или ещё не начавший действовать токен; отозванный или неизвестный refresh |
| 403 | запрошенные скоупы недоступны по ролям или клиенту; грант не разрешён клиенту; заблокированный пользователь; на RS — нехватка скоупа или роли |
| 409 | повторное использование refresh-токена после ротации |
| 429 | превышен лимит обращений к `/token` (опционально, `auth.rate-limit.enabled=true`) |
| 503 | сервер авторизации недоступен для интроспекции |
| 500 | внутренняя ошибка; логируется со стеком, клиенту секреты не отдаются |

Тело ошибки всегда в формате `{"error": "...", "error_description": "..."}`.

---

## Конфигурация

Основные параметры в `src/main/resources/application.properties`, порт и файл лога —
в `application-auth.properties` и `application-rs.properties`. Переопределить без пересборки
можно через внешние файлы `config/auth.properties` и `config/rs.properties`, они подключаются
автоматически, если существуют.

| Параметр | По умолчанию | Значение |
|---|---|---|
| `auth.secret` | dev-значение | секрет HMAC-SHA256, обязательно заменить в проде |
| `auth.issuer` | `mini-auth` | значение `iss` |
| `auth.audience` | `payments-api` | аудитория по умолчанию |
| `auth.access-ttl-sec` | 900 | TTL access-токена |
| `auth.refresh-ttl-days` | 14 | TTL refresh-токена |
| `auth.clock-skew-sec` | 60 | допуск часов при проверке `iat`/`exp` |
| `auth.seed-demo-data` | true | создание демо-данных при пустых таблицах |
| `auth.rate-limit.enabled` | false | лимит на `/token` |
| `rs.secret` | `${auth.secret}` | общий секрет проверки подписи |
| `rs.audience` | `payments-api` | ожидаемое `aud` |
| `rs.auth-server-url` | `http://localhost:8080` | адрес для интроспекции |
| `rs.introspection-enabled` | true | проверять отзыв на сервере авторизации |

Логи пишутся в консоль и в `logs/auth-server.log` / `logs/resource-server.log`.
Секреты, пароли и тело токенов в логи не попадают.

---

## Структура БД

DDL лежит в `src/main/resources/init.sql` и применяется при старте
(`spring.sql.init.mode=always`, все выражения идемпотентны). Синтаксис совместим
с H2 2.x и PostgreSQL 12+.

| Таблица | Назначение |
|---|---|
| `users`, `user_roles` | пользователи и назначенные им роли |
| `roles`, `role_scopes` | роли и входящие в них скоупы (RBAC) |
| `clients`, `client_grants`, `client_scopes` | клиентские приложения, их гранты и скоупы |
| `refresh_index` | журнал refresh-токенов: `rotated`, `revoked`, `replaced_by` |
| `revocation` | журнал отзывов по `jti` и `refresh_id` |
| `audit_events` | аудит и метрики: выдачи, ошибки, отзывы |

Записи об отзыве с истёкшим `expires_at` удаляются при следующем вызове `/revoke`:
после истечения самого токена хранить их незачем.

---

## Структура проекта

```
common/     крипто, кодеки, время, формат токенов — без Spring и без HTTP
  codec/    Base64Url
  crypto/   HmacSigner, PasswordHasher
  time/     TimeProvider (подменяемые часы для тестов)
  token/    TokenClaims, TokenCodec, TokenValidator
auth/       сервер авторизации
  domain/   JPA-сущности
  repo/     репозитории Spring Data
  service/  TokenService, ScopeResolver, AuditService, DemoDataSeeder
  web/      контроллер, обработчик ошибок, rate-limit
rs/         ресурсный сервер
  security/ BearerTokenFilter, AuthorizationInterceptor, @RequiresAuthority
  web/      PaymentsController
```

Крипто, работа со временем и кодеки вынесены в отдельный модуль и не зависят
ни от эндпоинтов, ни от репозиториев.

---

## Безопасность: что реализовано

- Пароли и секреты клиентов — только BCrypt-хеши, cost 12.
- Сравнение подписей константное по времени (`MessageDigest.isEqual`).
- Проверяется `alg` в заголовке: `none` и подмена алгоритма отклоняются.
- Refresh адресован серверу авторизации (`aud=mini-auth`) и не принимается на RS.
- Ротация refresh: старый токен помечается `rotated`, повторное использование даёт 409
  и отзывает всю цепочку выданных из него токенов.
- Отзыв по `jti` защищает от повторного применения украденного access-токена.
- Аудит пишется в БД и в лог без секретов.

---

## Тест-набор

| Класс | Что покрывает |
|---|---|
| `support/TokenCodecTest` | подпись и разбор, чужой секрет, подмена payload, `alg: none`, границы clock skew, BCrypt |
| `auth/TokenIssueFlowTest` | password и client_credentials, неверный пароль, неверный секрет клиента, неизвестный грант, битый JSON, ограничение скоупов ролями, запрет неразрешённого гранта, `/config` |
| `auth/RefreshRevocationTest` | ротация refresh, повтор после ротации (409), чужой клиент, чужая подпись, отзыв access и refresh, интроспекция активного, истёкшего и подделанного токена, clock skew |
| `rs/ResourceAccessTest` | 401 без токена, чужая подпись, истёкший токен, чужая аудитория, refresh вместо access, отозванный токен, 503 при недоступном auth-сервере, 403 без скоупа, 403 без роли, успешные чтение, запись и удаление |
| `e2e/EndToEndFlowTest` | оба приложения на реальных портах: логин, доступ к API, ротация, отзыв и мгновенный 401 |
| `e2e/RestartPersistenceTest` | перезапуск сервера авторизации: refresh продолжает работать, отзыв остаётся в силе |

