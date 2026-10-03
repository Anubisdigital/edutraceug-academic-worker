# edutraceug-academic-worker

Academic structure API for Edutrace — subjects, A-Level combinations, and per-student subject assignment.

## Base URL

https://edutraceug-academic-worker.anubisdigital114-9df.workers.dev

## Secrets

- `ACCOUNT-SERVICE-FIREBASE` — Firebase service-account JSON

## Routes

### Subjects

- `GET    /schools/:sid/subjects`
- `POST   /schools/:sid/subjects`
- `PATCH  /schools/:sid/subjects/:subjectId`
- `DELETE /schools/:sid/subjects/:subjectId`
- `POST   /schools/:sid/subjects/seed-defaults`

### Combinations

- `GET    /schools/:sid/combinations`
- `POST   /schools/:sid/combinations`
- `PATCH  /schools/:sid/combinations/:comboId`
- `DELETE /schools/:sid/combinations/:comboId`
- `POST   /schools/:sid/combinations/seed-defaults`

### Students

- `GET    /schools/:sid/students`
- `GET    /schools/:sid/students/:rosterId`
- `PUT    /schools/:sid/students/:rosterId/subjects`
- `PUT    /schools/:sid/students/:rosterId/combination`
- `DELETE /schools/:sid/students/:rosterId/combination`
- `POST   /schools/:sid/students/bulk`

### Excel

- `GET  /schools/:sid/subjects/template`
- `POST /schools/:sid/subjects/upload`
- `POST /schools/:sid/subjects/upload/confirm`

### O-Level bulk

- `POST /schools/:sid/olevel/apply`
- `GET  /schools/:sid/olevel/coverage`

## Auth

Every route except `/health` requires a Firebase ID token in `Authorization: Bearer <token>`.
Roles allowed: `schoolAdmin` (write), `teacher` (read).

## Deploy

```bash
npx wrangler deploy
