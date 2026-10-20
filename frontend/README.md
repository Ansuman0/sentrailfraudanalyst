# Sentrail frontend (web service)

React 18 + TypeScript (Vite). Talks to the backend only through `src/services/` (`http.ts` is the sole fetch wrapper and the only
caller of `/auth/refresh`). It never enforces permissions: the server does.

```
frontend/
  src/pages/ components/ hooks/ services/ types/ utils/ test/
  Dockerfile, nginx.conf.template   production image: static build behind unprivileged nginx
```

```bash
npm install && cp .env.example .env.local
npm run dev        # http://localhost:5173
npm test && npm run typecheck && npm run build
```

`VITE_API_BASE_URL` (public API URL) is baked in at build time.
