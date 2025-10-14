## SIEM Dashboard (Next.js) - Frontend

This is the frontend dashboard for the SIEM project, built with Next.js, React, Tailwind CSS, and Prisma.

### Prerequisites
- Node.js 18+ and npm
- PostgreSQL database (connection URL)

### Environment variables
Create a `.env` file inside `dashboard/` with the following variables:

```
# Required by Prisma
DATABASE_URL="postgresql://USER:PASSWORD@HOST:PORT/DBNAME?schema=public"

# JWT secret for auth (change in production)
JWT_SECRET="your-strong-secret"
```

Notes:
- `DATABASE_URL` is used by Prisma and the app to connect to PostgreSQL.
- `JWT_SECRET` defaults to `supersecretkey` if not set, but you should override it.

### Install dependencies
From the `dashboard/` directory:

```bash
npm install
```

### Generate Prisma Client (if schema changed)
```bash
npx prisma generate
```

The generator outputs the client into `lib/generated/prisma` (see `prisma/schema.prisma`).

### Development
Runs Next.js in dev mode on port 3002 (configured in `package.json`).

```bash
npm run dev
```

Open `http://localhost:3002`.

### Build
```bash
npm run build
```

### Start (production)
After building:

```bash
npm run start
```

The app reads env variables from `.env` at runtime. Ensure the database is reachable.

### Project structure (frontend)
- `pages/` - Next.js pages (routes like `login`, `signup`, `dashboard`, `logs`, `alerts`).
- `lib/` - Auth helpers (`auth.ts`), Prisma client (`lib/generated/prisma`) and wrapper (`prisma.ts`).
- `prisma/schema.prisma` - Prisma schema connected via `DATABASE_URL`.
- `styles/` and Tailwind config for styling.

### Common issues
- If you change the Prisma schema, run `npx prisma generate` again.
- Ensure `DATABASE_URL` is valid and the database is running.
- For JWT errors, set a strong `JWT_SECRET` in `.env`.


