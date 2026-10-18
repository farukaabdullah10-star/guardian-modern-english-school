# Guardian Modern English School — Production Starter

## Stack
Node.js + Express + PostgreSQL + JWT in an HttpOnly cookie + bcrypt password hashing.

## Deploy
1. Create a PostgreSQL database on your hosting provider.
2. Run `db/schema.sql` against that database.
3. Copy `.env.example` to `.env` and fill `DATABASE_URL` and a strong `JWT_SECRET`.
4. Run `npm install`.
5. Run `npm start`.
6. Put the site behind HTTPS in production.

## Important
This is a production-oriented starter, not a claim that the school is already live. Before real use, add automated backups, audit logs, password reset, CSRF protection if the deployment architecture needs it, stronger validation, and a proper migration system. Do not use the demo credentials in production.
