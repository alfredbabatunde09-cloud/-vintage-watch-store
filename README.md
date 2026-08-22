# VINTAGE Luxury Watch Store — Pro Version

This version adds a real local SQLite database and a protected admin dashboard.

## What was added

- SQLite database: `data/store.db`
- Customer orders saved permanently in the database
- Admin login
- Admin dashboard at `/admin`
- View all orders
- Change order status: new / contacted / paid / completed / cancelled
- Delete orders
- Mobile-friendly dashboard
- Protected order-management API

## Run

Install Node.js, then:

```bash
npm install
npm start
```

Open the store:

http://localhost:3000

Open the admin:

http://localhost:3000/admin

## Default development login

Username:
`admin`

Password:
`ChangeMe123!`

CHANGE THIS before deploying.

## Production environment variables

Set:

`ADMIN_USERNAME=your-admin-name`

`ADMIN_PASSWORD=a-long-random-password`

`SESSION_SECRET=a-long-random-secret`

`PORT=3000`

For example on Linux/macOS:

```bash
ADMIN_USERNAME=myadmin ADMIN_PASSWORD='use-a-long-password' SESSION_SECRET='random-long-secret' npm start
```

## Important for public deployment

This is a functional starter backend, but for a real high-value store you should:
1. Use HTTPS.
2. Set strong admin credentials in environment variables.
3. Never expose the database file publicly.
4. Use a managed database (PostgreSQL/Supabase/Neon) if the hosting filesystem is temporary.
5. Add email/WhatsApp notifications if you want instant alerts.
6. Add proper payment processing before accepting actual payments.
7. Add stronger authentication/rate limiting for a production launch.

The current "GET THE LOOK" flow is an order-request system; it does NOT process payments.
