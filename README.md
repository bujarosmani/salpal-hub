# SalPal API

Backend server for SalPal Hub warehouse management system.

## Environment Variables (set in Railway)

| Variable | Value |
|----------|-------|
| `SB_URL` | `https://mierymdbtsuwgwihtyiu.supabase.co` |
| `SB_SERVICE_KEY` | Your Supabase service role key |
| `JWT_SECRET` | Any long random string (e.g. `salpal-super-secret-2026`) |

## Endpoints

- `POST /api/login` — authenticate, returns JWT token
- `GET /api/data` — load all data (role-filtered)
- `POST /api/upsert` — save a record
- `DELETE /api/delete` — delete a record (admin only)
- `GET /health` — health check
