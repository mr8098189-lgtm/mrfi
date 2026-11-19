# MrFi V3 — Production-Ready Starter

## Included
- PostgreSQL production database
- Admin authentication + PostgreSQL-backed sessions
- OTP verification flow with provider adapter
- Customer application + tracking page
- Admin analytics and application management
- Document upload
- Aadhaar/PAN verification adapter
- WhatsApp Cloud API adapter + click-to-chat fallback
- Video KYC scheduling link
- Audit log table
- Rate limiting and Helmet security headers

## Run
1. Install Node.js 18+.
2. Create PostgreSQL database `mrfi`.
3. Copy `.env.example` to `.env`.
4. Fill `DATABASE_URL`, `SESSION_SECRET`, admin credentials.
5. `npm install`
6. `npm start`
7. Open `http://localhost:3000`.

## Important integrations
The project deliberately uses provider adapters for OTP and Aadhaar/PAN verification. Real identity verification must be connected to an authorized provider; do not store raw Aadhaar/PAN numbers unnecessarily. Use tokenized/reference IDs where supported and follow applicable privacy, KYC, RBI/lender and data-retention requirements.

WhatsApp: set `WHATSAPP_CLOUD_TOKEN` and `WHATSAPP_PHONE_NUMBER_ID` to enable API messaging. Without them, the site still provides click-to-chat.

Video KYC: the demo page creates a meeting room. Replace it with your approved KYC/video provider before production.

## Production deployment
Recommended stack:
- App: Render / Railway / Fly.io / AWS
- Database: managed PostgreSQL (Neon / Supabase / Render Postgres / AWS RDS)
- File storage: S3-compatible private bucket instead of local `/uploads`
- HTTPS: platform-managed TLS
- Secrets: platform secret manager
- Backups: managed Postgres backups
- Monitoring: uptime + error monitoring

## Before accepting real loan applications
Complete legal/compliance review, privacy notice, consent language, lender/NBFC authorization/partnership requirements, KYC provider agreement, data retention/deletion policy, access controls, document encryption and incident-response procedures.
