# Lumen Gateway Frontend

Next.js App Router frontend for the Lumen v2.1 gateway. The landing page includes a scroll-driven Three.js prism stage, `/login` provides Google and email/password authentication, `/profile` manages each signed-in user's profile, and `/portal` contains the workspace console.

## Run locally

1. Install Node.js 20.9 or newer.
2. Copy `.env.example` to `.env.local`.
3. Run `npm ci`, then `npm run dev`.
4. Open `http://localhost:3000`.

The `.env.example` points at the Lumen Supabase project and includes its public publishable key. Publishable keys are intended for browser apps; never add a Supabase secret or service-role key to a `NEXT_PUBLIC_*` variable.

## Supabase setup

The `public.profiles` table, row-level security policies, and auth-user profile trigger are included in `supabase/migrations/20261022165404_lumen_profiles_and_auth_trigger.sql` and have been applied to the Lumen project. Every new Google or email account gets a profile row. Each user can read and update only their own profile.

Email/password sign-in, account creation, email confirmation, and password reset are implemented in `/login`. The app returns users to `/portal` after authentication by default; profile login returns to `/profile`.

For sign-up confirmation and password reset emails to reach general users, configure a production SMTP provider in Supabase. Supabase's default email service is restricted to pre-authorized team addresses and is intended for testing; see [Supabase custom SMTP setup](https://supabase.com/docs/guides/auth/auth-smtp).

To enable Google sign-in, create a Google OAuth web client and add its client ID and secret in **Supabase Dashboard → Authentication → Sign In / Providers → Google**. Use this Supabase callback URL in the Google OAuth client:

`https://yiluayooeeuvyyckhpvr.supabase.co/auth/v1/callback`

In **Authentication → URL Configuration**, set the local Site URL to `http://localhost:3000` and add `http://localhost:3000/**` to the redirect URL allow list. Add the production domain Site URL and redirect allow-list entry after deployment. Email confirmation and password reset emails return through `/auth/callback` before landing at `/portal` or `/login?mode=reset-password` on the current frontend origin.

## Lumen gateway connection

Set `NEXT_PUBLIC_LUMEN_API_URL` to the deployed Python bridge URL. The browser forwards the user's Supabase access token as a bearer token. The custom Lumen engine, signing keys, cloud identity, and tool implementations belong in that trusted backend and must never be placed in this frontend. See [BACKEND_CONTRACT.md](./BACKEND_CONTRACT.md) for the required API routes and security boundary.

Without a reachable bridge, the portal labels sample scenarios and exports as preview data. Supabase authentication and profile storage work independently of the Lumen gateway.

## Deployment

Deploy this directory as a Next.js project on Vercel. Configure `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY`, and `NEXT_PUBLIC_LUMEN_API_URL` in the Vercel project settings. Add the deployed origin to Supabase Auth's redirect URL allow list. Keep backend secrets and AWS credentials in the Python gateway environment.
