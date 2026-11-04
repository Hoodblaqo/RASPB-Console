# RASPB Console

Public repository for a small shared-account console. Friends use the hosted website; everyone shares one PostgreSQL database.

## Included

- Account registration and password-hashed login
- Owner account bootstrapped from private deployment environment variables
- Owner-only panel to lock/unlock members
- Lock action requires a private message; the affected member sees it after signing in
- Owner can also send private inbox messages
- Login history visible to the owner
- Responsive mobile web interface

## Deploy on Render

1. Create a PostgreSQL database on Render.
2. Create a new **Web Service** from this repository.
3. Build command: `pip install -r requirements.txt`
4. Start command: `gunicorn app:app`
5. Add these environment variables to the web service:
   - `DATABASE_URL`: Render's **Internal Database URL** from your PostgreSQL database
   - `SECRET_KEY`: a long random secret (Render can generate one)
   - `OWNER_USERNAME`: the owner login name you choose
   - `OWNER_PASSWORD`: a unique strong password; never put it in GitHub
   - `COOKIE_SECURE`: `true`
6. Deploy. Open the Render URL, register friend accounts, and sign in with the owner account to manage them.

The owner account is created on first startup if it does not already exist. Set owner environment variables before making the service public. The owner username is reserved from normal registration.

## iPhone / a-Shell

The web app works directly in Safari on iPhone. No JSON file is needed on friends' phones; all accounts, locks and messages are stored in the shared database.

## Security notes

- Never commit passwords, API keys, database URLs or secret keys.
- Use HTTPS (Render provides it).
- The admin panel is protected by the server-side owner flag, not by a hidden button.
- This project is an account-management console. It does not include scanning or access to other people's devices.
- The existing local network scanner is not included in this repository because its exact source was not provided here. Keep any network testing limited to networks you own or are explicitly authorized to assess.
